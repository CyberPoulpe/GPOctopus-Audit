#!/usr/bin/env python3
"""
GPOctopus Audit — Audit de sécurité des GPO Active Directory
Analyse LDAP + SYSVOL, rapport HTML interactif
CIS Benchmarks · ANSSI · Microsoft Security Baseline

Usage :
  python3 gpoctopus.py                          # wizard interactif
  python3 gpoctopus.py --demo                   # mode démo sans AD
  python3 gpoctopus.py --dc 192.168.1.1 --domain corp.local --user admin --password 'P@ss!' -o rapport.html

Dépendances :
  pip3 install ldap3 jinja2 impacket pycryptodome --break-system-packages
"""

# ── Auto-installation des dépendances ─────────────────────────────────────────
import sys
import subprocess

def _check_and_install_deps():
    deps = {
        'ldap3':        'ldap3',
        'jinja2':       'jinja2',
        'impacket':     'impacket',
        'Cryptodome':   'pycryptodome',
    }
    missing = []
    for module, package in deps.items():
        try:
            __import__(module)
        except ImportError:
            missing.append(package)

    if not missing:
        return

    print(f"[*] Dépendances manquantes : {', '.join(missing)}")
    print("[*] Installation automatique en cours...")
    for pkg in missing:
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'install', pkg, '--break-system-packages'],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"[+] {pkg} installé")
        else:
            # Essai sans --break-system-packages (virtualenv, etc.)
            result2 = subprocess.run(
                [sys.executable, '-m', 'pip', 'install', pkg],
                capture_output=True, text=True
            )
            if result2.returncode == 0:
                print(f"[+] {pkg} installé")
            else:
                print(f"[!] Impossible d'installer {pkg} automatiquement")
                print(f"    Commande manuelle : pip3 install {pkg} --break-system-packages")
                sys.exit(1)
    print("[+] Dépendances installées — redémarrage...")
    os.execv(sys.executable, [sys.executable] + sys.argv)

import os
_check_and_install_deps()

# ─── Patch MD4 (OpenSSL 3.x) ────────────────────────────────────────────────
# OpenSSL 3.x a supprimé MD4 du provider par défaut.
# NTLM (utilisé par ldap3) en a besoin — on le réimplémente via Cryptodome.

import hashlib as _hashlib

def _apply_md4_patch():
    try:
        _hashlib.new('md4', b'test')
        return
    except (ValueError, Exception):
        pass
    try:
        from Cryptodome.Hash import MD4 as _CD_MD4
    except ImportError:
        try:
            from Crypto.Hash import MD4 as _CD_MD4
        except ImportError:
            raise RuntimeError(
                "MD4 non disponible et Cryptodome absent.\n"
                "Fix : pip3 install pycryptodome --break-system-packages"
            )
    class _MD4Wrapper:
        name = 'md4'; digest_size = 16; block_size = 64
        def __init__(self, data=b''):
            self._h = _CD_MD4.new()
            if data: self._h.update(data)
        def update(self, data): self._h.update(data); return self
        def digest(self): return self._h.digest()
        def hexdigest(self): return self._h.hexdigest()
        def copy(self):
            import copy; return copy.deepcopy(self)
    _orig = _hashlib.new
    def _patched(name, data=b'', **kwargs):
        if name.lower() == 'md4': return _MD4Wrapper(data)
        return _orig(name, data, **kwargs)
    _hashlib.new = _patched

_apply_md4_patch()

import argparse
import json
import os
import re
import sys
import struct
from datetime import datetime
from pathlib import Path

# Patch MD4 pour OpenSSL 3.x — doit être avant l'import ldap3
try:
    import md4_patch
except Exception:
    pass

try:
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
    from ldap3.core.exceptions import LDAPException
except ImportError:
    print("[!] ldap3 manquant : pip install ldap3")
    sys.exit(1)

try:
    from jinja2 import Template
except ImportError:
    print("[!] jinja2 manquant : pip install jinja2")
    sys.exit(1)

# ─── Règles d'audit ─────────────────────────────────────────────────────────
# check_key doit correspondre EXACTEMENT à ce que parse_gpttmpl() retourne
# (tout en minuscules, sans underscores, tel qu'écrit dans le .inf)

AUDIT_RULES = [
    # ── Mots de passe ──
    {
        "id": "PWD-001",
        "title": "Longueur minimale du mot de passe insuffisante",
        "severity": "critical",
        "ref": "CIS 1.1.1 · ANSSI R-03 · MS Baseline",
        "category": "Mots de passe",
        "check_key": "minimumpasswordlength",   # clé telle que dans GptTmpl.inf
        "section": "password_policy",
        "threshold": 14,
        "operator": "lt",
        "remediation": "Configurer MinimumPasswordLength ≥ 14 dans la Default Domain Policy.",
    },
    {
        "id": "PWD-002",
        "title": "Historique des mots de passe trop court",
        "severity": "critical",
        "ref": "CIS 1.1.2 · ANSSI R-03",
        "category": "Mots de passe",
        "check_key": "passwordhistorysize",
        "section": "password_policy",
        "threshold": 24,
        "operator": "lt",
        "remediation": "PasswordHistorySize ≥ 24 pour empêcher la réutilisation cyclique.",
    },
    {
        "id": "PWD-003",
        "title": "Complexité du mot de passe désactivée",
        "severity": "critical",
        "ref": "CIS 1.1.5 · ANSSI R-03",
        "category": "Mots de passe",
        "check_key": "passwordcomplexity",
        "section": "password_policy",
        "threshold": 1,
        "operator": "ne",
        "remediation": "PasswordComplexity = 1 (activé).",
    },
    {
        "id": "PWD-004",
        "title": "Durée maximale du mot de passe illimitée (= 0) ou excessive (> 365j)",
        "severity": "warning",
        "ref": "CIS 1.1.3 · ANSSI R-03",
        "category": "Mots de passe",
        "check_key": "maximumpasswordage",
        "section": "password_policy",
        "threshold": 365,
        "operator": "gt_or_zero",
        "remediation": "MaximumPasswordAge entre 60 et 365 jours. 0 = illimité (non recommandé).",
    },
    # ── Authentification réseau ──
    {
        "id": "AUTH-001",
        "title": "Stockage des hash LAN Manager activé",
        "severity": "critical",
        "ref": "CIS 2.3.11.2 · ANSSI R-05",
        "category": "Authentification",
        "check_key": "nolmhash",
        "section": "system_access",
        "threshold": 1,
        "operator": "ne",
        "remediation": "NoLMHash = 1 (Network security: Do not store LAN Manager hash = Enabled).",
    },
    {
        "id": "AUTH-002",
        "title": "NTLMv1 autorisé (LmCompatibilityLevel < 5)",
        "severity": "critical",
        "ref": "CIS 2.3.11.7 · ANSSI R-06",
        "category": "Authentification",
        "check_key": "lmcompatibilitylevel",
        "section": "system_access",
        "threshold": 5,
        "operator": "lt",
        "remediation": "LmCompatibilityLevel = 5 (NTLMv2 only, refuse LM & NTLM).",
    },
    {
        "id": "AUTH-003",
        "title": "Seuil de verrouillage désactivé ou trop élevé (> 10)",
        "severity": "warning",
        "ref": "CIS 1.2.1 · ANSSI R-04",
        "category": "Authentification",
        "check_key": "lockoutbadcount",
        "section": "system_access",
        "threshold": 10,
        "operator": "gt_or_zero",
        "remediation": "LockoutBadCount entre 5 et 10. 0 = pas de verrouillage (non recommandé).",
    },
    {
        "id": "AUTH-004",
        "title": "Durée de verrouillage de compte insuffisante (< 15 min)",
        "severity": "warning",
        "ref": "CIS 1.2.2 · ANSSI R-04",
        "category": "Authentification",
        "check_key": "lockoutduration",
        "section": "system_access",
        "threshold": 15,
        "operator": "lt",
        "remediation": "LockoutDuration ≥ 15 minutes.",
    },
    # ── Audit ──
    {
        "id": "AUDIT-001",
        "title": "Audit des connexions non configuré",
        "severity": "warning",
        "ref": "CIS 17.5.1 · ANSSI R-09",
        "category": "Audit",
        "check_key": "auditlogonevents",        # tout en minuscules
        "section": "event_audit",
        "threshold": 0,
        "operator": "eq",
        "remediation": "AuditLogonEvents = 3 (Success + Failure).",
    },
    {
        "id": "AUDIT-002",
        "title": "Audit de la gestion des comptes non configuré",
        "severity": "warning",
        "ref": "CIS 17.2.1 · ANSSI R-09",
        "category": "Audit",
        "check_key": "auditaccountmanage",
        "section": "event_audit",
        "threshold": 0,
        "operator": "eq",
        "remediation": "AuditAccountManage = 3 (Success + Failure).",
    },
    {
        "id": "AUDIT-003",
        "title": "Audit des modifications de stratégie non configuré",
        "severity": "warning",
        "ref": "CIS 17.7.1",
        "category": "Audit",
        "check_key": "auditpolicychange",
        "section": "event_audit",
        "threshold": 0,
        "operator": "eq",
        "remediation": "AuditPolicyChange = 3 (Success + Failure).",
    },
    {
        "id": "LOG-001",
        "title": "Taille du journal Sécurité insuffisante (< 1 Go recommandé)",
        "severity": "warning",
        "ref": "CIS 18.9.27.1 · ANSSI R-09",
        "category": "Audit",
        "check_key": "maximumlogsize",
        "section": "security log",
        "threshold": 1048576,
        "operator": "lt",
        "remediation": "MaximumLogSize ≥ 1048576 Ko (1 Go) pour le journal Sécurité. Un journal trop petit écrase les événements anciens — impossible de remonter un incident.",
    },
    {
        "id": "AUDIT-006",
        "title": "Audit de l'utilisation des privilèges non configuré",
        "severity": "info",
        "ref": "CIS 17.8.1 · ANSSI R-09",
        "category": "Audit",
        "check_key": "auditprivilegeusse",
        "section": "event_audit",
        "threshold": 0,
        "operator": "eq",
        "remediation": "AuditPrivilegeUse = 1 (succès). Détecte l'utilisation de droits sensibles (SeDebugPrivilege, SeTakeOwnershipPrivilege...) souvent exploités lors d'attaques.",
    },
    {
        "id": "AUDIT-007",
        "title": "Audit des événements système non configuré",
        "severity": "info",
        "ref": "CIS 17.9.1 · ANSSI R-09",
        "category": "Audit",
        "check_key": "auditsystemevents",
        "section": "event_audit",
        "threshold": 0,
        "operator": "eq",
        "remediation": "AuditSystemEvents = 1 (succès). Trace les démarrages/arrêts système, la modification de l'heure système et les pertes d'événements d'audit.",
    },
    {
        "id": "PWD-006",
        "title": "Durée minimale du mot de passe = 0 (changement immédiat possible)",
        "severity": "warning",
        "ref": "CIS 1.1.4 · ANSSI R-03",
        "category": "Mots de passe",
        "check_key": "minimumpasswordage",
        "section": "password_policy",
        "threshold": 1,
        "operator": "lt",
        "remediation": "MinimumPasswordAge ≥ 1 jour. Sans durée minimale, un utilisateur peut changer son mot de passe 24 fois d'affilée pour retrouver l'ancien — contourne l'historique.",
    },
    # ── Droits ──
    {
        "id": "PRIV-001",
        "title": "Accès réseau anonyme autorisé (RestrictAnonymous = 0)",
        "severity": "critical",
        "ref": "CIS 2.3.10.2 · ANSSI R-10",
        "category": "Droits & Privilèges",
        "check_key": "restrictanonymous",
        "section": "system_access",
        "threshold": 1,
        "operator": "lt",
        "remediation": "RestrictAnonymous = 1 minimum, 2 idéalement.",
    },
    {
        "id": "PRIV-002",
        "title": "Compte Invité activé",
        "severity": "warning",
        "ref": "CIS 2.3.1.2",
        "category": "Droits & Privilèges",
        "check_key": "enableguestaccount",
        "section": "system_access",
        "threshold": 0,
        "operator": "ne",
        "remediation": "EnableGuestAccount = 0 (désactivé).",
    },
    # ── Registre (Registry.pol) ──
    {
        "id": "SYS-001",
        "title": "WDigest activé — mots de passe en clair dans lsass",
        "severity": "critical",
        "ref": "KB2871997 · ANSSI R-08",
        "category": "Système",
        "check_key": None,
        "section": "registry",
        "reg_key": r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
        "reg_value": "UseLogonCredential",
        "reg_expected": 0,
        "remediation": "UseLogonCredential = 0 via GPO Préférences (Registre). Pas de redémarrage requis sur Win10/11.",
    },
    {
        "id": "SYS-002",
        "title": "SMBv1 non désactivé explicitement",
        "severity": "warning",
        "ref": "MS ADV170012 · ANSSI R-07",
        "category": "Système",
        "check_key": None,
        "section": "registry",
        "reg_key": r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "reg_value": "SMB1",
        "reg_expected": 0,
        "remediation": "SMB1 = 0 via GPO Registre. Ou PowerShell : Set-SmbServerConfiguration -EnableSMB1Protocol $false",
    },
    {
        "id": "SYS-003",
        "title": "Pare-feu Windows désactivé par GPO",
        "severity": "warning",
        "ref": "CIS 9.1.1 · ANSSI R-11",
        "category": "Système",
        "check_key": None,
        "section": "registry",
        "reg_key": r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile",
        "reg_value": "EnableFirewall",
        "reg_expected": 1,
        "remediation": "EnableFirewall = 1. Gérer les exceptions plutôt que de désactiver le pare-feu.",
    },
    {
        "id": "SYS-004",
        "title": "AutoPlay/AutoRun non désactivé",
        "severity": "warning",
        "ref": "CIS 18.9.8.1 · ANSSI R-14",
        "category": "Système",
        "check_key": None,
        "section": "registry",
        "reg_key": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "reg_value": "NoDriveTypeAutoRun",
        "reg_expected": 255,
        "remediation": "NoDriveTypeAutoRun = 0xFF (255) pour désactiver sur tous les lecteurs.",
    },
    {
        "id": "SYS-005",
        "title": "Credential Guard non configuré",
        "severity": "info",
        "ref": "MS Credential Guard · ANSSI",
        "category": "Système",
        "check_key": None,
        "section": "registry",
        "reg_key": r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard",
        "reg_value": "EnableVirtualizationBasedSecurity",
        "reg_expected": 1,
        "remediation": "Activer via GPO Device Guard. Requis : UEFI, Secure Boot, TPM 2.0, Win10/11 64-bit.",
    },
    # ── Kerberos ──
    {
        "id": "KRB-001",
        "title": "Durée de vie des tickets Kerberos trop longue (> 10h)",
        "severity": "warning",
        "ref": "CIS 2.3.9.1 · ANSSI R-06",
        "category": "Kerberos",
        "check_key": "maxtickerage",
        "section": "kerberos_policy",
        "threshold": 10,
        "operator": "gt",
        "remediation": "MaxTicketAge ≤ 10h. Un ticket long-lived donne plus de temps à un attaquant pour l'exploiter (Pass-the-Ticket).",
    },
    {
        "id": "KRB-002",
        "title": "Tolérance d'horloge Kerberos trop élevée (> 5 min)",
        "severity": "warning",
        "ref": "CIS 2.3.9.3 · ANSSI R-06",
        "category": "Kerberos",
        "check_key": "maxclockskew",
        "section": "kerberos_policy",
        "threshold": 5,
        "operator": "gt",
        "remediation": "MaxClockSkew ≤ 5 minutes. Une tolérance excessive facilite les attaques par replay de tickets.",
    },
    {
        "id": "KRB-003",
        "title": "Renouvellement des tickets Kerberos trop long (> 7 jours)",
        "severity": "info",
        "ref": "CIS 2.3.9.2 · ANSSI R-06",
        "category": "Kerberos",
        "check_key": "maxrenewage",
        "section": "kerberos_policy",
        "threshold": 7,
        "operator": "gt",
        "remediation": "MaxRenewAge ≤ 7 jours. Limite la durée pendant laquelle un ticket volé peut être renouvelé.",
    },
]

# ─── Règles sur les [Privilege Rights] du GptTmpl.inf ───────────────────────
AUDIT_RULES_PRIVRIGHTS = [
    {
        "id": "PRIV-R001",
        "title": "SeDebugPrivilege accordé à des comptes non-Administrateurs",
        "severity": "critical",
        "ref": "CIS 2.2.15 · ANSSI R-38",
        "category": "Droits & Privilèges",
        "right_key": "sedebugprivilege",
        "allowed_groups": {"*s-1-5-32-544"},
        "remediation": "SeDebugPrivilege = Administrators seulement. Permet de lire la mémoire de tout processus — Mimikatz l'utilise pour extraire les credentials de lsass.",
    },
    {
        "id": "PRIV-R002",
        "title": "SeTcbPrivilege (Act as part of OS) accordé",
        "severity": "critical",
        "ref": "CIS 2.2.11 · ANSSI R-38",
        "category": "Droits & Privilèges",
        "right_key": "setcbprivilege",
        "empty_only": True,
        "remediation": "SeTcbPrivilege doit être vide. Ce droit permet à un processus d'agir comme le système d'exploitation — escalade totale garantie.",
    },
    {
        "id": "PRIV-R003",
        "title": "SeTakeOwnershipPrivilege accordé au-delà des Admins",
        "severity": "warning",
        "ref": "CIS 2.2.48 · ANSSI R-38",
        "category": "Droits & Privilèges",
        "right_key": "setakeownershipprivilege",
        "allowed_groups": {"*s-1-5-32-544"},
        "remediation": "SeTakeOwnership = Administrators seulement. Contourne les ACL sur n'importe quel objet.",
    },
    {
        "id": "PRIV-R004",
        "title": "SeBackupPrivilege accordé au-delà des Admins/Backup Operators",
        "severity": "warning",
        "ref": "CIS 2.2.10 · ANSSI R-38",
        "category": "Droits & Privilèges",
        "right_key": "sebackupprivilege",
        "allowed_groups": {"*s-1-5-32-544", "*s-1-5-32-551"},
        "remediation": "SeBackupPrivilege = Administrators + Backup Operators. Permet de lire tout fichier indépendamment des ACL — exfiltration ruche SAM.",
    },
    {
        "id": "PRIV-R005",
        "title": "SeLoadDriverPrivilege accordé au-delà des Admins",
        "severity": "critical",
        "ref": "CIS 2.2.30 · ANSSI R-38",
        "category": "Droits & Privilèges",
        "right_key": "seloaddriverprivilege",
        "allowed_groups": {"*s-1-5-32-544"},
        "remediation": "SeLoadDriverPrivilege = Administrators seulement. Charger un driver malveillant = contrôle total du noyau, contournement de tout EDR.",
    },
]


def evaluate_privright_rules(privright_settings: dict) -> list:
    """Évalue les règles Privilege Rights depuis [Privilege Rights] de GptTmpl.inf."""
    findings = []
    if not privright_settings:
        return findings
    for rule in AUDIT_RULES_PRIVRIGHTS:
        key = rule["right_key"].lower()
        raw = privright_settings.get(key)
        if raw is None:
            continue
        assigned = {v.strip().lower() for v in raw.split(',') if v.strip()}
        violated = False
        detail = f"Droit accordé à : {raw}"
        if rule.get("empty_only"):
            if assigned:
                violated = True
                detail = f"Droit non vide — accordé à : {raw}"
        elif "allowed_groups" in rule:
            allowed = {g.lower() for g in rule["allowed_groups"]}
            extra = assigned - allowed
            if extra:
                violated = True
                detail = f"Groupes non autorisés : {', '.join(sorted(extra))}"
        if violated:
            findings.append({
                "rule_id":    rule["id"],
                "title":      rule["title"],
                "severity":   rule["severity"],
                "ref":        rule["ref"],
                "category":   rule["category"],
                "remediation":rule["remediation"],
                "detail":     detail,
                "not_configured": False,
            })
    return findings


# ─── Règles sur les [Registry Values] du GptTmpl.inf ────────────────────────
# Format valeur : "type,valeur" ex: "4,1" = REG_DWORD valeur 1

AUDIT_RULES_REGVAL = [
    {
        "id": "UAC-001",
        "title": "UAC désactivé (EnableLUA = 0)",
        "severity": "critical",
        "ref": "CIS 2.3.17.1 · ANSSI R-38 · MS Baseline",
        "category": "UAC & Élévation de privilèges",
        "regval_key": "machine\\software\\microsoft\\windows\\currentversion\\policies\\system\\enablelua",
        "bad_val": "4,0",
        "remediation": "EnableLUA = 1. L'UAC est une défense fondamentale contre l'escalade de privilèges. Un malware peut s'élever silencieusement si UAC est désactivé.",
    },
    {
        "id": "UAC-002",
        "title": "Admins sans demande de confirmation UAC (ConsentPromptBehaviorAdmin = 0)",
        "severity": "critical",
        "ref": "CIS 2.3.17.2 · ANSSI R-38",
        "category": "UAC & Élévation de privilèges",
        "regval_key": "machine\\software\\microsoft\\windows\\currentversion\\policies\\system\\consentpromptbehavioradmin",
        "bad_val": "4,0",
        "remediation": "ConsentPromptBehaviorAdmin = 2 (demande credentials) ou 5 (demande confirmation). Valeur 0 = élévation silencieuse = tout malware devient SYSTEM sans interaction.",
    },
    {
        "id": "SMB-001",
        "title": "Signature SMB non requise côté client (RequireSecuritySignature = 0)",
        "severity": "warning",
        "ref": "CIS 2.3.8.1 · ANSSI PA-022",
        "category": "Authentification réseau",
        "regval_key": "machine\\system\\currentcontrolset\\services\\lanmanworkstation\\parameters\\requiresecuritysignature",
        "bad_val": "4,0",
        "remediation": "RequireSecuritySignature = 1. Protège contre SMB relay / MITM. Vérifier la compatibilité NAS et imprimantes réseau avant déploiement.",
    },
    {
        "id": "LDAP-001",
        "title": "Intégrité LDAP client désactivée (LDAPClientIntegrity = 0)",
        "severity": "critical",
        "ref": "CIS 2.3.11.8 · MS ADV190023 · ANSSI R-06",
        "category": "Authentification réseau",
        "regval_key": "machine\\system\\currentcontrolset\\services\\ldap\\ldapclientintegrity",
        "bad_val": "4,0",
        "remediation": "LDAPClientIntegrity = 2 (signature requise). Valeur 0 = les requêtes LDAP ne sont pas signées — permet des attaques LDAP relay pour escalader les privilèges dans l'AD (CVE critique).",
    },
    {
        "id": "PRINT-001",
        "title": "Installation drivers imprimantes non restreinte aux admins (PrintNightmare)",
        "severity": "critical",
        "ref": "CVE-2021-34527 · MS KB5005010",
        "category": "Services & Composants système",
        "regval_key": "machine\\system\\currentcontrolset\\control\\print\\providers\\lanman print services\\servers\\addprinterdrivers",
        "bad_val": "4,0",
        "remediation": "AddPrinterDrivers = 1 (seuls les admins). Valeur 0 = tout utilisateur peut installer des drivers imprimantes — vecteur PrintNightmare pour obtenir SYSTEM. Déployer aussi le patch KB5005010.",
    },

    # ── UAC complémentaires ──
    {
        "id": "UAC-003",
        "title": "Compte administrateur intégré non filtré (FilterAdministratorToken = 0)",
        "severity": "warning",
        "ref": "CIS 2.3.17.3 · MS Baseline",
        "category": "UAC & Élévation de privilèges",
        "regval_key": "machine\\software\\microsoft\\windows\\currentversion\\policies\\system\\filteradministratortoken",
        "bad_val": "4,0",
        "remediation": "FilterAdministratorToken = 1. Applique le mode approbation administrateur même au compte Administrateur intégré (RID 500). Réduit la surface d'attaque pass-the-hash.",
    },
    {
        "id": "UAC-004",
        "title": "Jeton d'accès réseau plein pour les comptes locaux (LocalAccountTokenFilterPolicy = 1)",
        "severity": "critical",
        "ref": "MS KB951016 · ANSSI R-38",
        "category": "UAC & Élévation de privilèges",
        "regval_key": "machine\\software\\microsoft\\windows\\currentversion\\policies\\system\\localaccounttokenfilterpolicy",
        "bad_val": "4,1",
        "remediation": "LocalAccountTokenFilterPolicy = 0. Valeur 1 = les comptes locaux admins obtiennent un jeton complet via le réseau — permet le Pass-the-Hash latéral sur tous les postes avec le même mot de passe admin local. Combiner avec LAPS.",
    },

    # ── Authentification réseau complémentaires ──
    {
        "id": "NTLM-001",
        "title": "Trafic NTLM sortant non restreint (RestrictSendingNTLMTraffic)",
        "severity": "warning",
        "ref": "CIS 2.3.11.9 · ANSSI R-06",
        "category": "Authentification réseau",
        "regval_key": "machine\\system\\currentcontrolset\\control\\lsa\\msv1_0\\restrictsendingntlmtraffic",
        "bad_val": "4,0",
        "remediation": "RestrictSendingNTLMTraffic = 1 (audit) puis = 2 (blocage). Valeur 0 = NTLM envoyé librement à n'importe quel serveur — vecteur d'attaque NTLM relay depuis un poste compromis.",
    },
    {
        "id": "LDAP-002",
        "title": "Intégrité LDAP non au niveau maximum (LDAPClientIntegrity ≠ 2)",
        "severity": "warning",
        "ref": "CIS 2.3.11.8 · MS ADV190023",
        "category": "Authentification réseau",
        "regval_key": "machine\\system\\currentcontrolset\\services\\ldap\\ldapclientintegrity",
        "bad_val": "4,1",
        "remediation": "LDAPClientIntegrity = 2 (signature requise, pas juste négociée). Valeur 1 = signature seulement si le serveur la propose — pas suffisant contre une attaque downgrade.",
    },

    # ── LSASS protection ──
    {
        "id": "LSA-001",
        "title": "Protection LSASS (RunAsPPL) non activée",
        "severity": "warning",
        "ref": "MS KB3033929 · ANSSI R-08",
        "category": "Services & Composants système",
        "regval_key": "machine\\system\\currentcontrolset\\control\\lsa\\runasppl",
        "bad_val": "4,1",
        "operator": "ne",
        "remediation": "RunAsPPL = 1 (REG_DWORD). Protège lsass.exe comme processus protégé — Mimikatz ne peut plus lire les credentials en mémoire même avec les droits admin locaux. Requis : Secure Boot activé.",
    },

    # ── Mots de passe complémentaires ──
    {
        "id": "PWD-005",
        "title": "Avertissement d'expiration trop court (< 14 jours)",
        "severity": "info",
        "ref": "CIS 1.1.6 · ANSSI R-03",
        "category": "Mots de passe",
        "regval_key": "machine\\software\\microsoft\\windows nt\\currentversion\\winlogon\\passwordexpirywarning",
        "bad_val": "4,0",
        "remediation": "PasswordExpiryWarning ≥ 14 jours. Avertit les utilisateurs suffisamment tôt pour éviter les verrouillages à l'expiration.",
    },

    # ── Audit complémentaires ──
    {
        "id": "AUDIT-005",
        "title": "Audit avancé non prioritaire sur l'audit legacy",
        "severity": "info",
        "ref": "CIS 17.1.1 · ANSSI R-09",
        "category": "Audit",
        "regval_key": "machine\\system\\currentcontrolset\\control\\lsa\\scenoapplylegacyauditpolicy",
        "bad_val": "4,0",
        "remediation": "SCENoApplyLegacyAuditPolicy = 1. Permet d'utiliser les politiques d'audit avancées (audit.csv) sans conflit avec les paramètres d'audit legacy.",
    },

    # ── Accès réseau anonyme ──
    {
        "id": "ANON-001",
        "title": "Tout le monde inclut les anonymes (EveryoneIncludesAnonymous = 1)",
        "severity": "warning",
        "ref": "CIS 2.3.10.1 · ANSSI R-10",
        "category": "Droits & Accès réseau",
        "regval_key": "machine\\system\\currentcontrolset\\control\\lsa\\everyoneincludesanonymous",
        "bad_val": "4,1",
        "remediation": "EveryoneIncludesAnonymous = 0. Valeur 1 = le groupe Everyone (Tout le monde) inclut les connexions anonymes — étend les permissions aux utilisateurs non authentifiés.",
    },
    {
        "id": "ANON-002",
        "title": "Partages accessibles anonymement non restreints",
        "severity": "warning",
        "ref": "CIS 2.3.10.4 · ANSSI R-10",
        "category": "Droits & Accès réseau",
        "regval_key": "machine\\system\\currentcontrolset\\services\\lanmanserver\\parameters\\restrictnullsessaccess",
        "bad_val": "4,0",
        "remediation": "RestrictNullSessAccess = 1. Empêche l'accès anonyme aux partages réseau. Valeur 0 = les partages listés dans NullSessionShares sont accessibles sans authentification.",
    },

    # ── RDP / NLA ──
    {
        "id": "RDP-001",
        "title": "NLA (Network Level Authentication) non requis pour RDP",
        "severity": "warning",
        "ref": "CIS 18.10.56.2 · ANSSI R-12",
        "category": "Accès distant",
        "regval_key": "machine\\software\\policies\\microsoft\\windows nt\\terminal services\\userauthenication",
        "bad_val": "4,0",
        "remediation": "UserAuthentication = 1. NLA exige l'authentification AD avant d'établir la session RDP — empêche l'exploitation de vulnérabilités RDP pré-auth (BlueKeep CVE-2019-0708).",
    },

    # ── PowerShell ──
    {
        "id": "PS-001",
        "title": "Journalisation PowerShell désactivée",
        "severity": "warning",
        "ref": "CIS 18.9.100.1 · ANSSI R-09",
        "category": "Audit",
        "regval_key": "machine\\software\\policies\\microsoft\\windows\\powershell\\scriptblocklogging\\enablescriptblocklogging",
        "bad_val": "4,0",
        "remediation": "EnableScriptBlockLogging = 1. Enregistre tout le contenu des scripts PowerShell exécutés dans l'EventLog (Event ID 4104). Essentiel pour détecter les attaques PowerShell (Empire, Cobalt Strike...).",
    },

    # ── Kerberos ──
    {
        "id": "KERB-002",
        "title": "DES Kerberos non désactivé (SupportedEncryptionTypes inclut DES)",
        "severity": "warning",
        "ref": "CIS 2.3.11.4 · ANSSI R-07",
        "category": "Authentification réseau",
        "regval_key": "machine\\software\\microsoft\\windows\\currentversion\\policies\\system\\kerberos\\parameters\\supportedencryptiontypes",
        "bad_val": "4,3",
        "remediation": "SupportedEncryptionTypes = 2147483644 (AES128+AES256 uniquement, sans DES/RC4). DES est cassé depuis 2000. RC4 vulnérable aux attaques Kerberoasting.",
    },
]


def _regval_int(val_str: str) -> int | None:
    """Extrait la valeur entière d'une entrée registry_values (format 'type,valeur')."""
    try:
        parts = val_str.strip().split(',')
        return int(parts[-1].strip())
    except (ValueError, IndexError):
        return None



# ─── Règles sur les Registry.xml (préférences registre GPO) ──────────────────
# Ces valeurs viennent de Machine/User/Preferences/Registry/Registry.xml
# Clé format : (hive\key_lower, name_lower) -> int

AUDIT_RULES_REGISTRY_XML = [
    {
        "id": "REGXML-001",
        "title": "Partages administratifs activés via GPO (AutoShareWks = 1)",
        "severity": "critical",
        "ref": "CIS 2.3.10.3 · ANSSI R-10",
        "category": "Droits & Accès réseau",
        "hive_key": "hklm\\system\\currentcontrolset\\services\\lanmanserver\\parameters",
        "name": "autosharewks",
        "bad_int": 1,
        "operator": "eq",
        "remediation": "AutoShareWks = 0. Valeur 1 = les partages C$, D$, ADMIN$ sont actifs sur tous les postes — mouvement latéral trivial avec un compte admin local. Désactiver sauf besoin explicite.",
    },
    {
        "id": "REGXML-002",
        "title": "Jeton d'accès réseau plein pour comptes locaux (LocalAccountTokenFilterPolicy = 1)",
        "severity": "critical",
        "ref": "MS KB951016 · ANSSI R-38 · CIS 18.3.1",
        "category": "UAC & Élévation de privilèges",
        "hive_key": "hklm\\software\\microsoft\\windows\\currentversion\\policies\\system",
        "name": "localaccounttokenfilterpolicy",
        "bad_int": 1,
        "operator": "eq",
        "remediation": "LocalAccountTokenFilterPolicy = 0. Valeur 1 = les admins locaux obtiennent un token élevé via réseau — permet le Pass-the-Hash sur tous les postes avec le même mot de passe admin local. Combiner avec LAPS pour des mots de passe uniques.",
    },
    {
        "id": "REGXML-003",
        "title": "UAC désactivé via préférences registre (EnableLUA = 0)",
        "severity": "critical",
        "ref": "CIS 2.3.17.1 · ANSSI R-38",
        "category": "UAC & Élévation de privilèges",
        "hive_key": "hklm\\software\\microsoft\\windows\\currentversion\\policies\\system",
        "name": "enablelua",
        "bad_int": 0,
        "operator": "eq",
        "remediation": "EnableLUA = 1. UAC désactivé via Registry.xml GPO — prioritaire sur les paramètres de sécurité. Supprimer cette entrée et configurer via les paramètres de sécurité GPO standard.",
    },
    {
        "id": "REGXML-004",
        "title": "WDigest activé via préférences registre (UseLogonCredential = 1)",
        "severity": "critical",
        "ref": "KB2871997 · ANSSI R-08",
        "category": "Authentification",
        "hive_key": "hklm\\system\\currentcontrolset\\control\\securityproviders\\wdigest",
        "name": "uselogoncredential",
        "bad_int": 1,
        "operator": "eq",
        "remediation": "UseLogonCredential = 0. WDigest activé = mots de passe en clair dans lsass, extractibles par Mimikatz en une commande.",
    },
    {
        "id": "REGXML-005",
        "title": "SMBv1 activé via préférences registre",
        "severity": "warning",
        "ref": "MS ADV170012 · ANSSI R-07",
        "category": "Authentification réseau",
        "hive_key": "hklm\\system\\currentcontrolset\\services\\lanmanserver\\parameters",
        "name": "smb1",
        "bad_int": 1,
        "operator": "eq",
        "remediation": "SMB1 = 0. SMBv1 est exploité par WannaCry/NotPetya. Vérifier les équipements legacy avant de le désactiver.",
    },
    {
        "id": "REGXML-006",
        "title": "Pare-feu Windows désactivé via préférences registre",
        "severity": "critical",
        "ref": "CIS 9.1.1 · ANSSI R-11",
        "category": "Services & Composants système",
        "hive_key": "hklm\\software\\policies\\microsoft\\windowsfirewall\\domainprofile",
        "name": "enablefirewall",
        "bad_int": 0,
        "operator": "eq",
        "remediation": "EnableFirewall = 1. Le pare-feu Windows est une défense en profondeur essentielle contre les mouvements latéraux. Gérer les exceptions via GPO plutôt que de le désactiver.",
    },
    {
        "id": "REGXML-007",
        "title": "PowerShell Script Block Logging désactivé",
        "severity": "warning",
        "ref": "CIS 18.9.100.1 · ANSSI R-09",
        "category": "Audit",
        "hive_key": "hklm\\software\\policies\\microsoft\\windows\\powershell\\scriptblocklogging",
        "name": "enablescriptblocklogging",
        "bad_int": 0,
        "operator": "eq",
        "remediation": "EnableScriptBlockLogging = 1. Journalise tout le code PowerShell exécuté (Event ID 4104). Indispensable pour détecter les attaques PowerShell.",
    },
]


def evaluate_registry_xml_rules(rsop_registry_xml: dict) -> list:
    """Évalue les règles sur les Registry.xml agrégés dans le RSOP."""
    findings = []
    for rule in AUDIT_RULES_REGISTRY_XML:
        hive_key = rule["hive_key"].lower()
        name = rule["name"].lower()
        actual = rsop_registry_xml.get((hive_key, name))
        if actual is None:
            continue
        try:
            actual_int = int(actual)
        except (ValueError, TypeError):
            actual_int = None

        bad_int = rule.get("bad_int")
        op = rule.get("operator", "eq")
        violated = False
        if actual_int is not None and bad_int is not None:
            if op == "eq":
                violated = actual_int == bad_int
            elif op == "ne":
                violated = actual_int != bad_int
            elif op == "gt":
                violated = actual_int > bad_int
            elif op == "lt":
                violated = actual_int < bad_int

        if violated:
            findings.append({
                "rule_id": rule["id"],
                "title": rule["title"],
                "severity": rule["severity"],
                "ref": rule["ref"],
                "category": rule["category"],
                "remediation": rule["remediation"],
                "detail": f"Valeur détectée dans Registry.xml (préférences GPO) : {actual_int} — problème confirmé",
                "not_configured": False,
            })
    return findings


def evaluate_regval_rules(rsop_regval_settings: dict) -> list:
    """Évalue les règles AUDIT_RULES_REGVAL sur la section [Registry Values] du RSOP.
    Chaque règle peut avoir :
      - bad_val : valeur exacte problématique (ex: "4,0")
      - bad_val + operator : comparaison numérique (lt, gt, ne, eq)
    """
    findings = []
    for rule in AUDIT_RULES_REGVAL:
        key = rule["regval_key"].lower()
        actual = rsop_regval_settings.get(key)
        if actual is None:
            continue  # Non configuré = valeur par défaut Windows, pas analysé ici

        bad_val = rule.get("bad_val", "").lower().replace(" ", "")
        actual_norm = actual.lower().replace(" ", "")
        operator = rule.get("operator", "eq")  # eq par défaut = correspondance exacte

        violated = False
        detail_val = actual

        if operator in ("eq", None) or "operator" not in rule:
            violated = (actual_norm == bad_val)
        else:
            actual_int = _regval_int(actual)
            bad_int = _regval_int(bad_val) if bad_val else None
            if actual_int is not None and bad_int is not None:
                if operator == "lt":
                    violated = actual_int < bad_int
                elif operator == "gt":
                    violated = actual_int > bad_int
                elif operator == "ne":
                    violated = actual_int != bad_int
                elif operator == "lte":
                    violated = actual_int <= bad_int

        if violated:
            findings.append({
                "rule_id": rule["id"],
                "title": rule["title"],
                "severity": rule["severity"],
                "ref": rule["ref"],
                "category": rule["category"],
                "remediation": rule["remediation"],
                "detail": f"Valeur RSOP : {actual} — problème détecté selon {rule['ref'].split('·')[0].strip()}",
                "not_configured": False,
            })
    return findings



# ─── Parseurs ────────────────────────────────────────────────────────────────


# ─── Parseurs de préférences GPO ─────────────────────────────────────────────

try:
    from xml.etree import ElementTree as ET
except ImportError:
    ET = None

def _xml_attr(el, *keys, default=''):
    """Récupère un attribut XML en testant plusieurs noms."""
    for k in keys:
        v = el.get(k) or el.get(k.lower()) or el.get(k.upper())
        if v is not None:
            return v
    return default

def parse_printers_xml(content: str) -> list:
    """Parse Printers.xml — gère SharedPrinter, PortPrinter, LocalPrinter."""
    if not ET or not content:
        return []
    printers = []
    try:
        root = ET.fromstring(content)
        # Tags possibles selon le type d'imprimante
        printer_tags = {'Printer', 'SharedPrinter', 'PortPrinter', 'LocalPrinter'}
        for p in root.iter():
            tag = p.tag.split('}')[-1] if '}' in p.tag else p.tag
            if tag not in printer_tags:
                continue
            # Attributs directs sur l'élément
            name   = _xml_attr(p, 'name', 'status')
            action = _xml_attr(p, 'image', 'action')  # image=3 = supprimer
            uid    = _xml_attr(p, 'uid')
            changed = _xml_attr(p, 'changed')
            # Attributs dans Properties/
            props = None
            for child in p:
                ctag = child.tag.split('}')[-1] if '}' in child.tag else child.tag
                if ctag.lower() in ('properties', 'propertie'):
                    props = child
                    break
            path    = ''
            default_p = False
            comment = ''
            if props is not None:
                path      = _xml_attr(props, 'path', 'uncPath', 'serverName', 'portName')
                default_p = _xml_attr(props, 'default', 'Default') in ('1', 'true', 'True')
                comment   = _xml_attr(props, 'comment', 'Comment', 'location', 'Location')
                if not name:
                    name = _xml_attr(props, 'localName', 'shareName', 'printerName')
                if not path:
                    path = _xml_attr(props, 'ipAddress', 'serverName')

            # Déterminer l'action lisible
            action_map = {'0': 'Créer', '1': 'Remplacer', '2': 'Mettre à jour',
                          '3': 'Supprimer', 'C': 'Créer', 'R': 'Remplacer',
                          'U': 'Mettre à jour', 'D': 'Supprimer'}
            action_label = action_map.get(action, action or '?')

            if name or path:
                printers.append({
                    'name':    name or path or '(sans nom)',
                    'path':    path,
                    'action':  action_label,
                    'default': default_p,
                    'comment': comment,
                    'type':    tag,
                })
    except Exception:
        pass
    return printers

def parse_drives_xml(content: str) -> list:
    """Parse Machine/Preferences/Drives/Drives.xml"""
    if not ET or not content:
        return []
    drives = []
    try:
        root = ET.fromstring(content)
        for d in root.iter():
            if d.tag.endswith('}Drive') or d.tag == 'Drive':
                _p = d.find('.//{*}Properties'); props = _p if _p is not None else d.find('Properties')
                if props is None:
                    props = d
                path   = _xml_attr(props, 'path', 'uncPath', 'Path')
                letter = _xml_attr(props, 'letter', 'driveLetter', 'Letter')
                label  = _xml_attr(props, 'label', 'Label')
                action = _xml_attr(props, 'action', 'Action')
                if path or letter:
                    drives.append({
                        'letter': letter,
                        'path':   path,
                        'label':  label,
                        'action': action,
                    })
    except Exception:
        pass
    return drives

def parse_shortcuts_xml(content: str) -> list:
    """Parse Machine/Preferences/Shortcuts/Shortcuts.xml"""
    if not ET or not content:
        return []
    shortcuts = []
    try:
        root = ET.fromstring(content)
        for s in root.iter():
            if s.tag.endswith('}Shortcut') or s.tag == 'Shortcut':
                _p = s.find('.//{*}Properties'); props = _p if _p is not None else s.find('Properties')
                if props is None:
                    props = s
                name       = _xml_attr(props, 'name', 'shortcutPath')
                target     = _xml_attr(props, 'targetPath', 'targetType', 'Target')
                location   = _xml_attr(props, 'location', 'destPath', 'Location')
                action     = _xml_attr(props, 'action', 'Action')
                if name or target:
                    shortcuts.append({
                        'name':     name,
                        'target':   target,
                        'location': location,
                        'action':   action,
                    })
    except Exception:
        pass
    return shortcuts

def parse_scheduledtasks_xml(content: str) -> list:
    """Parse Machine/Preferences/ScheduledTasks/ScheduledTasks.xml"""
    if not ET or not content:
        return []
    tasks = []
    try:
        root = ET.fromstring(content)
        for t in root.iter():
            tag = t.tag.split('}')[-1] if '}' in t.tag else t.tag
            if tag in ('ScheduledTask', 'ImmediateTask', 'TaskV2', 'ImmediateTaskV2'):
                _p = t.find('.//{*}Properties'); props = _p if _p is not None else t.find('Properties')
                if props is None:
                    props = t
                name    = _xml_attr(props, 'name', 'runAs')
                action  = _xml_attr(props, 'action', 'Action')
                cmd     = _xml_attr(props, 'appName', 'command', 'application')
                args    = _xml_attr(props, 'args', 'arguments')
                user    = _xml_attr(props, 'runAs', 'userId', 'logonType')
                if name or cmd:
                    tasks.append({
                        'name':   name,
                        'action': action,
                        'cmd':    cmd,
                        'args':   args,
                        'user':   user,
                    })
    except Exception:
        pass
    return tasks

def parse_scripts(content_startup: str, content_shutdown: str,
                  content_logon: str, content_logoff: str) -> dict:
    """Parse les scripts GPO depuis scripts.ini.
    Supporte les deux formats :
      - CmdLine0 / Parameters0  (ancien format)
      - 0CmdLine / 0Parameters  (format courant Windows)
    """
    scripts = {'startup': [], 'shutdown': [], 'logon': [], 'logoff': []}

    def _parse_ini_scripts(text, section):
        result = []
        if not text:
            return result
        in_section = False
        entries = {}
        for line in text.replace('\r\n', '\n').replace('\r', '\n').splitlines():
            line = line.strip()
            if not line or line.startswith(';'):
                continue
            if line.lower() == f'[{section.lower()}]':
                in_section = True
                continue
            elif line.startswith('[') and line.endswith(']'):
                in_section = False
                continue
            if in_section and '=' in line:
                k, _, v = line.partition('=')
                entries[k.strip().lower()] = v.strip()

        # Format 1 : CmdLine0, Parameters0, CmdLine1, ...
        i = 0
        found = False
        while f'cmdline{i}' in entries:
            found = True
            cmd    = entries[f'cmdline{i}']
            params = entries.get(f'parameters{i}', '')
            if cmd:
                result.append({'cmd': cmd, 'params': params})
            i += 1

        # Format 2 : 0CmdLine, 0Parameters, 1CmdLine, ...
        if not found:
            i = 0
            while f'{i}cmdline' in entries:
                cmd    = entries[f'{i}cmdline']
                params = entries.get(f'{i}parameters', '')
                if cmd:
                    result.append({'cmd': cmd, 'params': params})
                i += 1

        return result

    scripts['startup']  = _parse_ini_scripts(content_startup,  'Startup')
    scripts['shutdown'] = _parse_ini_scripts(content_shutdown, 'Shutdown')
    scripts['logon']    = _parse_ini_scripts(content_logon,    'Logon')
    scripts['logoff']   = _parse_ini_scripts(content_logoff,   'Logoff')
    return scripts

def parse_groups_xml(content: str) -> list:
    """Parse Machine/Preferences/Groups/Groups.xml (groupes locaux)"""
    if not ET or not content:
        return []
    groups = []
    try:
        root = ET.fromstring(content)
        for g in root.iter():
            if g.tag.endswith('}Group') or g.tag == 'Group':
                _p = g.find('.//{*}Properties'); props = _p if _p is not None else g.find('Properties')
                if props is None:
                    props = g
                name    = _xml_attr(props, 'groupName', 'name')
                action  = _xml_attr(props, 'action', 'Action')
                members = []
                for m in g.iter():
                    mt = m.tag.split('}')[-1] if '}' in m.tag else m.tag
                    if mt == 'Member':
                        mname = _xml_attr(m, 'name', 'sid')
                        mact  = _xml_attr(m, 'action')
                        if mname:
                            members.append({'name': mname, 'action': mact})
                if name:
                    groups.append({'name': name, 'action': action, 'members': members})
    except Exception:
        pass
    return groups

def parse_envvars_xml(content: str) -> list:
    """Parse Machine/Preferences/EnvironmentVariables/EnvironmentVariables.xml"""
    if not ET or not content:
        return []
    vars_ = []
    try:
        root = ET.fromstring(content)
        for e in root.iter():
            if e.tag.endswith('}EnvironmentVariable') or e.tag == 'EnvironmentVariable':
                _p = e.find('.//{*}Properties'); props = _p if _p is not None else e.find('Properties')
                if props is None:
                    props = e
                name   = _xml_attr(props, 'name', 'Name')
                value  = _xml_attr(props, 'value', 'Value')
                action = _xml_attr(props, 'action', 'Action')
                if name:
                    vars_.append({'name': name, 'value': value, 'action': action})
    except Exception:
        pass
    return vars_

def parse_registry_xml(content: str) -> list:
    """Parse Machine|User/Preferences/Registry/Registry.xml
    Retourne une liste de {hive, key, name, type, value, action}"""
    if not ET or not content:
        return []
    entries = []
    try:
        root = ET.fromstring(content)
        for reg in root.iter():
            tag = reg.tag.split('}')[-1] if '}' in reg.tag else reg.tag
            if tag != 'Registry':
                continue
            props = None
            for child in reg:
                ctag = child.tag.split('}')[-1] if '}' in child.tag else child.tag
                if ctag.lower() == 'properties':
                    props = child
                    break
            if props is None:
                props = reg
            hive    = _xml_attr(props, 'hive', 'Hive')
            key     = _xml_attr(props, 'key', 'Key')
            name    = _xml_attr(props, 'name', 'Name') or _xml_attr(reg, 'name')
            type_   = _xml_attr(props, 'type', 'Type')
            value   = _xml_attr(props, 'value', 'Value')
            action  = _xml_attr(props, 'action', 'Action', 'image')
            action_map = {'U': 'Mettre à jour', 'C': 'Créer', 'R': 'Remplacer',
                          'D': 'Supprimer', '0': 'Créer', '1': 'Remplacer',
                          '2': 'Mettre à jour', '3': 'Supprimer'}
            action_label = action_map.get(action, action or 'Mettre à jour')
            if key or name:
                entries.append({
                    'hive':   hive or 'HKLM',
                    'key':    key,
                    'name':   name,
                    'type':   type_,
                    'value':  value,
                    'action': action_label,
                })
    except Exception:
        pass
    return entries


def parse_files_xml(content: str) -> list:
    """Parse Machine|User/Preferences/Files/Files.xml (copie de fichiers)."""
    if not ET or not content:
        return []
    files = []
    try:
        root = ET.fromstring(content)
        for f in root.iter():
            tag = f.tag.split('}')[-1] if '}' in f.tag else f.tag
            if tag != 'File':
                continue
            name   = _xml_attr(f, 'name', 'status')
            props  = next((c for c in f if (c.tag.split('}')[-1] if '}' in c.tag else c.tag).lower() == 'properties'), None)
            if props is None:
                props = f
            src    = _xml_attr(props, 'fromPath', 'sourcePath', 'from')
            dst    = _xml_attr(props, 'targetPath', 'destPath', 'to')
            action = _xml_attr(props, 'action', 'Action')
            action_map = {'U': 'Mettre à jour', 'C': 'Créer', 'R': 'Remplacer', 'D': 'Supprimer'}
            files.append({
                'name':   name or src.split('\\')[-1] if src else '?',
                'src':    src,
                'dst':    dst,
                'action': action_map.get(action, action or 'Copier'),
            })
    except Exception:
        pass
    return files


def parse_audit_csv(content: str) -> list:
    """Parse Machine/Microsoft/Windows NT/Audit/audit.csv — audit avancé."""
    if not content:
        return []
    entries = []
    lines = content.replace('\r\n', '\n').replace('\r', '\n').splitlines()
    # Ignorer la ligne d'en-tête si présente
    for line in lines:
        line = line.strip()
        if not line or line.startswith('Machine Name') or line.startswith(',System,Subcategory'):
            # Chercher la vraie ligne d'en-tête
            if 'Subcategory' in line and 'Inclusion' in line:
                continue
        parts = line.split(',')
        if len(parts) < 5:
            continue
        # Format : MachineName, PolicyTarget, Subcategory, GUID, InclusionSetting, ExclusionSetting
        subcategory = parts[2].strip() if len(parts) > 2 else ''
        inclusion   = parts[4].strip() if len(parts) > 4 else ''
        if not subcategory or not inclusion:
            continue
        if subcategory.lower() in ('subcategory', 'policy target', ''):
            continue
        # Traduire les valeurs
        inclusion_map = {
            'Success and Failure': 'Succès + Échec',
            'Success':             'Succès uniquement',
            'Failure':             'Échec uniquement',
            'No Auditing':         "Pas d'audit",
        }
        inclusion_fr = inclusion_map.get(inclusion, inclusion)
        alert = None
        if inclusion == 'No Auditing':
            alert = 'Audit désactivé'
        entries.append({
            'subcategory': subcategory,
            'inclusion':   inclusion_fr,
            'alert':       alert,
        })
    return entries


def parse_services_xml(content: str) -> list:
    """Parse Machine/Preferences/Services/Services.xml."""
    if not ET or not content:
        return []
    services = []
    try:
        root = ET.fromstring(content)
        for svc in root.iter():
            tag = svc.tag.split('}')[-1] if '}' in svc.tag else svc.tag
            if tag != 'NTService':
                continue
            name = _xml_attr(svc, 'name', 'serviceName')
            props = next((c for c in svc if (c.tag.split('}')[-1] if '}' in c.tag else c.tag).lower() == 'properties'), None)
            if props is None:
                props = svc
            startup  = _xml_attr(props, 'startupType', 'StartupType')
            action   = _xml_attr(props, 'serviceAction', 'ServiceAction')
            svc_name = _xml_attr(props, 'serviceName', 'ServiceName') or name
            gpo_action = _xml_attr(svc, 'image', 'action')
            gpo_action_map = {'0': 'Créer', '1': 'Remplacer', '2': 'Mettre à jour', '3': 'Supprimer',
                              'C': 'Créer', 'R': 'Remplacer', 'U': 'Mettre à jour', 'D': 'Supprimer'}
            alert = None
            if startup and startup.upper() == 'DISABLED':
                alert = f'Service désactivé : {svc_name}'
            elif action and action.upper() == 'STOP':
                alert = f'Service arrêté : {svc_name}'
            services.append({
                'name':    svc_name or name,
                'startup': startup or '?',
                'action':  action or '?',
                'gpo_act': gpo_action_map.get(gpo_action, gpo_action or 'Mettre à jour'),
                'alert':   alert,
            })
    except Exception:
        pass
    return services


def parse_psscripts_ini(content: str) -> dict:
    """Parse psscripts.ini — scripts PowerShell GPO.
    Même format que scripts.ini mais pour les scripts .ps1."""
    return parse_scripts(content, '', '', '')


def parse_gpttmpl(content: str) -> dict:
    """Parse GptTmpl.inf → dict {section: {clé_lowercase: valeur}}
    Robuste aux encodages mixtes, espaces parasites et sections inconnues.
    """
    result = {}
    content = content.replace('\r\n', '\n').replace('\r', '\n')
    if content.startswith('\ufeff'):
        content = content[1:]

    section_map = {
        "system access":           "system_access",
        "password policy":         "password_policy",
        "event audit":             "event_audit",
        "registry values":         "registry_values",
        "kerberos policy":         "kerberos_policy",
        "privilege rights":        "privilege_rights",
        "group membership":        "group_membership",
        "file security":           "file_security",
        "service general setting": "service_general",
        "registry keys":           "registry_keys",
        "application log":         "application_log",
        "system log":              "system_log",
        "security log":            "security_log",
        "unicode":                 "unicode",
        "version":                 "version",
    }
    current = None

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(';') or line.startswith('#'):
            continue
        if line.startswith('[') and line.endswith(']'):
            sec = line[1:-1].strip().lower()
            current = section_map.get(sec, sec.replace(' ', '_'))
            if current not in result:
                result[current] = {}
            continue
        if '=' in line and current is not None:
            key, _, val = line.partition('=')
            k = key.strip().lower()
            v = val.strip().strip('"')
            if current == 'registry_values':
                v = re.sub(r'\s*,\s*', ',', v)
            result[current][k] = v

    return result


def parse_registry_pol(data: bytes) -> list:
    """Parse Registry.pol → liste de (key_lower, value_name_lower, type, parsed_value)"""
    entries = []
    if len(data) < 8 or data[:4] != b'PReg':
        return entries

    offset = 8
    while offset < len(data) - 4:
        if data[offset:offset+2] != b'[\x00':
            offset += 2
            continue
        offset += 2

        def read_wstr(pos):
            end = pos
            while end + 1 < len(data):
                if data[end] == 0 and data[end+1] == 0:
                    break
                end += 2
            return data[pos:end].decode('utf-16-le', errors='replace'), end + 2

        key, offset = read_wstr(offset)
        if offset >= len(data) or data[offset:offset+2] != b';\x00':
            continue
        offset += 2
        value_name, offset = read_wstr(offset)
        if offset >= len(data) or data[offset:offset+2] != b';\x00':
            continue
        offset += 2
        if offset + 4 > len(data):
            break
        reg_type = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        if offset >= len(data) or data[offset:offset+2] != b';\x00':
            continue
        offset += 2
        if offset + 4 > len(data):
            break
        data_size = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        if offset >= len(data) or data[offset:offset+2] != b';\x00':
            continue
        offset += 2
        val_data = data[offset:offset+data_size]
        offset += data_size
        if offset < len(data) and data[offset:offset+2] == b']\x00':
            offset += 2

        if reg_type == 4 and len(val_data) >= 4:
            parsed_val = struct.unpack_from('<I', val_data)[0]
        elif reg_type == 1:
            parsed_val = val_data.decode('utf-16-le', errors='replace').rstrip('\x00')
        else:
            parsed_val = val_data.hex()

        entries.append((key.lower(), value_name.lower(), reg_type, parsed_val))

    return entries


# ─── Moteur RSOP (agrégat de toutes les GPO) ─────────────────────────────────

def detect_gpo_conflicts(gpos: list) -> list:
    """
    Détecte les conflits GPO : même paramètre configuré avec des valeurs DIFFÉRENTES
    dans au moins deux GPO actives.

    Distinction avec les redondances (true_duplicates) :
      - Redondance  = même clé, même valeur  → inutile mais inoffensif
      - Conflit     = même clé, valeurs diff → l'ordre d'application détermine
                      ce qui s'applique réellement, souvent involontaire.

    Règles de priorité Windows (simplifiées) :
      - GPO liée à une OU enfant > GPO liée à une OU parente
      - GPO Enforced écrase toujours les autres
      - À priorité égale : ordre dans gPLink (dernier = priorité haute)
      - Dans build_rsop : le dernier dans la liste gpos[] écrase le précédent

    Retourne une liste de conflits triés par criticité.
    """
    # Clés / sections à ignorer — métadonnées ou valeurs légitimement variables
    SKIP_KEYS = {
        'unicode', 'signature', 'revision', 'passwordexpirywarning',
        'lsaanonymousnamelookup', 'requirelogontochangepassword',
        'maximumlogsize',  # peut varier légitimement par type de log
    }
    SKIP_SECTIONS = {'unicode', 'version'}
    SKIP_KEY_PREFIXES = (
        'software\\policies\\microsoft\\systemcertificates',
        'software\\policies\\microsoft\\windows\\safer',
        'software\\microsoft\\systemcertificates',
    )

    # Paramètres de sécurité critiques — un conflit dessus mérite un warning fort
    SECURITY_SENSITIVE = {
        'minimumpasswordlength', 'passwordcomplexity', 'passwordhistorysize',
        'maximumpasswordage', 'lockoutbadcount', 'lockoutduration',
        'nolmhash', 'lmcompatibilitylevel', 'restrictanonymous',
        'enableguestaccount', 'auditlogonevents', 'auditaccountmanage',
        'auditpolicychange', 'uselogoncredential', 'smb1',
        'enablefirewall', 'enablelua', 'consentpromptbehavioradmin',
        'requiresecuritysignature', 'ldapclientintegrity', 'runasppl',
        'enablescriptblocklogging',
    }

    # Index : paramètre → liste de {gpo_name, gpo_guid, value, enforced}
    # Structure : { (section, key_lower) : [ {gpo, value, enforced, ou} ] }
    param_index: dict = {}

    def _add(section: str, key: str, value: str, gpo: dict):
        k = key.lower().strip()
        if k in SKIP_KEYS:
            return
        if section in SKIP_SECTIONS:
            return
        if any(k.startswith(p) for p in SKIP_KEY_PREFIXES):
            return
        composite = (section, k)
        if composite not in param_index:
            param_index[composite] = []
        is_enforced = any(l.get('enforced') for l in gpo.get('links', []))
        param_index[composite].append({
            'gpo_name':  gpo['name'],
            'gpo_guid':  gpo['guid'],
            'value':     str(value).strip(),
            'enforced':  is_enforced,
            'ou_count':  len(gpo.get('links', [])),
        })

    for gpo in gpos:
        if gpo.get('flags') == '3':   # GPO entièrement désactivée
            continue

        # ── GptTmpl.inf (settings) ──
        for section, params in gpo.get('settings', {}).items():
            if not params:
                continue
            for k, v in params.items():
                _add(section, k, v, gpo)

        # ── Registry.pol (binary) ──
        for (reg_key, vname, rtype, val) in gpo.get('registry_entries', []):
            sk = reg_key.lower().split('\\')[-1]   # clé courte
            _add('registry_pol', f"{reg_key}\\{vname}".lower(), str(val), gpo)

        # ── Registry Values dans GptTmpl.inf ──
        for k, v in gpo.get('settings', {}).get('registry_values', {}).items():
            _add('registry_values', k.lower(), str(v), gpo)

        # ── Registry.xml (préférences) ──
        for scope in ('registry_xml_machine', 'registry_xml_user'):
            for entry in gpo.get(scope, []):
                full = (
                    f"{entry.get('hive','').lower()}\\"
                    f"{entry.get('key','').lower()}\\"
                    f"{entry.get('name','').lower()}"
                )
                _add('registry_xml', full, str(entry.get('value', '')), gpo)

    # ── Analyser les conflits ──
    conflicts = []
    for (section, key), entries in param_index.items():
        if len(entries) < 2:
            continue

        # Dédupliquer par GPO (une GPO peut apparaître plusieurs fois si multiOU)
        seen_guids: dict = {}
        for e in entries:
            g = e['gpo_guid']
            if g not in seen_guids:
                seen_guids[g] = e
            else:
                # Garder la version "enforced" si applicable
                if e['enforced'] and not seen_guids[g]['enforced']:
                    seen_guids[g] = e
        unique_entries = list(seen_guids.values())

        if len(unique_entries) < 2:
            continue

        # Récupérer toutes les valeurs distinctes
        conflict_values = list({e['value'] for e in unique_entries})
        if len(conflict_values) < 2:
            continue   # Même valeur dans toutes les GPO → redondance, pas conflit

        # Identifier la GPO gagnante (dernière dans la liste = priorité haute dans build_rsop)
        # Parmi les GPO en conflit, la gagnante est celle avec enforced=True ou la dernière
        enforced_entries = [e for e in unique_entries if e['enforced']]
        winner = enforced_entries[-1] if enforced_entries else unique_entries[-1]
        losers = [e for e in unique_entries if e['gpo_guid'] != winner['gpo_guid']]

        # Niveau de criticité du conflit
        key_short = key.split('\\')[-1].lower()
        is_security = key_short in SECURITY_SENSITIVE or section in (
            'password_policy', 'system_access', 'event_audit'
        )
        severity = 'conflict_high' if is_security else 'conflict_low'

        # Label lisible
        section_labels = {
            'password_policy':  'Politique de mots de passe',
            'system_access':    'Accès système',
            'event_audit':      'Audit',
            'registry_pol':     'Registre (Registry.pol)',
            'registry_values':  'Registre (GptTmpl.inf)',
            'registry_xml':     'Registre (préférences XML)',
            'kerberos_policy':  'Stratégie Kerberos',
            'privilege_rights': 'Droits utilisateurs',
        }
        section_label = section_labels.get(section, section)

        # Alléger winner/losers — garder uniquement les champs affichés dans le HTML
        def _slim(e):
            return {
                'gpo_name': e['gpo_name'],
                'gpo_guid': e['gpo_guid'],
                'value':    e['value'],
                'enforced': e['enforced'],
            }

        conflicts.append({
            'section':         section,
            'section_label':   section_label,
            'key':             key,
            'key_short':       key_short,
            'is_security':     is_security,
            'conflict_values': conflict_values,
            'winner':          _slim(winner),
            'losers':          [_slim(l) for l in losers],
            'enforced_wins':   bool(enforced_entries),
            'gpo_count':       len(unique_entries),
            'label':           f"{section_label} → {key_short}",
        })

    # Trier : sécurité d'abord, puis nombre de GPO en conflit
    conflicts.sort(key=lambda c: (0 if c['is_security'] else 1, -c['gpo_count']))
    return conflicts[:100]   # cap à 100 pour ne pas exploser le JSON


def _enrich_gpos_for_search(gpos: list, gpo_reports: list) -> list:
    """Injecte findings et wmi_filter dans chaque GPO pour l'index de recherche."""
    report_by_guid = {r['guid']: r for r in gpo_reports}
    for gpo in gpos:
        report = report_by_guid.get(gpo['guid'], {})
        gpo['_findings_preview'] = [
            {'title': f['title'], 'severity': f['severity'], 'category': f.get('category', '')}
            for f in report.get('findings', [])
        ]
    return gpos


def build_search_index(gpos: list) -> list:
    """
    Construit un index de recherche exhaustif sur toutes les GPO.
    Chaque entrée représente un élément trouvable : paramètre, imprimante,
    lecteur, script, tâche, registre, service, groupe, variable, fichier...

    Structure d'une entrée :
    {
        'gpo_name':  str,   # nom de la GPO
        'gpo_guid':  str,   # GUID pour navigation
        'type':      str,   # catégorie (imprimante, script, registre, ...)
        'type_icon': str,   # emoji pour l'UI
        'key':       str,   # nom du paramètre / clé
        'value':     str,   # valeur / chemin / commande
        'context':   str,   # info supplémentaire (OU, action, utilisateur...)
        'search_blob': str, # texte concaténé pour la recherche full-text
    }
    """
    index = []

    # Labels lisibles pour les sections GptTmpl.inf
    SECTION_LABELS = {
        'password_policy':  ('Politique mots de passe', '🔑'),
        'system_access':    ('Accès système',            '🔒'),
        'event_audit':      ('Audit événements',         '📋'),
        'kerberos_policy':  ('Stratégie Kerberos',       '🎫'),
        'privilege_rights': ('Droits utilisateurs',      '👤'),
        'registry_values':  ('Registre (GptTmpl)',       '🗝'),
    }

    # Labels lisibles pour les clés GptTmpl.inf
    KEY_LABELS = {
        'minimumpasswordlength':    'Longueur minimale mot de passe',
        'maximumpasswordage':       'Durée max mot de passe (jours)',
        'minimumpasswordage':       'Durée min mot de passe (jours)',
        'passwordhistorysize':      'Historique mots de passe',
        'passwordcomplexity':       'Complexité requise',
        'lockoutbadcount':          'Seuil de verrouillage',
        'lockoutduration':          'Durée de verrouillage (min)',
        'resetlockoutcount':        'Réinitialisation compteur (min)',
        'nolmhash':                 'Stockage hash LM',
        'lmcompatibilitylevel':     'Niveau NTLM',
        'restrictanonymous':        'Restriction accès anonyme',
        'enableguestaccount':       'Compte Invité',
        'auditlogonevents':         'Audit connexions',
        'auditaccountmanage':       'Audit gestion comptes',
        'auditpolicychange':        'Audit changements stratégie',
        'auditprivilegeusse':       'Audit utilisation privilèges',
        'auditsystemevents':        'Audit événements système',
        'uselogoncredential':       'WDigest (mots de passe en clair)',
        'smb1':                     'SMBv1',
        'enablefirewall':           'Pare-feu Windows',
        'enablelua':                'UAC (EnableLUA)',
        'runasppl':                 'Protection LSASS (RunAsPPL)',
        'enablescriptblocklogging': 'PowerShell ScriptBlock Logging',
    }

    def _add(gpo, type_, icon, key, value, context=''):
        # search_blob est construit côté JS au premier chargement — pas besoin de le sérialiser
        index.append({
            'gpo_name':  gpo['name'],
            'gpo_guid':  gpo['guid'],
            'type':      type_,
            'type_icon': icon,
            'key':       key,
            'value':     str(value) if value is not None else '',
            'context':   context,
        })

    for gpo in gpos:
        name = gpo['name']
        guid = gpo['guid']

        # ── Nom de la GPO elle-même ──────────────────────────────────────────
        _add(gpo, 'GPO', '📄', 'Nom', name,
             f"{len(gpo.get('links', []))} lien(s) OU")

        # ── GptTmpl.inf (settings) ──────────────────────────────────────────
        for section, params in gpo.get('settings', {}).items():
            if not params:
                continue
            if section in ('unicode', 'version'):
                continue
            sec_label, sec_icon = SECTION_LABELS.get(section, (section, '⚙'))
            for k, v in params.items():
                key_label = KEY_LABELS.get(k.lower(), k)
                _add(gpo, sec_label, sec_icon, key_label, v, section)

        # ── Registry.pol (binaire) ──────────────────────────────────────────
        for (reg_key, vname, rtype, val) in gpo.get('registry_entries', []):
            short_key = reg_key.split('\\')[-1]
            _add(gpo, 'Registre (Registry.pol)', '🗝',
                 f"{short_key} → {vname}", str(val), reg_key)

        # ── Registry.pol utilisateur ─────────────────────────────────────────
        for (reg_key, vname, rtype, val) in gpo.get('registry_entries_user', []):
            short_key = reg_key.split('\\')[-1]
            _add(gpo, 'Registre utilisateur (Registry.pol)', '🗝',
                 f"{short_key} → {vname}", str(val), reg_key)

        # ── Imprimantes Machine ──────────────────────────────────────────────
        for p in gpo.get('printers', []):
            ctx = f"Action: {p.get('action','')} | Type: {p.get('type','')}"
            if p.get('default'):
                ctx += ' | Imprimante par défaut'
            if p.get('comment'):
                ctx += f" | {p['comment']}"
            _add(gpo, 'Imprimante (Machine)', '🖨',
                 p.get('name', ''), p.get('path', ''), ctx)

        # ── Imprimantes Utilisateur ──────────────────────────────────────────
        for p in gpo.get('printers_user', []):
            ctx = f"Action: {p.get('action','')} | Type: {p.get('type','')}"
            if p.get('default'):
                ctx += ' | Imprimante par défaut'
            _add(gpo, 'Imprimante (Utilisateur)', '🖨',
                 p.get('name', ''), p.get('path', ''), ctx)

        # ── Lecteurs réseau Machine ──────────────────────────────────────────
        for d in gpo.get('drives', []):
            _add(gpo, 'Lecteur réseau (Machine)', '💾',
                 f"{d.get('letter','')}:", d.get('path', ''),
                 f"Label: {d.get('label','')} | Action: {d.get('action','')}")

        # ── Lecteurs réseau Utilisateur ──────────────────────────────────────
        for d in gpo.get('drives_user', []):
            _add(gpo, 'Lecteur réseau (Utilisateur)', '💾',
                 f"{d.get('letter','')}:", d.get('path', ''),
                 f"Label: {d.get('label','')} | Action: {d.get('action','')}")

        # ── Raccourcis Machine ───────────────────────────────────────────────
        for s in gpo.get('shortcuts_machine', []):
            _add(gpo, 'Raccourci (Machine)', '🔗',
                 s.get('name', ''), s.get('target', ''),
                 f"Emplacement: {s.get('location','')} | Action: {s.get('action','')}")

        # ── Raccourcis Utilisateur ───────────────────────────────────────────
        for s in gpo.get('shortcuts_user', []):
            _add(gpo, 'Raccourci (Utilisateur)', '🔗',
                 s.get('name', ''), s.get('target', ''),
                 f"Emplacement: {s.get('location','')} | Action: {s.get('action','')}")

        # ── Scripts ─────────────────────────────────────────────────────────
        scripts = gpo.get('scripts', {})
        scope_labels = {
            'startup':  'Script démarrage machine',
            'shutdown': 'Script arrêt machine',
            'logon':    'Script ouverture session',
            'logoff':   'Script fermeture session',
        }
        for scope_key, scope_label in scope_labels.items():
            for sc in (scripts.get(scope_key) or []):
                if isinstance(sc, dict):
                    cmd    = sc.get('cmd', '')
                    params = sc.get('params', '')
                else:
                    cmd, params = str(sc), ''
                if cmd:
                    _add(gpo, scope_label, '📜',
                         cmd, params, scope_label)

        # ── Tâches planifiées ────────────────────────────────────────────────
        for t in gpo.get('scheduled_tasks', []):
            cmd = t.get('cmd', '') + (' ' + t.get('args', '') if t.get('args') else '')
            _add(gpo, 'Tâche planifiée', '⏰',
                 t.get('name', cmd), cmd,
                 f"Utilisateur: {t.get('user','')} | Action: {t.get('action','')}")

        # ── Groupes locaux ───────────────────────────────────────────────────
        for g in gpo.get('groups', []):
            members = ', '.join(m.get('name', '') for m in g.get('members', []))
            _add(gpo, 'Groupe local', '👥',
                 g.get('name', ''), members,
                 f"Action: {g.get('action','')}")
            # Indexer aussi les membres individuellement
            for m in g.get('members', []):
                _add(gpo, 'Membre de groupe', '👤',
                     m.get('name', ''), g.get('name', ''),
                     f"Groupe: {g.get('name','')} | Action: {m.get('action','')}")

        # ── Variables d'environnement ────────────────────────────────────────
        for v in gpo.get('env_vars', []):
            _add(gpo, "Variable d'environnement", '⚙',
                 v.get('name', ''), v.get('value', ''),
                 f"Action: {v.get('action','')}")

        # ── Services Windows ─────────────────────────────────────────────────
        for s in gpo.get('services', []):
            _add(gpo, 'Service Windows', '🔧',
                 s.get('name', ''),
                 f"{s.get('startup','')} / {s.get('action','')}",
                 f"Action GPO: {s.get('gpo_act','')}")

        # ── Copie de fichiers ────────────────────────────────────────────────
        for f in gpo.get('files_machine', []):
            _add(gpo, 'Copie de fichier (Machine)', '📁',
                 f.get('name', ''), f.get('dst', ''),
                 f"Source: {f.get('src','')} | Action: {f.get('action','')}")

        for f in gpo.get('files_user', []):
            _add(gpo, 'Copie de fichier (Utilisateur)', '📁',
                 f.get('name', ''), f.get('dst', ''),
                 f"Source: {f.get('src','')} | Action: {f.get('action','')}")

        # ── Audit avancé (audit.csv) ─────────────────────────────────────────
        for a in gpo.get('audit_csv', []):
            _add(gpo, 'Audit avancé', '🔍',
                 a.get('subcategory', ''), a.get('inclusion', ''),
                 'audit.csv')

        # ── Préférences Registre XML ─────────────────────────────────────────
        for scope, key in [('Machine', 'registry_xml_machine'),
                            ('Utilisateur', 'registry_xml_user')]:
            for r in gpo.get(key, []):
                full_key = (
                    f"{r.get('hive','').upper()}\\"
                    f"{r.get('key','')}\\"
                    f"{r.get('name','')}"
                ).rstrip('\\')
                _add(gpo, f'Préférences Registre ({scope})', '📋',
                     r.get('name', '') or r.get('key', ''),
                     str(r.get('value', '')),
                     f"{full_key} | Action: {r.get('action','')}")

        # ── Liens OU ────────────────────────────────────────────────────────
        for link in gpo.get('links', []):
            _add(gpo, 'Lien OU', '⊢',
                 link.get('ou', ''), '',
                 f"{'ENFORCED' if link.get('enforced') else 'Normal'}"
                 f"{' | Lien désactivé' if link.get('disabled') else ''}")

        # ── Findings de sécurité ─────────────────────────────────────────────
        for f in gpo.get('_findings_preview', []):
            _add(gpo, 'Constatation sécurité', '🔒',
                 f.get('title', ''), f.get('severity', ''), f.get('category', ''))

    return index


def _gpo_flags(gpo: dict) -> int:
    try: return int(gpo.get('flags', 0))
    except: return 0

def is_gpo_fully_disabled(gpo: dict) -> bool:
    return _gpo_flags(gpo) == 3

def is_gpo_computer_disabled(gpo: dict) -> bool:
    return _gpo_flags(gpo) in (1, 3)

def is_gpo_user_disabled(gpo: dict) -> bool:
    return _gpo_flags(gpo) in (2, 3)

def _ou_depth(ou_dn: str) -> int:
    return len([p for p in ou_dn.split(',') if p.strip().upper().startswith('OU=')])

def _gpo_max_depth(gpo: dict) -> int:
    links = gpo.get('links', [])
    if not links: return 0
    return max((_ou_depth(l.get('ou', '')) for l in links), default=0)

def build_rsop(gpos: list) -> tuple[dict, list]:
    """RSOP avec tri par profondeur OU (GPO domaine < OU parente < OU enfant < Enforced)."""
    """
    Construit le RSOP (Resultant Set of Policy) en agrégeant toutes les GPO.
    GPO priorité = ordre dans la liste (dernier = priorité la plus haute).
    Retourne (rsop_settings dict, rsop_registry list).
    """
    rsop_settings = {}
    rsop_registry = {}
    rsop_registry_xml = {}

    enforced_gpos = [g for g in gpos if any(l.get('enforced') for l in g.get('links', []))]
    normal_gpos   = [g for g in gpos if not any(l.get('enforced') for l in g.get('links', []))]
    normal_gpos.sort(key=_gpo_max_depth)
    enforced_gpos.sort(key=_gpo_max_depth)
    ordered_gpos = normal_gpos + enforced_gpos

    for gpo in ordered_gpos:
        if is_gpo_fully_disabled(gpo):
            continue

        # Fusionner les settings (dernier gagne = priorité la plus haute)
        for section, params in gpo.get('settings', {}).items():
            if not params:
                continue
            if section not in rsop_settings:
                rsop_settings[section] = {}
            for k, v in params.items():
                rsop_settings[section][k] = v

        # Fusionner les entrées registre (Registry.pol binaire)
        for (key, vname, rtype, val) in gpo.get('registry_entries', []):
            rsop_registry[(key, vname)] = val

        # Fusionner les préférences registre XML (Registry.xml)
        for scope in ('registry_xml_machine', 'registry_xml_user'):
            for entry in gpo.get(scope, []):
                # Normaliser la clé : HKEY_LOCAL_MACHINE\key\name
                hive = entry.get('hive', '').upper().replace('HKEY_LOCAL_MACHINE', 'HKLM').replace('HKEY_CURRENT_USER', 'HKCU')
                key_path = entry.get('key', '').lower()
                name = entry.get('name', '').lower()
                val_hex = entry.get('value', '')
                # Convertir la valeur hex en entier si possible
                try:
                    val_int = int(val_hex, 16) if val_hex.startswith('0') and len(val_hex) > 1 else int(val_hex)
                except (ValueError, TypeError):
                    val_int = val_hex
                full_key = f"{hive.lower()}\\{key_path}".replace('hkey_local_machine', 'hklm').replace('hkey_current_user', 'hkcu')
                rsop_registry_xml[(full_key, name)] = val_int

    rsop_reg_list = [(k, v, 4, val) for (k, v), val in rsop_registry.items()]
    return rsop_settings, rsop_reg_list, rsop_registry_xml


def int_val(v, default=0):
    try:
        return int(str(v).strip())
    except Exception:
        return default


def evaluate_rule_on_rsop(rule: dict, rsop_settings: dict, rsop_registry: dict) -> dict | None:
    """
    Évalue une règle sur le RSOP global.
    Retourne un finding si la règle est violée, None si conforme.
    'Non configuré dans le RSOP' = potentiellement un problème uniquement pour
    les règles critiques de sécurité explicites.
    """
    section = rule['section']
    operator = rule.get('operator', '')

    # ── Règles registre (Registry.pol) ──
    if section == 'registry':
        key_lower = rule['reg_key'].lower()
        val_lower = rule['reg_value'].lower()
        expected = rule['reg_expected']
        actual = rsop_registry.get((key_lower, val_lower), None)

        if actual is None:
            # Non configuré via GPO = impossible de conclure sans SYSVOL
            # Signaler en 'info' uniquement (pas une violation certaine)
            return {
                'rule_id': rule['id'],
                'title': rule['title'],
                'severity': 'info',
                'ref': rule['ref'],
                'category': rule['category'],
                'remediation': rule['remediation'],
                'detail': f"Non configuré via GPO (valeur attendue : {expected}). "
                          f"Monter le SYSVOL pour vérifier la valeur réelle via Registry.pol.",
                'not_configured': True,
            }
        if actual != expected:
            return {
                'rule_id': rule['id'],
                'title': rule['title'],
                'severity': rule['severity'],
                'ref': rule['ref'],
                'category': rule['category'],
                'remediation': rule['remediation'],
                'detail': f"Valeur appliquée : {actual} (attendu : {expected})",
                'not_configured': False,
            }
        return None  # Conforme

    # ── Règles GptTmpl.inf ──
    sec = rsop_settings.get(section, {})
    check_key = rule.get('check_key', '').lower()
    raw = sec.get(check_key)

    if raw is None:
        # Non configuré dans le RSOP = la valeur par défaut Windows s'applique.
        # On ne peut pas conclure à une violation sans lire le SYSVOL.
        # On remonte uniquement en 'info' pour signaler que c'est à vérifier.
        if rule['severity'] in ('critical', 'warning'):
            return {
                'rule_id': rule['id'],
                'title': rule['title'],
                'severity': 'info',   # Dégradé : on ne sait pas, pas une violation certaine
                'ref': rule['ref'],
                'category': rule['category'],
                'remediation': rule['remediation'],
                'detail': "Non configuré explicitement via GPO — valeur par défaut Windows appliquée. "
                          "Monter le SYSVOL pour une analyse complète (Registry.pol + GptTmpl.inf).",
                'not_configured': True,
            }
        return None

    actual = int_val(raw)
    threshold = rule.get('threshold', 0)
    violated = False

    if operator == 'lt' and actual < threshold:
        violated = True
    elif operator == 'gt' and actual > threshold and actual != 0:
        violated = True
    elif operator == 'gt_or_zero' and (actual == 0 or actual > threshold):
        violated = True
    elif operator == 'ne' and actual != threshold:
        violated = True
    elif operator == 'eq' and actual == threshold:
        violated = True

    if violated:
        op_str = {'lt': f'< {threshold}', 'gt': f'> {threshold}',
                  'ne': f'≠ {threshold}', 'eq': str(threshold),
                  'gt_or_zero': f'= 0 ou > {threshold}'}.get(operator, str(threshold))
        return {
            'rule_id': rule['id'],
            'title': rule['title'],
            'severity': rule['severity'],
            'ref': rule['ref'],
            'category': rule['category'],
            'remediation': rule['remediation'],
            'detail': f"Valeur appliquée par le RSOP : {actual} (attendu : {op_str})",
            'not_configured': False,
        }
    return None  # Conforme


def evaluate_rule_on_gpo(rule: dict, settings: dict, registry_entries: list) -> dict | None:
    """
    Évalue une règle sur une GPO individuelle.
    Ne remonte un finding QUE si la GPO configure explicitement une mauvaise valeur.
    Si le paramètre est absent → None (la GPO ne parle pas de ça).
    """
    section = rule['section']
    operator = rule.get('operator', '')

    if section == 'registry':
        key_lower = rule['reg_key'].lower()
        val_lower = rule['reg_value'].lower()
        expected = rule['reg_expected']
        reg_dict = {(e[0], e[1]): e[3] for e in registry_entries}
        actual = reg_dict.get((key_lower, val_lower), None)
        if actual is None:
            return None  # GPO ne configure pas ce paramètre → pas un finding sur cette GPO
        if actual != expected:
            return {
                'rule_id': rule['id'],
                'title': rule['title'],
                'severity': rule['severity'],
                'ref': rule['ref'],
                'category': rule['category'],
                'remediation': rule['remediation'],
                'detail': f"Valeur : {actual} (attendu : {expected})",
            }
        return None

    sec = settings.get(section, {})
    check_key = rule.get('check_key', '').lower()
    raw = sec.get(check_key)
    if raw is None:
        return None  # GPO ne configure pas ce paramètre → pas un finding sur cette GPO

    actual = int_val(raw)
    threshold = rule.get('threshold', 0)
    violated = False

    if operator == 'lt' and actual < threshold:
        violated = True
    elif operator == 'gt' and actual > threshold and actual != 0:
        violated = True
    elif operator == 'gt_or_zero' and (actual == 0 or actual > threshold):
        violated = True
    elif operator == 'ne' and actual != threshold:
        violated = True
    elif operator == 'eq' and actual == threshold:
        violated = True

    if not violated:
        return None

    op_str = {'lt': f'< {threshold}', 'gt': f'> {threshold}',
              'ne': f'≠ {threshold}', 'eq': str(threshold),
              'gt_or_zero': f'= 0 ou > {threshold}'}.get(operator, str(threshold))
    return {
        'rule_id': rule['id'],
        'title': rule['title'],
        'severity': rule['severity'],
        'ref': rule['ref'],
        'category': rule['category'],
        'remediation': rule['remediation'],
        'detail': f"Valeur : {actual} (attendu : {op_str})",
    }


# ─── Collecteur LDAP + SYSVOL ───────────────────────────────────────────────

class GPOCollector:
    def __init__(self, dc, domain, username, password, use_ssl=False, sysvol_path=None):
        self.dc = dc
        self.domain = domain
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.sysvol_path = sysvol_path  # chemin local monté, ex: /mnt/sysvol
        self.conn = None
        self.base_dn = ','.join(f'DC={p}' for p in domain.split('.'))

    def connect_ldap(self):
        port = 636 if self.use_ssl else 389
        server = Server(self.dc, port=port, use_ssl=self.use_ssl, get_info=ALL)
        user = f"{self.domain}\\{self.username}"
        try:
            self.conn = Connection(server, user=user, password=self.password,
                                   authentication=NTLM, auto_bind=True)
            print(f"[+] LDAP connecté à {self.dc}")
            return True
        except LDAPException as e:
            print(f"[!] Erreur LDAP : {e}")
            return False

    def get_gpos_from_ldap(self):
        gpo_dn = f"CN=Policies,CN=System,{self.base_dn}"
        self.conn.search(
            search_base=gpo_dn,
            search_filter='(objectClass=groupPolicyContainer)',
            search_scope=SUBTREE,
            attributes=['displayName', 'cn', 'gPCFileSysPath',
                        'versionNumber', 'flags', 'whenCreated', 'whenChanged',
                        'gPCWQLFilter'],
        )
        wmi_filters = self._get_wmi_filters()
        gpos = []
        for entry in self.conn.entries:
            guid = str(entry.cn) if entry.cn else ''
            sysvol = str(entry.gPCFileSysPath) if entry.gPCFileSysPath else ''
            if not guid:
                continue
            wql_filter_dn = str(entry.gPCWQLFilter) if entry.gPCWQLFilter else ''
            wmi_info = None
            if wql_filter_dn and wql_filter_dn not in ('', 'None', '[]'):
                wmi_guid_m = re.search(r'\{([0-9A-Fa-f-]{36})\}', wql_filter_dn)
                if wmi_guid_m:
                    wmi_guid = '{' + wmi_guid_m.group(1).upper() + '}'
                    wmi_info = wmi_filters.get(wmi_guid, {
                        'guid': wmi_guid, 'name': wmi_guid,
                        'query': wql_filter_dn, 'description': '',
                    })
            gpos.append({
                'name': str(entry.displayName) if entry.displayName else f'GPO-{guid[:8]}',
                'guid': guid,
                'sysvol_path': sysvol,
                'version': str(entry.versionNumber) if entry.versionNumber else '0',
                'flags': str(entry.flags) if entry.flags else '0',
                'created': str(entry.whenCreated) if entry.whenCreated else '',
                'changed': str(entry.whenChanged) if entry.whenChanged else '',
                'links': [],
                'settings': {},
                'registry_entries': [],
                'wmi_filter': wmi_info,
            })
        print(f"[+] {len(gpos)} GPO trouvées ({sum(1 for g in gpos if g['wmi_filter'])} avec filtre WMI)")
        return gpos

    def _get_wmi_filters(self) -> dict:
        """Récupère les filtres WMI depuis l'AD."""
        filters = {}
        try:
            wmi_dn = f"CN=SOM,CN=WMIPolicy,CN=System,{self.base_dn}"
            self.conn.search(search_base=wmi_dn, search_filter='(objectClass=msWMI-Som)',
                             search_scope=SUBTREE, attributes=['cn','msWMI-Name','msWMI-Parm1','msWMI-Parm2'])
            for entry in self.conn.entries:
                guid = str(entry.cn) if entry.cn else ''
                if not guid: continue
                name  = str(getattr(entry, 'msWMI-Name',  '') or '')
                desc  = str(getattr(entry, 'msWMI-Parm1', '') or '')
                query = str(getattr(entry, 'msWMI-Parm2', '') or '')
                wql_m = re.search(r'SELECT\s+.+', query, re.IGNORECASE | re.DOTALL)
                clean = wql_m.group(0).strip() if wql_m else query[:200]
                filters['{' + guid.strip('{}').upper() + '}'] = {
                    'guid': guid, 'name': name or guid,
                    'query': clean, 'description': desc,
                }
        except Exception:
            pass
        return filters

    def get_gpo_links(self):
        self.conn.search(
            search_base=self.base_dn,
            search_filter='(gPLink=*)',
            search_scope=SUBTREE,
            attributes=['distinguishedName', 'gPLink'],
        )
        links = {}
        # Regex robuste : UUID format standard dans un bloc [LDAP://...;flag]
        GPLINK_RE = re.compile(
            r'\[LDAP://[^\]]*\{([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}'
            r'-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}[^;]*;(\d+)\]',
            re.IGNORECASE
        )
        for entry in self.conn.entries:
            gp_link = str(entry.gPLink)
            ou_dn = str(entry.distinguishedName)
            for m in GPLINK_RE.finditer(gp_link):
                guid = '{' + m.group(1).upper() + '}'
                flag = int(m.group(2))
                links.setdefault(guid, []).append({
                    'ou': ou_dn, 'flags': flag,
                    'enforced': flag & 2 != 0, 'disabled': flag & 1 != 0,
                })
        return links

    def _init_smb(self):
        """Connexion SMB via impacket — pas besoin de mount.cifs."""
        try:
            from impacket.smbconnection import SMBConnection
            smb = SMBConnection(self.dc, self.dc, timeout=10)
            smb.login(self.username, self.password, self.domain)
            self._smb = smb
            # Détecter le nom exact du partage SYSVOL
            all_shares = [s['shi1_netname'].rstrip('\x00') for s in smb.listShares()]
            sysvol_shares = [s for s in all_shares if s.upper() == 'SYSVOL']
            self._sysvol_share = sysvol_shares[0] if sysvol_shares else 'SYSVOL'
            print(f"    [+] SMB connecté — partages : {all_shares}")

            # Test de lecture immédiat sur la Default Domain Policy (toujours présente)
            test_path = f"\\{self.domain}\\Policies\\{{31B2F340-016D-11D2-945F-00C04FB984F9}}\\GPT.INI"
            buf = []
            try:
                smb.getFile(self._sysvol_share, test_path, buf.append)
                print(f"    [+] Lecture SYSVOL OK ({len(b''.join(buf))} octets)")
            except Exception as e_test:
                # Essai avec chemin court sans domaine
                test_path2 = f"\\Policies\\{{31B2F340-016D-11D2-945F-00C04FB984F9}}\\GPT.INI"
                buf2 = []
                try:
                    smb.getFile(self._sysvol_share, test_path2, buf2.append)
                    print(f"    [+] Lecture SYSVOL OK (chemin court, {len(b''.join(buf2))} octets)")
                    self._smb_path_prefix = ''  # pas de préfixe domaine
                except Exception:
                    print(f"    [!] Lecture SYSVOL échoue : {e_test}")
                    print(f"    [!] Chemin testé : {test_path}")

            return True
        except Exception as e:
            self._smb = None
            self._sysvol_share = 'SYSVOL'
            print(f"    [!] SMB direct indisponible : {e}")
            return False

    def _smb_read(self, share: str, rel_path: str) -> bytes | None:
        """Lit un fichier via SMB impacket."""
        if not getattr(self, '_smb', None):
            return None
        try:
            buf = []
            self._smb.getFile(share, rel_path, buf.append)
            data = b''.join(buf)
            return data if data else None
        except Exception as e:
            # Ignorer les erreurs "fichier non trouvé" (normales pour les GPO partielles)
            # Logger les erreurs inattendues (connexion perdue, timeout...)
            msg = str(e).lower()
            if not any(x in msg for x in ('no such', 'not found', 'object_name', 'status_object',
                                           'file not', 'path not', 'bad network')):
                if getattr(self, '_smb_errors', 0) < 3:  # Max 3 warnings pour ne pas spammer
                    self._smb_errors = getattr(self, '_smb_errors', 0) + 1
                    print(f"    [!] SMB inattendu sur {rel_path[-50:]}: {e}")
            return None

    def _unc_to_parts(self, unc_path: str):
        """Extrait la liste des segments apres Policies depuis un chemin UNC."""
        import re
        parts = [p for p in re.split(r'[/\\]+', unc_path) if p]
        try:
            pol_idx = next(i for i, p in enumerate(parts) if p.lower() == 'policies')
            return parts[pol_idx + 1:]
        except StopIteration:
            return []

    def read_file_bytes(self, unc_path: str) -> bytes | None:
        after = self._unc_to_parts(unc_path)
        if not after:
            return None

        # Priorité 1 : SYSVOL monté localement
        if self.sysvol_path:
            for dom in [self.domain, self.domain.upper(), self.domain.lower()]:
                path = os.path.join(self.sysvol_path, dom, 'Policies', *after)
                if os.path.exists(path):
                    with open(path, 'rb') as f:
                        return f.read()

        # Priorité 2 : lecture SMB directe via impacket
        if getattr(self, '_smb', None):
            rel = '\\' + self.domain + '\\Policies\\' + '\\'.join(after)
            data = self._smb_read(self._sysvol_share, rel)
            if data is not None:
                return data
            rel2 = '\\' + '\\'.join(after)
            data = self._smb_read(self._sysvol_share, rel2)
            if data is not None:
                return data
            # Debug : log les échecs sur les fichiers XML de préférences
            fname = after[-1] if after else '?'
            if fname.endswith('.xml') or fname.endswith('.XML'):
                print(f"      [debug] {fname} introuvable — rel={rel[-70:]}")

        return None

    def read_file_text(self, unc_path: str) -> str | None:
        data = self.read_file_bytes(unc_path)
        if data is None:
            return None
        for enc in ('utf-16', 'utf-8', 'latin-1'):
            try:
                return data.decode(enc)
            except Exception:
                continue
        return None

    def collect_gpo_settings(self, gpo: dict):
        raw_base = gpo['sysvol_path']
        if not raw_base:
            return

        import re as _re
        # Décomposer le base en segments (insensible au nb de backslashes)
        segs_base = [s for s in _re.split(r'[/\\]+', raw_base) if s]
        # segs_base ex: ['sdis25.lan', 'SysVol', 'sdis25.lan', 'Policies', '{GUID}']
        if not segs_base or not any(s.lower() == 'policies' for s in segs_base):
            # Chemin SYSVOL invalide ou inattendu — on ne peut pas lire cette GPO
            return

        def smb_rel(*parts):
            """Chemin relatif impacket : \\domaine\\Policies\\{GUID}\\..."""
            try:
                pol_i = next(i for i,s in enumerate(segs_base) if s.lower() == 'policies')
                after = segs_base[pol_i+1:] + list(parts)
            except StopIteration:
                after = segs_base + list(parts)
            return '\\' + self.domain + '\\Policies\\' + '\\'.join(after)

        def rb(*parts):
            """Lit un fichier en bytes via SMB."""
            if not getattr(self, '_smb', None):
                return None
            return self._smb_read(self._sysvol_share, smb_rel(*parts))

        def rx(*parts):
            """Lit un fichier XML."""
            data = rb(*parts)
            if not data:
                return None
            for enc in ('utf-16', 'utf-8', 'latin-1'):
                try:
                    txt = data.decode(enc)
                    if '<' in txt:
                        return txt
                except Exception:
                    continue
            return None

        def rt(*parts):
            """Lit un fichier texte."""
            data = rb(*parts)
            if not data:
                return None
            for enc in ('utf-16', 'utf-8', 'latin-1'):
                try:
                    return data.decode(enc)
                except Exception:
                    continue
            return None

        # ── Machine : sécurité ──
        inf = rt('Machine', 'Microsoft', 'Windows NT', 'SecEdit', 'GptTmpl.inf')
        if inf:
            gpo['settings'] = parse_gpttmpl(inf)

        # ── Machine : registre ──
        pol = rb('Machine', 'Registry.pol')
        if pol:
            gpo['registry_entries'] = parse_registry_pol(pol)

        # ── User : registre ──
        pol_u = rb('User', 'Registry.pol')
        if pol_u:
            gpo['registry_entries_user'] = parse_registry_pol(pol_u)

        # ── Préférences Machine ──
        x = rx('Machine', 'Preferences', 'Printers', 'Printers.xml')
        if x: gpo['printers'] = parse_printers_xml(x)

        x = rx('Machine', 'Preferences', 'Drives', 'Drives.xml')
        if x: gpo['drives'] = parse_drives_xml(x)

        x = rx('Machine', 'Preferences', 'Shortcuts', 'Shortcuts.xml')
        if x: gpo['shortcuts_machine'] = parse_shortcuts_xml(x)

        x = rx('Machine', 'Preferences', 'ScheduledTasks', 'ScheduledTasks.xml')
        if x: gpo['scheduled_tasks'] = parse_scheduledtasks_xml(x)

        x = rx('Machine', 'Preferences', 'Groups', 'Groups.xml')
        if x: gpo['groups'] = parse_groups_xml(x)

        x = rx('Machine', 'Preferences', 'EnvironmentVariables', 'EnvironmentVariables.xml')
        if x: gpo['env_vars'] = parse_envvars_xml(x)

        x = rx('Machine', 'Preferences', 'Files', 'Files.xml')
        if x: gpo['files_machine'] = parse_files_xml(x)

        x = rx('User', 'Preferences', 'Files', 'Files.xml')
        if x: gpo['files_user'] = parse_files_xml(x)

        x = rx('Machine', 'Preferences', 'Services', 'Services.xml')
        if x: gpo['services'] = parse_services_xml(x)

        x = rt('Machine', 'Microsoft', 'Windows NT', 'Audit', 'audit.csv')
        if x: gpo['audit_csv'] = parse_audit_csv(x)

        # psscripts.ini (PowerShell) — complète scripts.ini
        ps_m = rt('Machine', 'Scripts', 'psscripts.ini')
        ps_u = rt('User', 'Scripts', 'psscripts.ini')
        if ps_m or ps_u:
            ps = parse_psscripts_ini(ps_m or '')
            ps_u_parsed = parse_psscripts_ini(ps_u or '')
            # Fusionner avec les scripts existants
            existing = gpo.get('scripts', {'startup':[],'shutdown':[],'logon':[],'logoff':[]})
            for k in ('startup', 'shutdown'):
                existing[k] = existing.get(k, []) + ps.get(k, [])
            for k in ('logon', 'logoff'):
                existing[k] = existing.get(k, []) + ps_u_parsed.get(k, [])
            if any(existing.values()):
                gpo['scripts'] = existing

        # ── Préférences User ──
        x = rx('User', 'Preferences', 'Printers', 'Printers.xml')
        if x: gpo['printers_user'] = parse_printers_xml(x)

        x = rx('User', 'Preferences', 'Drives', 'Drives.xml')
        if x: gpo['drives_user'] = parse_drives_xml(x)

        x = rx('User', 'Preferences', 'Shortcuts', 'Shortcuts.xml')
        if x: gpo['shortcuts_user'] = parse_shortcuts_xml(x)

        # ── Préférences Registre XML (Registry.xml) ──
        x = rx('Machine', 'Preferences', 'Registry', 'Registry.xml')
        if x: gpo['registry_xml_machine'] = parse_registry_xml(x)

        x = rx('User', 'Preferences', 'Registry', 'Registry.xml')
        if x: gpo['registry_xml_user'] = parse_registry_xml(x)

        # ── Scripts ──
        sm_ini = rt('Machine', 'Scripts', 'scripts.ini')
        su_ini = rt('User', 'Scripts', 'scripts.ini')
        sc = parse_scripts(sm_ini, sm_ini, su_ini, su_ini)
        if not any(sc.values()):
            sc['startup']  = [{'cmd': f.get_longname(), 'params': ''} for f in self._list_scripts(smb_rel('Machine', 'Scripts', 'Startup'))]
            sc['shutdown'] = [{'cmd': f.get_longname(), 'params': ''} for f in self._list_scripts(smb_rel('Machine', 'Scripts', 'Shutdown'))]
            sc['logon']    = [{'cmd': f.get_longname(), 'params': ''} for f in self._list_scripts(smb_rel('User', 'Scripts', 'Logon'))]
            sc['logoff']   = [{'cmd': f.get_longname(), 'params': ''} for f in self._list_scripts(smb_rel('User', 'Scripts', 'Logoff'))]
        if any(sc.values()):
            gpo['scripts'] = sc

        # ── Log résumé ──
        parts = []
        if gpo.get('settings'): parts.append('sécurité')
        if gpo.get('registry_entries'): parts.append(f"{len(gpo['registry_entries'])} reg.machine")
        if gpo.get('registry_entries_user'): parts.append(f"{len(gpo['registry_entries_user'])} reg.user")
        if gpo.get('printers') or gpo.get('printers_user'): parts.append('imprimantes')
        if gpo.get('drives') or gpo.get('drives_user'): parts.append('lecteurs')
        if gpo.get('shortcuts_machine') or gpo.get('shortcuts_user'): parts.append('raccourcis')
        if gpo.get('scheduled_tasks'): parts.append('tâches')
        if gpo.get('scripts'): parts.append('scripts')
        if gpo.get('groups'): parts.append('groupes')
        if gpo.get('env_vars'): parts.append('vars env')
        if gpo.get('registry_xml_machine') or gpo.get('registry_xml_user'): parts.append('registre XML')
        if gpo.get('files_machine') or gpo.get('files_user'): parts.append('fichiers')
        if gpo.get('services'): parts.append('services')
        if gpo.get('audit_csv'): parts.append('audit avancé')
        if parts:
            print(f"    [+] {gpo['name']} : {', '.join(parts)}")

    def _list_scripts(self, rel_path: str) -> list:
        """Liste les scripts dans un dossier SYSVOL via SMB."""
        if not getattr(self, '_smb', None):
            return []
        try:
            files = self._smb.listPath(self._sysvol_share, rel_path + '\\*')
            return [f for f in files if f.get_longname() not in ('..', '.', '')]
        except Exception:
            return []

    def collect_all(self):
        if not self.connect_ldap():
            return None
        gpos = self.get_gpos_from_ldap()
        links = self.get_gpo_links()

        # Connexion SMB directe via impacket (pas besoin de mount.cifs)
        self._init_smb()

        total = len(gpos)
        for i, gpo in enumerate(gpos, 1):
            gpo['links'] = links.get(gpo['guid'].upper(), [])
            self.collect_gpo_settings(gpo)
            if i % 50 == 0 or i == total:
                print(f"    [*] {i}/{total} GPO traitées...")
        self.conn.unbind()
        if getattr(self, '_smb', None):
            try:
                self._smb.logoff()
            except Exception:
                pass
        return gpos



# ─── Mode démo ──────────────────────────────────────────────────────────────

def generate_demo_data() -> list:
    return [
        {
            'name': 'Default Domain Policy',
            'guid': '{31B2F340-016D-11D2-945F-00C04FB984F9}',
            'sysvol_path': '', 'version': '5', 'flags': '0',
            'created': '2020-01-15', 'changed': '2024-03-01',
            'links': [{'ou': 'DC=corp,DC=local', 'flags': 0, 'enforced': False, 'disabled': False}],
            'settings': {
                'password_policy': {
                    'minimumpasswordlength': '8',
                    'passwordhistorysize': '5',
                    'passwordcomplexity': '0',
                    'maximumpasswordage': '42',
            'wmi_filter': None,
                },
                'system_access': {
                    'lockoutbadcount': '0',
                    'lockoutduration': '30',
                    'nolmhash': '0',
                    'lmcompatibilitylevel': '1',
                    'restrictanonymous': '0',
                    'enableguestaccount': '0',
            'wmi_filter': None,
                },
                'event_audit': {
                    'auditlogonevents': '0',
                    'auditaccountmanage': '0',
                    'auditpolicychange': '0',
            'wmi_filter': None,
                },
            'wmi_filter': None,
            },
            'registry_entries': [
                (r'hklm\system\currentcontrolset\control\securityproviders\wdigest',
                 'uselogoncredential', 4, 1),
                (r'hklm\system\currentcontrolset\services\lanmanserver\parameters',
                 'smb1', 4, 1),
            ],
            'wmi_filter': None,
        },
        {
            'name': 'GPO_Sécurité_Postes_WS2022',
            'guid': '{A45E3C8D-1234-5678-ABCD-EF0123456789}',
            'sysvol_path': '', 'version': '12', 'flags': '0',
            'created': '2022-06-10', 'changed': '2025-01-15',
            'links': [
                {'ou': 'OU=Workstations,DC=corp,DC=local', 'flags': 0, 'enforced': False, 'disabled': False},
                {'ou': 'OU=Laptops,DC=corp,DC=local', 'flags': 0, 'enforced': False, 'disabled': False},
            ],
            'settings': {
                'password_policy': {
                    'minimumpasswordlength': '16',
                    'passwordhistorysize': '24',
                    'passwordcomplexity': '1',
                    'maximumpasswordage': '90',
            'wmi_filter': None,
                },
                'system_access': {
                    'nolmhash': '1',
                    'lmcompatibilitylevel': '5',
                    'enableguestaccount': '0',
                    'lockoutbadcount': '5',
                    'lockoutduration': '30',
                    'restrictanonymous': '1',
            'wmi_filter': None,
                },
                'event_audit': {
                    'auditlogonevents': '3',
                    'auditaccountmanage': '3',
                    'auditpolicychange': '3',
            'wmi_filter': None,
                },
            'wmi_filter': None,
            },
            'registry_entries': [
                (r'hklm\software\policies\microsoft\windowsfirewall\domainprofile',
                 'enablefirewall', 4, 1),
                (r'hklm\software\microsoft\windows\currentversion\policies\explorer',
                 'nodrivetypeautorun', 4, 255),
                (r'hklm\system\currentcontrolset\control\deviceguard',
                 'enablevirtualizationbasedsecurity', 4, 1),
                (r'hklm\system\currentcontrolset\control\securityproviders\wdigest',
                 'uselogoncredential', 4, 0),
                (r'hklm\system\currentcontrolset\services\lanmanserver\parameters',
                 'smb1', 4, 0),
            ],
            'printers': [
                {'name': 'HP LaserJet Bureau', 'path': r'\\print01\HP-Bureau', 'action': 'U', 'default': True},
                {'name': 'Ricoh Salle Reunion', 'path': r'\\print01\Ricoh-SR', 'action': 'U', 'default': False},
            ],
            'drives': [
                {'letter': 'H', 'path': r'\\file01\homes\%username%', 'label': 'Mon dossier', 'action': 'U'},
                {'letter': 'S', 'path': r'\\file01\shared', 'label': 'Partage commun', 'action': 'U'},
            ],
            'shortcuts_user': [
                {'name': 'Intranet', 'target': 'https://intranet.corp.local', 'location': 'Bureau', 'action': 'C'},
            ],
            'scripts': {
                'startup': [{'cmd': r'\\file01\scripts\map_drives.ps1', 'params': ''}],
                'shutdown': [], 'logon': [], 'logoff': [],
            'wmi_filter': None,
            },
            'scheduled_tasks': [
                {'name': 'Sauvegarde profil', 'cmd': 'robocopy.exe',
                 'args': r'%USERPROFILE% \\backup01\profiles', 'user': 'SYSTEM', 'action': 'C'},
            ],
            'wmi_filter': None,
        },
        {
            'name': 'GPO_Désactivations_Legacy',
            'guid': '{B12C4D5E-9876-5432-FEDC-BA9876543210}',
            'sysvol_path': '', 'version': '3', 'flags': '0',
            'created': '2019-03-20', 'changed': '2021-11-05',
            'links': [{'ou': 'OU=Legacy,DC=corp,DC=local', 'flags': 0, 'enforced': False, 'disabled': False}],
            'settings': {'password_policy': {}, 'system_access': {}, 'event_audit': {}},
            'registry_entries': [
                (r'hklm\software\policies\microsoft\windowsfirewall\domainprofile',
                 'enablefirewall', 4, 0),  # Pare-feu OFF — mauvaise pratique
            ],
            'wmi_filter': None,
        },
        {
            'name': 'GPO_Chiffrement_BitLocker',
            'guid': '{C23D5E6F-AAAA-BBBB-CCCC-DDDDEEEEFFFF}',
            'sysvol_path': '', 'version': '8', 'flags': '0',
            'created': '2023-01-10', 'changed': '2024-08-20',
            'links': [{'ou': 'OU=Computers,DC=corp,DC=local', 'flags': 2, 'enforced': True, 'disabled': False}],
            'settings': {'password_policy': {}, 'system_access': {}, 'event_audit': {}},
            'registry_entries': [],
            'wmi_filter': None,
        },
        {
            'name': 'GPO_Legacy_XP_Obsolete',
            'guid': '{D34E6F70-1111-2222-3333-444455556666}',
            'sysvol_path': '', 'version': '1', 'flags': '0',
            'created': '2008-05-12', 'changed': '2010-02-01',
            'links': [],  # Orpheline
            'settings': {'password_policy': {}, 'system_access': {}, 'event_audit': {}},
            'registry_entries': [],
            'wmi_filter': None,
        },
        # ── GPO générant des conflits démontrables ──
        {
            'name': 'GPO_Audit_Serveurs',
            'guid': '{E45F7081-2222-3333-4444-555566667777}',
            'sysvol_path': '', 'version': '4', 'flags': '0',
            'created': '2021-09-01', 'changed': '2023-06-15',
            'links': [{'ou': 'OU=Servers,DC=corp,DC=local', 'flags': 0, 'enforced': False, 'disabled': False}],
            'settings': {
                'password_policy': {
                    # Conflit sécurité : longueur différente de Default Domain Policy (8) et GPO_Sécurité (16)
                    'minimumpasswordlength': '12',
                    'maximumpasswordage': '180',   # Conflit avec Default (42) et Sécurité (90)
            'wmi_filter': None,
                },
                'event_audit': {
                    # Conflit audit : valeur différente de GPO_Sécurité_Postes (3)
                    'auditlogonevents':   '1',    # Succès seulement vs Succès+Échec
                    'auditaccountmanage': '2',    # Échec seulement
            'wmi_filter': None,
                },
                'system_access': {
                    'lmcompatibilitylevel': '3',   # Conflit : Default=1, Sécurité=5, ici=3
                    'lockoutbadcount': '15',        # Conflit : Default=0, Sécurité=5, ici=15
            'wmi_filter': None,
                },
            'wmi_filter': None,
            },
            'registry_entries': [
                # Conflit registre : pare-feu OFF ici vs ON dans GPO_Sécurité
                (r'hklm\software\policies\microsoft\windowsfirewall\domainprofile',
                 'enablefirewall', 4, 0),
            ],
            'wmi_filter': None,
        },
        {
            'name': 'GPO_Conformité_RGPD',
            'guid': '{F5608892-3333-4444-5555-666677778888}',
            'sysvol_path': '', 'version': '2', 'flags': '0',
            'created': '2022-05-20', 'changed': '2022-11-30',
            'links': [{'ou': 'OU=Workstations,DC=corp,DC=local', 'flags': 0, 'enforced': False, 'disabled': False}],
            'settings': {
                'password_policy': {
                    # Conflit : encore une valeur différente pour minimumpasswordlength
                    'minimumpasswordlength': '10',
                    'passwordhistorysize': '12',    # Conflit avec Default (5) et Sécurité (24)
            'wmi_filter': None,
                },
                'system_access': {
                    'lockoutduration': '5',         # Conflit : Sécurité=30, ici=5
                    'nolmhash': '1',                # Pas de conflit (même valeur que Sécurité)
            'wmi_filter': None,
                },
            'wmi_filter': None,
            },
            'registry_entries': [],
            'wmi_filter': None,
        },
    ]


# ─── Analyse ─────────────────────────────────────────────────────────────────

# Labels lisibles pour les clés GptTmpl.inf
_LABELS = {
    # Password Policy
    'minimumpasswordlength':    ('Longueur minimale mot de passe', 'caractères'),
    'maximumpasswordage':       ('Durée max mot de passe', 'jours'),
    'minimumpasswordage':       ('Durée min mot de passe', 'jours'),
    'passwordhistorysize':      ('Historique mots de passe', 'entrées'),
    'passwordcomplexity':       ('Complexité requise', '1=oui 0=non'),
    # System Access
    'lockoutbadcount':          ('Seuil verrouillage', 'tentatives'),
    'lockoutduration':          ('Durée verrouillage', 'minutes'),
    'resetlockoutcount':        ('Réinitialisation compteur', 'minutes'),
    'nolmhash':                 ('Pas de hash LM', '1=oui'),
    'lmcompatibilitylevel':     ('Niveau NTLM', '5=NTLMv2 only'),
    'restrictanonymous':        ('Restriction accès anonyme', ''),
    'enableguestaccount':       ('Compte Invité', '0=désactivé'),
    'lsacrashonapivulnerability':('LSA crash sur vuln', ''),
    # Event Audit
    'auditlogonevents':         ('Audit connexions', '3=succès+échec'),
    'auditaccountmanage':       ('Audit gestion comptes', '3=succès+échec'),
    'auditpolicychange':        ('Audit changements stratégie', '3=succès+échec'),
    'auditprivilegeusse':       ('Audit utilisation privilèges', ''),
    'auditsystemevents':        ('Audit événements système', ''),
    'auditobjectaccess':        ('Audit accès objets', ''),
    'auditaccountlogon':        ('Audit logon compte', ''),
    'auditprocesstracking':     ('Audit suivi processus', ''),
    'auditdirserviceaccess':    ('Audit accès services annuaire', ''),
}

_SECTION_LABELS = {
    'password_policy':  'Politique de mots de passe',
    'system_access':    'Accès système & authentification',
    'event_audit':      'Audit des événements',
    'kerberos_policy':  'Stratégie Kerberos',
    'privilege_rights': 'Droits utilisateurs',
    'registry_values':  'Valeurs de registre (GptTmpl)',
}

_REG_LABELS = {
    'uselogoncredential':               ('WDigest — mots de passe en clair', 'CRITIQUE si = 1'),
    'smb1':                             ('SMBv1 activé', 'CRITIQUE si = 1'),
    'enablefirewall':                   ('Pare-feu Windows', '0=désactivé'),
    'nodrivetypeautorun':               ('AutoRun désactivé', '255=tout désactivé'),
    'enablevirtualizationbasedsecurity':('Credential Guard / VBS', '1=activé'),
    'lmcompatibilitylevel':             ('Niveau NTLM (registre)', '5=NTLMv2 only'),
    'enablelua':                        ('UAC activé', '1=activé'),
    'consentpromptbehavioradmin':       ('UAC — comportement admins', '2=demande credentials'),
    'nolmhash':                         ('Pas de hash LM (registre)', '1=oui'),
}

def _format_gpo_content(gpo: dict) -> list:
    """Retourne une liste de sections {title, params:[{key,value,label,hint,alert}]}"""
    sections = []

    # ── Sections GptTmpl.inf ──
    for sec_key, sec_label in _SECTION_LABELS.items():
        params_raw = gpo.get('settings', {}).get(sec_key, {})
        if not params_raw:
            continue
        params = []
        for k, v in sorted(params_raw.items()):
            label, hint = _LABELS.get(k, (k, ''))
            # Détecter les valeurs problématiques
            alert = None
            try:
                vi = int(v)
                if k == 'minimumpasswordlength' and vi < 14:
                    alert = f'Trop court (recommandé ≥ 14)'
                elif k == 'passwordcomplexity' and vi == 0:
                    alert = 'Complexité désactivée'
                elif k == 'lockoutbadcount' and vi == 0:
                    alert = 'Verrouillage désactivé'
                elif k == 'nolmhash' and vi == 0:
                    alert = 'Hash LM stocké — risque élevé'
                elif k == 'lmcompatibilitylevel' and vi < 5:
                    alert = f'NTLMv1 autorisé (niveau {vi})'
                elif k in ('auditlogonevents','auditaccountmanage','auditpolicychange') and vi == 0:
                    alert = 'Audit désactivé'
                elif k == 'enableguestaccount' and vi == 1:
                    alert = 'Compte Invité activé'
            except (ValueError, TypeError):
                pass
            params.append({'key': k, 'value': v, 'label': label, 'hint': hint, 'alert': alert})
        if params:
            sections.append({'title': sec_label, 'icon': '🔒', 'params': params})

    # ── Registry.pol ──
    reg_entries = gpo.get('registry_entries', [])
    if reg_entries:
        params = []
        for (reg_key, vname, rtype, val) in reg_entries:
            label, hint = _REG_LABELS.get(vname.lower(), (vname, ''))
            # Clé courte lisible
            short_key = reg_key.split('\\')[-1]
            alert = None
            try:
                vi = int(val)
                if vname.lower() == 'uselogoncredential' and vi == 1:
                    alert = 'WDigest actif — mots de passe lisibles en mémoire'
                elif vname.lower() == 'smb1' and vi == 1:
                    alert = 'SMBv1 actif — vulnérable WannaCry/NotPetya'
                elif vname.lower() == 'enablefirewall' and vi == 0:
                    alert = 'Pare-feu désactivé par GPO'
                elif vname.lower() == 'enablelua' and vi == 0:
                    alert = 'UAC désactivé'
            except (ValueError, TypeError):
                pass
            params.append({
                'key': f'{short_key} → {vname}',
                'value': str(val),
                'label': label,
                'hint': hint,
                'alert': alert,
                'full_key': reg_key,
            })
        if params:
            sections.append({'title': 'Registre Windows — Machine (Registry.pol)', 'icon': '🗝', 'params': params})

    # ── Registre utilisateur ──
    reg_user = gpo.get('registry_entries_user', [])
    if reg_user:
        params = []
        for (reg_key, vname, rtype, val) in reg_user:
            label, hint = _REG_LABELS.get(vname.lower(), (vname, ''))
            short_key = reg_key.split('\\')[-1]
            params.append({'key': f'{short_key} → {vname}', 'value': str(val),
                           'label': label, 'hint': hint, 'alert': None})
        if params:
            sections.append({'title': 'Registre Windows — Utilisateur (Registry.pol)', 'icon': '🗝', 'params': params})

    # ── Imprimantes ──
    for scope, key in [('Machine', 'printers'), ('Utilisateur', 'printers_user')]:
        items = gpo.get(key, [])
        if items:
            params = []
            for p in items:
                label_parts = [p['action']]
                if p.get('default'):
                    label_parts.append('par défaut')
                if p.get('comment'):
                    label_parts.append(p['comment'])
                alert = None
                if p['action'] == 'Supprimer':
                    alert = 'Supprime les imprimantes existantes'
                params.append({
                    'key':   p['path'] or p['name'],
                    'value': p['name'],
                    'label': ' · '.join(label_parts),
                    'hint':  p.get('type', ''),
                    'alert': alert,
                })
            sections.append({'title': f'Imprimantes — {scope}', 'icon': '🖨', 'params': params})

    # ── Lecteurs réseau ──
    for scope, key in [('Machine', 'drives'), ('Utilisateur', 'drives_user')]:
        items = gpo.get(key, [])
        if items:
            params = [{'key': f"{d['letter']}:", 'value': d['path'],
                       'label': d['label'] or d['letter'],
                       'hint': d['action'], 'alert': None} for d in items]
            sections.append({'title': f'Lecteurs réseau — {scope}', 'icon': '💾', 'params': params})

    # ── Raccourcis ──
    for scope, key in [('Machine', 'shortcuts_machine'), ('Utilisateur', 'shortcuts_user')]:
        items = gpo.get(key, [])
        if items:
            params = [{'key': s['name'], 'value': s['target'],
                       'label': s['location'] or '', 'hint': s['action'], 'alert': None}
                      for s in items]
            sections.append({'title': f'Raccourcis — {scope}', 'icon': '🔗', 'params': params})

    # ── Tâches planifiées ──
    tasks = gpo.get('scheduled_tasks', [])
    if tasks:
        params = []
        for t in tasks:
            cmd = t['cmd'] + (' ' + t['args'] if t['args'] else '')
            alert = None
            # Détecter les tâches qui s'exécutent en SYSTEM ou admin
            if t['user'] and any(x in t['user'].upper() for x in ('SYSTEM', 'ADMINISTRATOR', 'ADMIN')):
                alert = f"Exécuté en tant que : {t['user']}"
            params.append({'key': t['name'] or cmd, 'value': cmd,
                           'label': t['user'] or 'Utilisateur non défini',
                           'hint': t['action'], 'alert': alert})
        sections.append({'title': 'Tâches planifiées', 'icon': '⏰', 'params': params})

    # ── Scripts ──
    scripts = gpo.get('scripts', {})
    if scripts and any(scripts.values()):
        params = []
        for scope_name, key in [('Démarrage machine', 'startup'), ('Arrêt machine', 'shutdown'),
                                 ('Ouverture session', 'logon'), ('Fermeture session', 'logoff')]:
            for s in (scripts.get(key) or []):
                if isinstance(s, dict):
                    cmd = s.get('cmd', '') + (' ' + s.get('params', '') if s.get('params') else '')
                else:
                    cmd = str(s)
                if cmd.strip():
                    params.append({'key': scope_name, 'value': cmd,
                                   'label': scope_name, 'hint': '', 'alert': None})
        if params:
            sections.append({'title': 'Scripts', 'icon': '📜', 'params': params})

    # ── Groupes locaux ──
    groups = gpo.get('groups', [])
    if groups:
        params = []
        for g in groups:
            members_str = ', '.join(m['name'] for m in g.get('members', [])[:5])
            if len(g.get('members', [])) > 5:
                members_str += f" (+{len(g['members'])-5})"
            alert = None
            if any('administrator' in m['name'].lower() for m in g.get('members', [])):
                alert = 'Membre administrateur détecté'
            params.append({'key': g['name'], 'value': members_str or '(vide)',
                           'label': g['action'] or '', 'hint': '', 'alert': alert})
        sections.append({'title': 'Groupes locaux', 'icon': '👥', 'params': params})

    # ── Variables d'environnement ──
    env_vars = gpo.get('env_vars', [])
    if env_vars:
        params = [{'key': v['name'], 'value': v['value'],
                   'label': v['action'] or '', 'hint': '', 'alert': None}
                  for v in env_vars]
        sections.append({'title': "Variables d'environnement", 'icon': '⚙', 'params': params})

    # ── Copie de fichiers ──
    for scope, key in [('Machine', 'files_machine'), ('Utilisateur', 'files_user')]:
        items = gpo.get(key, [])
        if items:
            params = []
            for f in items:
                alert = None
                # Signaler les copies vers des emplacements sensibles
                dst = f.get('dst', '')
                if dst and any(x in dst.lower() for x in ('system32', 'startup', 'programdata', 'appdata')):
                    alert = f"Destination sensible : {dst}"
                params.append({
                    'key':   f['name'],
                    'value': f['dst'] or '',
                    'label': f"{f['action']} · source : {f['src'] or '?'}",
                    'hint':  '',
                    'alert': alert,
                })
            sections.append({'title': f'Copie de fichiers — {scope}', 'icon': '📁', 'params': params})

    # ── Services Windows ──
    services = gpo.get('services', [])
    if services:
        params = []
        for s in services:
            params.append({
                'key':   s['name'],
                'value': f"{s['startup']} · action : {s['action']}",
                'label': s['gpo_act'],
                'hint':  '',
                'alert': s.get('alert'),
            })
        sections.append({'title': 'Services Windows', 'icon': '⚙', 'params': params})

    # ── Audit avancé ──
    audit = gpo.get('audit_csv', [])
    if audit:
        params = []
        for a in audit:
            params.append({
                'key':   a['subcategory'],
                'value': a['inclusion'],
                'label': '',
                'hint':  '',
                'alert': a.get('alert'),
            })
        sections.append({'title': 'Audit avancé (audit.csv)', 'icon': '🔍', 'params': params})

    # ── Préférences Registre XML ──
    for scope, key in [('Machine', 'registry_xml_machine'), ('Utilisateur', 'registry_xml_user')]:
        items = gpo.get(key, [])
        if items:
            params = []
            for r in items:
                full_key = f"{r['hive']}\\{r['key']}\\{r['name']}" if r['name'] else f"{r['hive']}\\{r['key']}"
                short = r['name'] or r['key'].split('\\')[-1]
                alert = None
                # Détecter les valeurs notables
                if r['name'] and any(kw in r['name'].lower() for kw in
                        ('password', 'passwd', 'admin', 'disable', 'enable', 'autorun', 'update')):
                    alert = f"{r['type']} = {r['value']}"
                params.append({
                    'key':   short,
                    'value': r['value'],
                    'label': f"{r['action']} · {r['type']}",
                    'hint':  r['key'],
                    'alert': alert,
                })
            sections.append({'title': f'Préférences registre XML — {scope}', 'icon': '📋', 'params': params})

    return sections


def analyze_gpos(gpos: list) -> dict:
    if not gpos:
        print("[!] Aucune GPO collectée — vérifiez la connexion LDAP et les droits du compte.")
        gpos = []
    # 1. RSOP global → findings globaux (ce qui s'applique réellement)
    rsop_settings, rsop_reg_list, rsop_registry_xml = build_rsop(gpos)
    rsop_registry = {(e[0], e[1]): e[3] for e in rsop_reg_list}

    global_findings = []
    for rule in AUDIT_RULES:
        finding = evaluate_rule_on_rsop(rule, rsop_settings, rsop_registry)
        if finding:
            global_findings.append(finding)

    # Évaluer les règles sur les [Registry Values] du GptTmpl.inf
    rsop_regval = rsop_settings.get('registry_values', {})
    global_findings += evaluate_regval_rules(rsop_regval)

    # Évaluer les règles sur les Registry.xml (préférences registre)
    global_findings += evaluate_registry_xml_rules(rsop_registry_xml)

    # Évaluer les droits utilisateurs (Privilege Rights)
    rsop_privrights = rsop_settings.get('privilege_rights', {})
    global_findings += evaluate_privright_rules(rsop_privrights)

    # Enrichir chaque finding avec : quelles GPO contiennent ce paramètre + action recommandée
    all_rules_by_id = {r['id']: r for r in AUDIT_RULES + AUDIT_RULES_REGVAL + AUDIT_RULES_REGISTRY_XML}
    for finding in global_findings:
        rid = finding['rule_id']
        rule = all_rules_by_id.get(rid, {})
        source_gpos = []  # GPO qui contiennent ce paramètre problématique

        # Chercher dans les settings des GPO
        for gpo in gpos:
            if gpo.get('flags') == '3':
                continue
            gpo_has_param = False
            # Vérifier dans registry_values (GptTmpl.inf)
            rv = gpo.get('settings', {}).get('registry_values', {})
            if rule.get('regval_key') and rule['regval_key'].lower() in rv:
                gpo_has_param = True
            # Vérifier dans registry_xml
            for scope in ('registry_xml_machine', 'registry_xml_user'):
                for entry in gpo.get(scope, []):
                    hive = entry.get('hive','').lower().replace('hkey_local_machine','hklm').replace('hkey_current_user','hkcu')
                    key = f"{hive}\\{entry.get('key','').lower()}"
                    name = entry.get('name','').lower()
                    if rule.get('hive_key') and rule.get('name'):
                        if key == rule['hive_key'].lower() and name == rule['name'].lower():
                            gpo_has_param = True
            # Vérifier dans settings sections standard
            if rule.get('section') and rule.get('check_key'):
                sec = gpo.get('settings', {}).get(rule['section'], {})
                if rule['check_key'] in sec:
                    gpo_has_param = True
            if gpo_has_param:
                source_gpos.append({'name': gpo['name'], 'guid': gpo['guid']})

        finding['source_gpos'] = source_gpos

        # Déterminer l'action : modifier GPO existante ou créer une nouvelle
        if source_gpos:
            finding['action_type'] = 'modify'
            finding['action_label'] = f"Modifier : {', '.join(g['name'] for g in source_gpos[:2])}" + (f" + {len(source_gpos)-2} autres" if len(source_gpos)>2 else "")
        else:
            finding['action_type'] = 'create'
            finding['action_label'] = "Créer une nouvelle GPO de sécurité"

    violated_ids = {f['rule_id'] for f in global_findings}
    compliant_rules = [r for r in AUDIT_RULES if r['id'] not in violated_ids]
    # Ajouter les règles REGVAL conformes
    compliant_rules += [r for r in AUDIT_RULES_REGVAL
                        if r['id'] not in violated_ids
                        and rsop_regval.get(r['regval_key'].lower())]

    # 2. Par GPO → uniquement les paramètres explicitement mal configurés dans cette GPO
    gpo_reports       = []
    orphan_gpos       = []
    gpo_content_index = {}   # guid → content_sections, chargé à la demande
    for gpo in gpos:
        if not gpo['links']:
            orphan_gpos.append(gpo['name'])
        per_gpo_findings = []
        for rule in AUDIT_RULES:
            f = evaluate_rule_on_gpo(rule, gpo.get('settings', {}), gpo.get('registry_entries', []))
            if f:
                per_gpo_findings.append(f)

        score = 100
        for f in per_gpo_findings:
            score -= {'critical': 25, 'warning': 10, 'info': 3}.get(f['severity'], 0)
        score = max(0, score)

        # Préparer le contenu lisible de la GPO
        content_sections = _format_gpo_content(gpo)
        has_content = any(s['params'] for s in content_sections)

        gpo_reports.append({
            'name':        gpo['name'],
            'guid':        gpo['guid'],
            'links':       gpo['links'],
            'link_count':  len(gpo['links']),
            'flags':       gpo.get('flags', '0'),
            'created':     gpo.get('created', ''),
            'changed':     gpo.get('changed', ''),
            'findings':    per_gpo_findings,
            'score':       score,
            'is_orphan':   not gpo['links'],
            'has_content': has_content,
            'wmi_filter':  gpo.get('wmi_filter'),
        })
        # Index de contenu séparé — chargé uniquement quand on ouvre une GPO
        gpo_content_index[gpo['guid']] = content_sections

    # 3. Redondances (même paramètre dans plusieurs GPO)
    param_seen = {}
    for gpo in gpos:
        for section, params in gpo.get('settings', {}).items():
            if not params:
                continue
            for key in params:
                k = f"{section}.{key}"
                param_seen.setdefault(k, []).append(gpo['name'])
        for (key, vname, _, _) in gpo.get('registry_entries', []):
            k = f"registry.{key}\\{vname}"
            param_seen.setdefault(k, []).append(gpo['name'])
    redundant = {k: v for k, v in param_seen.items() if len(v) > 1}

    # 4. Scores
    # ── Détection des vrais doublons (même clé + même valeur dans 2+ GPO) ──
    # Clés et sections à ignorer — métadonnées ou données légitimement dupliquées
    SKIP_KEYS = {
        'unicode', 'signature', 'revision', 'passwordexpirywarning',
        'lsaanonymousnamelookup', 'requirelogontochangepassword',
    }
    SKIP_SECTIONS = {'unicode', 'version'}
    # Préfixes de clés registre à ignorer (certificats PKI, WMI, etc.)
    SKIP_KEY_PREFIXES = (
        'registry.software\\policies\\microsoft\\systemcertificates',
        'registry.software\\policies\\microsoft\\windows\\safer',
        'registry.software\\microsoft\\systemcertificates',
        'registry.software\\policies\\microsoft\\windows nt\\dnsclient',
    )
    param_index = {}  # (section, key, value) -> [gpo_names]
    for gpo in gpos:
        if gpo.get('flags') == '3':
            continue
        # Settings GptTmpl.inf
        for section, params in gpo.get('settings', {}).items():
            if not params:
                continue
            if section in SKIP_SECTIONS:
                continue
            for k, v in params.items():
                if k.lower() in SKIP_KEYS:
                    continue
                composite = f"{section}.{k.lower()}"
                if any(composite.startswith(p) for p in SKIP_KEY_PREFIXES):
                    continue
                key = (section, k.lower(), str(v).lower())
                if key not in param_index:
                    param_index[key] = []
                param_index[key].append(gpo['name'])
        # Registry values GptTmpl.inf
        for k, v in gpo.get('settings', {}).get('registry_values', {}).items():
            k_low = k.lower()
            if any(k_low.startswith(p.replace('registry.', 'machine\\')) for p in SKIP_KEY_PREFIXES):
                continue
            key = ('registry_values', k_low, str(v).lower())
            if key not in param_index:
                param_index[key] = []
            param_index[key].append(gpo['name'])
        # Registry.xml
        for scope in ('registry_xml_machine', 'registry_xml_user'):
            for entry in gpo.get(scope, []):
                k = f"{entry.get('hive','').lower()}\\{entry.get('key','').lower()}\\{entry.get('name','').lower()}"
                v = entry.get('value', '')
                key = ('registry_xml', k, str(v).lower())
                if key not in param_index:
                    param_index[key] = []
                param_index[key].append(gpo['name'])

    # Garder uniquement les vrais doublons (même paramètre + même valeur dans 2+ GPO)
    true_duplicates = []
    for (section, k, v), gpo_names in param_index.items():
        if len(gpo_names) >= 2:
            # Dépublier les GPO en doublons (même GPO peut apparaître une seule fois)
            unique_gpos = list(dict.fromkeys(gpo_names))
            if len(unique_gpos) >= 2:
                # Déterminer si c'est un conflit ou redondance
                dup_type = 'redundant'  # même valeur = redondant (inutile)
                true_duplicates.append({
                    'section': section,
                    'key': k,
                    'value': v,
                    'gpos': unique_gpos,
                    'type': dup_type,
                    'label': f"{section} → {k} = {v}",
                })
    # Trier par nombre de GPO concernées
    true_duplicates.sort(key=lambda x: len(x['gpos']), reverse=True)

    # ── Détection des conflits GPO ──────────────────────────────────────────
    gpo_conflicts = detect_gpo_conflicts(gpos)
    conflicts_high = sum(1 for c in gpo_conflicts if c['is_security'])
    conflicts_low  = sum(1 for c in gpo_conflicts if not c['is_security'])

    criticals = sum(1 for f in global_findings if f['severity'] == 'critical')
    warnings  = sum(1 for f in global_findings if f['severity'] == 'warning')
    infos     = sum(1 for f in global_findings if f['severity'] == 'info')
    orphan_penalty   = min(len(orphan_gpos) * 1, 10)
    conflict_penalty = min(conflicts_high * 3 + conflicts_low, 15)
    global_score = max(0, min(100,
        100 - criticals * 15 - warnings * 5 - infos * 2
        - orphan_penalty - conflict_penalty
    ))

    return {
        'global_score': global_score,
        'total_findings': len(global_findings),
        'criticals': criticals,
        'warnings': warnings,
        'infos': infos,
        'compliant_count': len(compliant_rules),
        'compliant_rules': compliant_rules,
        'orphan_count': len(orphan_gpos),
        'orphan_gpos': orphan_gpos,
        'redundant_params': dict(list(redundant.items())[:15]),
        'true_duplicates': true_duplicates[:50],
        'gpo_conflicts': gpo_conflicts,
        'conflicts_high':    conflicts_high,
        'conflicts_low':     conflicts_low,
        'gpo_reports':       sorted(gpo_reports, key=lambda g: g['score']),
        'gpo_content_index': gpo_content_index,
        'all_findings':      global_findings,
        'generated_at':      datetime.now().strftime('%d/%m/%Y %H:%M'),
        'gpo_count':         len(gpos),
        'wmi_count':         sum(1 for g in gpos if g.get('wmi_filter')),
        'search_index':      build_search_index(_enrich_gpos_for_search(gpos, gpo_reports)),
    }


# ─── Template HTML ────────────────────────────────────────────────────────────

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="fr" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GPOctopus — {{ data.generated_at }}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&family=Inter:wght@400;500;600;700&display=swap');

/* ── Variables thème ─────────────────────────────── */
[data-theme="dark"]{
  --bg:#0d1117;--surface:#161b27;--surface2:#1c2133;--surface3:#222840;
  --border:#252d42;--border2:#2e3852;
  --txt:#c8cfe0;--txt2:#7a84a8;--txt3:#3d4a68;
  --red:#e05252;--red-bg:rgba(224,82,82,.1);
  --amber:#d4892a;--amber-bg:rgba(212,137,42,.1);
  --green:#3a9e72;--green-bg:rgba(58,158,114,.1);
  --blue:#4a7fd4;--blue-bg:rgba(74,127,212,.1);
  --teal:#2ab5a0;--teal-bg:rgba(42,181,160,.1);
  --purple:#8b6ddb;
}
[data-theme="light"]{
  --bg:#f0f2f7;--surface:#ffffff;--surface2:#eef0f6;--surface3:#e5e8f0;
  --border:#d5dae8;--border2:#c4c9d8;
  --txt:#1e2336;--txt2:#4e5878;--txt3:#8890aa;
  --red:#c03030;--red-bg:rgba(192,48,48,.08);
  --amber:#a86a10;--amber-bg:rgba(168,106,16,.08);
  --green:#1e7a54;--green-bg:rgba(30,122,84,.08);
  --blue:#2655b0;--blue-bg:rgba(38,85,176,.08);
  --teal:#1a8a78;--teal-bg:rgba(26,138,120,.08);
  --purple:#5c3fc0;
}

*{box-sizing:border-box;margin:0;padding:0}
html{font-size:14px}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--txt);min-height:100vh}

/* ── Layout ────────────────────────────────────────── */
.app{display:flex;height:100vh;overflow:hidden}

/* ── Sidebar ───────────────────────────────────────── */
.sidebar{
  width:220px;flex-shrink:0;
  background:var(--surface);
  border-right:1px solid var(--border);
  display:flex;flex-direction:column;
  overflow-y:auto;
}
.sb-logo{padding:18px 16px 14px;border-bottom:1px solid var(--border)}
.sb-logo h1{font-size:15px;font-weight:700;display:flex;align-items:center;gap:7px}
.sb-logo p{font-size:10px;color:var(--txt3);margin-top:3px}

/* Score ring */
.sb-score{padding:14px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px}
.score-ring{position:relative;width:52px;height:52px;flex-shrink:0}
.score-ring svg{transform:rotate(-90deg)}
.score-val{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;line-height:1}
.score-val .n{font-size:17px;font-weight:700;font-family:'JetBrains Mono',monospace}
.score-val .l{font-size:9px;color:var(--txt3)}
.score-info .label{font-size:11px;font-weight:600}
.score-info .sub{font-size:10px;color:var(--txt2);margin-top:2px;line-height:1.4}

/* Onglets principaux */
.main-tabs{display:flex;flex-direction:column;gap:2px;padding:12px 10px}
.main-tab{
  display:flex;align-items:center;gap:10px;
  padding:10px 12px;border-radius:6px;
  cursor:pointer;transition:background .12s;
  font-size:13px;color:var(--txt2);font-weight:500;
}
.main-tab:hover{background:var(--surface2);color:var(--txt)}
.main-tab.active{background:var(--blue-bg);color:var(--blue);border:1px solid rgba(74,127,212,.2)}
.main-tab .tab-icon{font-size:16px;width:20px;text-align:center;flex-shrink:0}
.main-tab .tab-badge{
  margin-left:auto;font-size:10px;font-weight:700;
  padding:1px 6px;border-radius:10px;
  background:var(--red-bg);color:var(--red);
  font-family:'JetBrains Mono',monospace;
}
.main-tab.active .tab-badge{background:rgba(74,127,212,.2);color:var(--blue)}

.sb-divider{height:1px;background:var(--border);margin:4px 10px}

/* Sous-navigation contextuelle */
.sub-nav{padding:6px 10px 10px}
.sub-nav-label{font-size:10px;font-weight:600;color:var(--txt3);text-transform:uppercase;letter-spacing:.06em;padding:6px 8px 4px}
.sub-item{
  display:flex;align-items:center;gap:8px;
  padding:6px 10px;border-radius:4px;
  cursor:pointer;font-size:12px;color:var(--txt2);
  transition:all .1s;
}
.sub-item:hover{background:var(--surface2);color:var(--txt)}
.sub-item.active{color:var(--txt);font-weight:500}
.sub-item .si-icon{width:16px;text-align:center;font-size:12px;flex-shrink:0}
.sub-item .si-count{margin-left:auto;font-size:10px;color:var(--txt3)}

.sb-footer{margin-top:auto;padding:12px 16px;border-top:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.theme-btn{width:30px;height:16px;background:var(--surface3);border-radius:8px;cursor:pointer;position:relative;border:1px solid var(--border2);flex-shrink:0}
.theme-btn::after{content:'';position:absolute;top:2px;left:2px;width:10px;height:10px;border-radius:50%;background:var(--txt3);transition:left .15s}
[data-theme="light"] .theme-btn::after{left:16px;background:var(--blue)}

/* ── Main content ──────────────────────────────────── */
.main{flex:1;overflow-y:auto;padding:0}

.tab-content{display:none;animation:fadeIn .2s ease}
.tab-content.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:translateY(0)}}

.page-header{
  padding:24px 32px 20px;
  border-bottom:1px solid var(--border);
  background:var(--surface);
  position:sticky;top:0;z-index:50;
}
.page-header h2{font-size:20px;font-weight:700;letter-spacing:-.3px}
.page-header p{font-size:12px;color:var(--txt2);margin-top:3px}

.content-area{padding:24px 32px}

/* ── Loader ─────────────────────────────────────────── */
.loader{
  position:fixed;inset:0;z-index:9999;
  background:var(--bg);
  display:flex;flex-direction:column;align-items:center;justify-content:center;gap:16px;
  transition:opacity .3s;
}
.loader.done{opacity:0;pointer-events:none}
.loader-ring{width:36px;height:36px;border:3px solid var(--border2);border-top-color:var(--blue);border-radius:50%;animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.loader-text{font-size:13px;color:var(--txt2)}

/* ── Cartes métriques ───────────────────────────────── */
.metrics-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:24px}
.metric-card{
  background:var(--surface);border:1px solid var(--border);border-radius:8px;
  padding:16px;cursor:pointer;transition:border-color .15s,background .15s;
}
.metric-card:hover{border-color:var(--border2);background:var(--surface2)}
.metric-card.red{border-left:3px solid var(--red)}
.metric-card.amber{border-left:3px solid var(--amber)}
.metric-card.green{border-left:3px solid var(--green)}
.metric-card.blue{border-left:3px solid var(--blue)}
.metric-card .mv{font-size:28px;font-weight:700;font-family:'JetBrains Mono',monospace;line-height:1}
.metric-card .ml{font-size:11px;color:var(--txt2);margin-top:4px}
.metric-card.red .mv{color:var(--red)}
.metric-card.amber .mv{color:var(--amber)}
.metric-card.green .mv{color:var(--green)}
.metric-card.blue .mv{color:var(--blue)}

/* ── Section titres ────────────────────────────────── */
.section-title{
  font-size:13px;font-weight:600;
  color:var(--txt2);text-transform:uppercase;letter-spacing:.06em;
  margin-bottom:12px;padding-bottom:8px;
  border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:8px;
}
.section-title .st-count{
  margin-left:auto;font-size:11px;font-weight:400;
  color:var(--txt3);text-transform:none;letter-spacing:0;
}

/* ── Finding cards ─────────────────────────────────── */
.finding-list{display:flex;flex-direction:column;gap:6px;margin-bottom:24px}

.finding-card{
  background:var(--surface);border:1px solid var(--border);border-radius:8px;
  overflow:hidden;transition:border-color .15s;
}
.finding-card:hover{border-color:var(--border2)}
.finding-card.critical{border-left:3px solid var(--red)}
.finding-card.warning{border-left:3px solid var(--amber)}
.finding-card.info{border-left:3px solid var(--blue)}
.finding-card.good{border-left:3px solid var(--green)}

.fc-head{
  display:flex;align-items:center;gap:12px;
  padding:12px 16px;cursor:pointer;
}
.fc-sev{
  width:7px;height:7px;border-radius:50%;flex-shrink:0;
}
.fc-sev.critical{background:var(--red)}
.fc-sev.warning{background:var(--amber)}
.fc-sev.info{background:var(--blue)}
.fc-sev.good{background:var(--green)}

.fc-main{flex:1;min-width:0}
.fc-title{font-size:13px;font-weight:500;line-height:1.3}
.fc-meta{font-size:11px;color:var(--txt3);margin-top:2px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.fc-pill{
  font-size:10px;padding:1px 7px;border-radius:10px;font-weight:600;
}
.fc-pill.critical{background:var(--red-bg);color:var(--red)}
.fc-pill.warning{background:var(--amber-bg);color:var(--amber)}
.fc-pill.info{background:var(--blue-bg);color:var(--blue)}
.fc-pill.good{background:var(--green-bg);color:var(--green)}

.fc-arrow{font-size:11px;color:var(--txt3);transition:transform .15s;flex-shrink:0}
.fc-arrow.open{transform:rotate(90deg)}

.fc-body{
  display:none;padding:0 16px 14px 35px;
  border-top:1px solid var(--border);
}
.fc-body.open{display:block}
.fc-detail{font-size:12px;color:var(--txt2);padding:10px 0 6px;line-height:1.6}
.fc-ref{font-size:11px;color:var(--txt3);margin-bottom:6px}
.fc-reco{
  font-size:12px;color:var(--green);
  padding:8px 12px;background:var(--green-bg);border-radius:4px;
  line-height:1.5;
}
.fc-sources{margin-top:8px;font-size:11px;color:var(--txt3);display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.fc-gpo-link{
  font-size:11px;color:var(--blue);cursor:pointer;
  padding:1px 6px;background:var(--blue-bg);border-radius:3px;
  font-family:'JetBrains Mono',monospace;
}
.fc-gpo-link:hover{text-decoration:underline}

/* Bouton expliquer */
.btn-explain{
  font-size:10px;padding:2px 8px;
  border:1px solid var(--teal);color:var(--teal);
  background:none;border-radius:4px;cursor:pointer;
  flex-shrink:0;
}
.btn-explain:hover{background:var(--teal-bg)}

/* Zone explication inline */
.explain-zone{
  margin-top:10px;padding:12px;
  background:var(--surface2);
  border-left:3px solid var(--teal);border-radius:0 6px 6px 0;
  display:none;
}
.explain-zone.open{display:block}
.explain-attack{font-size:12px;color:var(--txt2);margin-bottom:8px;line-height:1.5}
.explain-chips{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px}
.explain-chip{font-size:10px;padding:2px 8px;border-radius:3px;font-weight:500}
.explain-chip.tool{background:rgba(224,82,82,.12);color:var(--red)}
.explain-chip.impact{background:rgba(212,137,42,.12);color:var(--amber)}

/* Filtre non-configuré */
.nc-tag{
  font-size:10px;padding:1px 6px;border-radius:10px;margin-left:6px;
  background:var(--amber-bg);color:var(--amber);font-weight:500;
}

/* ── GPO cards ─────────────────────────────────────── */
.gpo-grid{display:flex;flex-direction:column;gap:6px}
.gpo-card{
  background:var(--surface);border:1px solid var(--border);border-radius:8px;
  cursor:pointer;transition:border-color .15s,background .15s;overflow:hidden;
}
.gpo-card:hover{border-color:var(--border2);background:var(--surface2)}
.gpo-card-head{display:flex;align-items:center;gap:12px;padding:12px 16px}
.gpo-name{font-size:13px;font-weight:500;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.gpo-badges{display:flex;gap:5px;align-items:center;flex-shrink:0;flex-wrap:wrap}
.badge{
  font-size:10px;padding:2px 7px;border-radius:10px;font-weight:600;
  white-space:nowrap;
}
.badge.score-good{background:var(--green-bg);color:var(--green)}
.badge.score-mid{background:var(--amber-bg);color:var(--amber)}
.badge.score-bad{background:var(--red-bg);color:var(--red)}
.badge.enforced{background:rgba(224,82,82,.12);color:var(--red)}
.badge.disabled{background:var(--surface3);color:var(--txt3)}
.badge.wmi{background:rgba(212,137,42,.12);color:var(--amber)}
.badge.orphan{background:var(--blue-bg);color:var(--blue)}

.gpo-card-body{
  display:none;padding:0 16px 14px;border-top:1px solid var(--border);
}
.gpo-card-body.open{display:block}
.gpo-ou-list{margin:10px 0;display:flex;flex-direction:column;gap:4px}
.ou-row{display:flex;align-items:center;gap:8px;font-size:11px;color:var(--txt2)}
.ou-depth{color:var(--txt3);font-size:10px;min-width:20px}
.ou-name{font-family:'JetBrains Mono',monospace;flex:1}
.gpo-params-preview{
  margin-top:8px;display:flex;flex-wrap:wrap;gap:4px;
}
.param-chip{
  font-size:10px;padding:2px 7px;border-radius:3px;
  background:var(--surface2);border:1px solid var(--border);
  color:var(--txt3);font-family:'JetBrains Mono',monospace;
}
.param-chip.alert{background:var(--red-bg);border-color:rgba(224,82,82,.25);color:var(--red)}

/* ── Onglet Diagnostic ─────────────────────────────── */
.search-bar{
  position:relative;margin-bottom:16px;
}
.search-bar input{
  width:100%;padding:14px 16px 14px 46px;
  background:var(--surface);border:1px solid var(--border2);border-radius:8px;
  color:var(--txt);font-size:14px;font-family:'Inter',sans-serif;
  outline:none;transition:border-color .15s,box-shadow .15s;
}
.search-bar input:focus{border-color:var(--blue);box-shadow:0 0 0 3px rgba(74,127,212,.12)}
.search-bar input::placeholder{color:var(--txt3)}
.search-icon{position:absolute;left:16px;top:50%;transform:translateY(-50%);color:var(--txt3);font-size:16px;pointer-events:none}

.search-hint{font-size:11px;color:var(--txt3);margin-bottom:14px}

/* Boutons raccourcis */
.shortcut-group{margin-bottom:20px}
.shortcut-label{font-size:10px;font-weight:600;color:var(--txt3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px}
.shortcut-row{display:flex;flex-wrap:wrap;gap:6px}
.shortcut-btn{
  padding:6px 12px;border-radius:6px;border:1px solid var(--border);
  background:none;cursor:pointer;font-size:12px;color:var(--txt2);
  font-family:'Inter',sans-serif;transition:all .12s;
}
.shortcut-btn:hover{border-color:var(--border2);color:var(--txt);background:var(--surface2)}
.shortcut-btn.combo{border-color:var(--teal);color:var(--teal)}
.shortcut-btn.combo:hover{background:var(--teal-bg)}

/* Résultats recherche */
.search-result-header{
  display:flex;align-items:center;gap:10px;flex-wrap:wrap;
  margin-bottom:12px;padding-bottom:10px;border-bottom:1px solid var(--border);
  font-size:12px;color:var(--txt2);
}
.syn-badge{font-size:10px;color:var(--teal);background:var(--teal-bg);padding:2px 6px;border-radius:3px}

.result-gpo{
  background:var(--surface);border:1px solid var(--border);border-radius:8px;
  margin-bottom:10px;overflow:hidden;
}
.result-gpo-head{
  display:flex;align-items:center;gap:10px;padding:12px 16px;
  background:var(--surface2);cursor:pointer;
}
.result-gpo-name{font-size:13px;font-weight:600;flex:1}
.covered-badges{display:flex;gap:4px}
.covered-badge{font-size:10px;padding:1px 6px;border-radius:3px;background:var(--teal-bg);color:var(--teal);font-weight:600}

/* Bandeau diagnostic OU */
.diag-banner{
  padding:8px 16px;background:var(--surface);
  border-top:1px solid var(--border);
  display:flex;align-items:flex-start;gap:20px;flex-wrap:wrap;
}
.diag-section{min-width:120px}
.diag-label{font-size:9px;text-transform:uppercase;letter-spacing:.06em;color:var(--txt3);margin-bottom:4px;font-weight:600}
.diag-ou-row{display:flex;align-items:center;gap:5px;font-size:10px;color:var(--txt2);font-family:'JetBrains Mono',monospace}

/* Tableau résultats */
.result-table{width:100%;border-collapse:collapse}
.result-table td{
  padding:6px 12px;border-bottom:1px solid var(--border);
  font-size:11px;vertical-align:middle;
}
.result-table tr:last-child td{border-bottom:none}
.result-table tr{cursor:pointer;transition:background .1s}
.result-table tr:hover{background:var(--surface2)}
.rt-type{color:var(--txt3);white-space:nowrap;width:140px}
.rt-key{font-weight:500;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rt-val{font-family:'JetBrains Mono',monospace;color:var(--txt2);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rt-ctx{color:var(--txt3);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

mark{background:rgba(74,127,212,.25);color:var(--txt);border-radius:2px;padding:0 1px}

/* État vide */
.empty-state{text-align:center;padding:60px 20px;color:var(--txt3)}
.empty-state .es-icon{font-size:48px;margin-bottom:16px}
.empty-state .es-title{font-size:15px;font-weight:500;color:var(--txt2);margin-bottom:8px}
.empty-state .es-sub{font-size:13px;line-height:1.8}

/* ── Inventaire ─────────────────────────────────────── */
.inv-tabs{display:flex;gap:4px;margin-bottom:20px;border-bottom:1px solid var(--border);padding-bottom:0}
.inv-tab{
  padding:8px 16px;font-size:12px;font-weight:500;color:var(--txt3);
  cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px;
  transition:color .12s;
}
.inv-tab:hover{color:var(--txt2)}
.inv-tab.active{color:var(--blue);border-bottom-color:var(--blue)}

.inv-panel{display:none}
.inv-panel.active{display:block}

/* OU cards */
.ou-card{
  background:var(--surface);border:1px solid var(--border);border-radius:8px;
  margin-bottom:8px;overflow:hidden;
}
.ou-card-head{
  display:flex;align-items:center;gap:10px;padding:12px 16px;
  cursor:pointer;transition:background .1s;
}
.ou-card-head:hover{background:var(--surface2)}
.ou-path{font-size:12px;font-family:'JetBrains Mono',monospace;flex:1;color:var(--txt2)}
.ou-card-body{display:none;border-top:1px solid var(--border)}
.ou-card-body.open{display:block}
.ou-gpo-row{
  display:flex;align-items:center;gap:10px;
  padding:9px 16px;border-bottom:1px solid var(--border);
  font-size:12px;transition:background .1s;
}
.ou-gpo-row:last-child{border-bottom:none}
.ou-gpo-row:hover{background:var(--surface2)}
.ou-priority{min-width:60px;font-size:10px;color:var(--txt3);font-family:'JetBrains Mono',monospace}
.ou-gpo-name{flex:1;color:var(--blue);cursor:pointer;font-weight:500}
.ou-gpo-name:hover{text-decoration:underline}
.ou-score{font-size:10px;font-weight:600}
.ou-changed{font-size:10px;color:var(--txt3)}

/* Type grid */
.type-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:10px;margin-bottom:20px}
.type-card{
  background:var(--surface);border:1px solid var(--border);border-radius:8px;
  padding:14px;cursor:pointer;transition:all .12s;
}
.type-card:hover{border-color:var(--border2);background:var(--surface2)}
.type-card .tc-icon{font-size:20px;margin-bottom:8px}
.type-card .tc-name{font-size:12px;font-weight:500;margin-bottom:4px}
.type-card .tc-count{font-size:11px;color:var(--txt3)}
.type-card .tc-bar{height:3px;background:var(--surface3);border-radius:2px;margin-top:8px;overflow:hidden}
.type-card .tc-fill{height:100%;background:var(--blue);border-radius:2px}

/* ── Timeline ──────────────────────────────────────── */
.tl-month{margin-bottom:20px}
.tl-month-label{
  font-size:11px;font-weight:600;color:var(--txt3);text-transform:uppercase;
  letter-spacing:.06em;padding:4px 0;margin-bottom:8px;
  border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px;
}
.tl-item{
  display:flex;align-items:flex-start;gap:12px;
  padding:10px 14px;background:var(--surface);border:1px solid var(--border);
  border-radius:6px;margin-bottom:5px;cursor:pointer;transition:all .12s;
}
.tl-item:hover{border-color:var(--border2);background:var(--surface2)}
.tl-date{min-width:44px;text-align:right;flex-shrink:0}
.tl-date .day{font-size:12px;font-weight:600;color:var(--txt)}
.tl-date .yr{font-size:10px;color:var(--txt3)}
.tl-info{flex:1;min-width:0}
.tl-name{font-size:13px;font-weight:500;color:var(--blue);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tl-ous{font-size:10px;color:var(--txt3);margin-top:2px}
.tl-badges{display:flex;gap:4px;align-items:center;flex-shrink:0}

/* ── Fiche GPO détail ─────────────────────────────── */
.gpo-detail-header{
  padding:20px 32px 16px;border-bottom:1px solid var(--border);
  background:var(--surface);
}
.gpo-detail-header h2{font-size:18px;font-weight:700}
.gpo-detail-meta{display:flex;flex-wrap:wrap;gap:16px;margin-top:10px;font-size:12px;color:var(--txt2)}
.gdm-item{display:flex;flex-direction:column;gap:2px}
.gdm-item .gdm-l{font-size:10px;color:var(--txt3);text-transform:uppercase;letter-spacing:.04em}
.gdm-item .gdm-v{font-family:'JetBrains Mono',monospace;color:var(--txt)}

.wmi-alert{
  margin:16px 32px 0;padding:12px 16px;
  background:var(--amber-bg);border:1px solid rgba(212,137,42,.3);border-radius:6px;
}
.wmi-alert-title{font-size:12px;font-weight:600;color:var(--amber);margin-bottom:6px}
.wmi-query{font-size:11px;font-family:'JetBrains Mono',monospace;background:var(--surface2);padding:6px 10px;border-radius:4px;color:var(--txt2);word-break:break-all;margin-top:6px}

.gpo-detail-body{padding:20px 32px}

.param-section{margin-bottom:16px;background:var(--surface);border:1px solid var(--border);border-radius:6px;overflow:hidden}
.ps-head{display:flex;align-items:center;gap:10px;padding:10px 14px;cursor:pointer;transition:background .1s}
.ps-head:hover{background:var(--surface2)}
.ps-icon{font-size:14px}
.ps-title{font-size:12px;font-weight:600;flex:1}
.ps-count{font-size:11px;color:var(--txt3)}
.ps-arr{font-size:11px;color:var(--txt3);transition:transform .15s}
.ps-arr.open{transform:rotate(90deg)}
.ps-body{display:none;border-top:1px solid var(--border)}
.ps-body.open{display:block}
.param-row{
  display:flex;align-items:center;gap:8px;
  padding:7px 14px;border-bottom:1px solid var(--border);font-size:12px;
}
.param-row:last-child{border-bottom:none}
.param-key{color:var(--txt2);flex:1;min-width:0}
.param-val{font-family:'JetBrains Mono',monospace;color:var(--txt);flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis}
.param-val.bad{color:var(--red)}
.param-hint{font-size:10px;color:var(--txt3);margin-left:4px}

/* ── Toolbar / filtres ─────────────────────────────── */
.toolbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:16px}
.search-mini{position:relative;flex:1;min-width:180px}
.search-mini input{
  width:100%;padding:7px 10px 7px 30px;
  background:var(--surface);border:1px solid var(--border);border-radius:6px;
  color:var(--txt);font-size:12px;outline:none;
}
.search-mini input:focus{border-color:var(--blue)}
.search-mini .si{position:absolute;left:10px;top:50%;transform:translateY(-50%);color:var(--txt3);font-size:13px;pointer-events:none}

.filter-btn{
  padding:5px 12px;border-radius:6px;border:1px solid var(--border);
  background:none;cursor:pointer;font-size:11px;color:var(--txt2);
  font-family:'Inter',sans-serif;transition:all .12s;white-space:nowrap;
}
.filter-btn:hover{border-color:var(--border2);color:var(--txt)}
.filter-btn.on{background:var(--blue);border-color:var(--blue);color:#fff;font-weight:500}
.filter-btn.teal{border-color:var(--teal);color:var(--teal)}
.filter-btn.teal:hover{background:var(--teal-bg)}

.gpo-source-select{
  font-size:11px;background:var(--surface);border:1px solid var(--border);
  color:var(--txt2);padding:5px 10px;border-radius:6px;cursor:pointer;
}

/* ── Conflits / doublons ───────────────────────────── */
.conflict-card{
  background:var(--surface);border:1px solid var(--border);border-radius:8px;
  margin-bottom:8px;overflow:hidden;
}
.conflict-card.high{border-left:3px solid var(--red)}
.conflict-card.low{border-left:3px solid var(--amber)}
.cc-head{display:flex;align-items:center;gap:10px;padding:11px 14px;cursor:pointer}
.cc-head:hover{background:var(--surface2)}
.cc-key{font-size:12px;font-family:'JetBrains Mono',monospace;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cc-body{display:none;padding:10px 14px;border-top:1px solid var(--border)}
.cc-body.open{display:block}
.cc-winner{font-size:11px;padding:6px 10px;background:var(--green-bg);border-radius:4px;margin-bottom:6px}
.cc-loser{font-size:11px;padding:6px 10px;background:var(--red-bg);border-radius:4px;margin-bottom:4px}

/* ── Info box ──────────────────────────────────────── */
.info-box{
  padding:10px 14px;background:var(--blue-bg);border:1px solid rgba(74,127,212,.2);
  border-radius:6px;font-size:12px;color:var(--txt2);margin-bottom:16px;line-height:1.5;
}

/* ── Back btn ──────────────────────────────────────── */
.back-btn{
  display:inline-flex;align-items:center;gap:6px;
  padding:6px 12px;margin-bottom:16px;
  background:var(--surface);border:1px solid var(--border);border-radius:6px;
  font-size:12px;color:var(--txt2);cursor:pointer;font-family:'Inter',sans-serif;
  transition:all .12s;
}
.back-btn:hover{border-color:var(--border2);color:var(--txt)}

/* ── Export btns ───────────────────────────────────── */
.export-btn{
  display:inline-flex;align-items:center;gap:5px;
  padding:4px 10px;background:none;border:1px solid var(--border);
  border-radius:4px;font-size:11px;color:var(--txt2);cursor:pointer;
  font-family:'Inter',sans-serif;transition:all .12s;
}
.export-btn:hover{border-color:var(--border2);color:var(--txt);background:var(--surface2)}

/* ── Graphiques dashboard ───────────────────────────── */
.charts-row{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px}
.chart-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:16px}
.chart-card h3{font-size:12px;font-weight:600;color:var(--txt2);margin-bottom:12px;text-transform:uppercase;letter-spacing:.05em}
.chart-wrap{position:relative;height:160px}

/* Légende donut */
.donut-legend{display:flex;flex-direction:column;gap:5px;margin-top:10px}
.dl-item{display:flex;align-items:center;gap:8px;font-size:11px}
.dl-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}

/* ── Responsive ────────────────────────────────────── */
@media(max-width:768px){
  .sidebar{display:none}
  .content-area{padding:16px}
  .charts-row{grid-template-columns:1fr}
}
</style>
</head>
<body>

<div class="loader" id="loader">
  <div class="loader-ring"></div>
  <div class="loader-text">Chargement de l'audit…</div>
</div>

<div class="app">

<!-- ══ SIDEBAR ══════════════════════════════════════════════════════════════ -->
<nav class="sidebar">
  <div class="sb-logo">
    <h1>🐙 GPOctopus</h1>
    <p>{{ data.generated_at }} · {{ data.gpo_count }} GPO</p>
  </div>

  <div class="sb-score">
    <div class="score-ring">
      <svg width="52" height="52" viewBox="0 0 52 52">
        <circle cx="26" cy="26" r="22" fill="none" stroke="var(--border2)" stroke-width="4"/>
        <circle cx="26" cy="26" r="22" fill="none"
          stroke="{% if data.global_score>=70%}var(--green){% elif data.global_score>=40%}var(--amber){% else %}var(--red){% endif %}"
          stroke-width="4" stroke-linecap="round"
          stroke-dasharray="{{ (data.global_score/100*138.2)|round(1) }} 138.2"/>
      </svg>
      <div class="score-val">
        <span class="n" style="color:{% if data.global_score>=70%}var(--green){% elif data.global_score>=40%}var(--amber){% else %}var(--red){% endif %}">{{ data.global_score }}</span>
        <span class="l">/100</span>
      </div>
    </div>
    <div class="score-info">
      <div class="label" style="color:{% if data.global_score>=70%}var(--green){% elif data.global_score>=40%}var(--amber){% else %}var(--red){% endif %}">
        {% if data.global_score>=70%}Satisfaisant{% elif data.global_score>=40%}À améliorer{% else %}Insuffisant{% endif %}
      </div>
      <div class="sub">{{ data.criticals }} critique · {{ data.warnings }} alerte<br>{{ data.compliant_count }} conforme · {{ data.orphan_count }} orpheline</div>
    </div>
  </div>

  <!-- Onglets principaux -->
  <div class="main-tabs">
    <div class="main-tab active" id="tab-btn-security" onclick="switchTab('security')">
      <span class="tab-icon">🔒</span>
      <span>Sécurité</span>
      {% if data.criticals > 0 %}<span class="tab-badge">{{ data.criticals }}</span>{% endif %}
    </div>
    <div class="main-tab" id="tab-btn-diag" onclick="switchTab('diag')">
      <span class="tab-icon">🔍</span>
      <span>Diagnostic</span>
    </div>
    <div class="main-tab" id="tab-btn-inventory" onclick="switchTab('inventory')">
      <span class="tab-icon">📋</span>
      <span>Inventaire</span>
    </div>
  </div>

  <div class="sb-divider"></div>

  <!-- Sous-nav contextuelle (change selon l'onglet) -->
  <div class="sub-nav" id="subnav-security">
    <div class="sub-nav-label">Sécurité</div>
    <div class="sub-item active" onclick="showSub('security','overview')"><span class="si-icon">◈</span>Vue d'ensemble<span class="si-count">{{ data.total_findings }}</span></div>
    <div class="sub-item" onclick="showSub('security','critical')"><span class="si-icon">🔴</span>Critiques<span class="si-count" style="color:var(--red)">{{ data.criticals }}</span></div>
    <div class="sub-item" onclick="showSub('security','warnings')"><span class="si-icon">🟡</span>Alertes<span class="si-count" style="color:var(--amber)">{{ data.warnings }}</span></div>
    <div class="sub-item" onclick="showSub('security','compliant')"><span class="si-icon">✅</span>Conformes<span class="si-count" style="color:var(--green)">{{ data.compliant_count }}</span></div>
    <div class="sub-item" onclick="showSub('security','conflicts')"><span class="si-icon">⚡</span>Conflits<span class="si-count" style="color:{% if data.conflicts_high>0%}var(--red){% else %}var(--txt3){% endif %}">{{ data.conflicts_high + data.conflicts_low }}</span></div>
    <div class="sub-item" onclick="showSub('security','orphans')"><span class="si-icon">◌</span>Orphelines<span class="si-count">{{ data.orphan_count }}</span></div>
  </div>

  <div class="sub-nav" id="subnav-diag" style="display:none">
    <div class="sub-nav-label">Diagnostic</div>
    <div class="sub-item active" onclick="showSub('diag','search')"><span class="si-icon">⌕</span>Recherche</div>
    <div class="sub-item" onclick="showSub('diag','gpolist')"><span class="si-icon">≡</span>Toutes les GPO</div>
    <div class="sub-item" onclick="showSub('diag','timeline')"><span class="si-icon">⏱</span>Timeline</div>
  </div>

  <div class="sub-nav" id="subnav-inventory" style="display:none">
    <div class="sub-nav-label">Inventaire</div>
    <div class="sub-item active" onclick="showSub('inventory','byou')"><span class="si-icon">⊢</span>Par OU</div>
    <div class="sub-item" onclick="showSub('inventory','bytype')"><span class="si-icon">◫</span>Par type</div>
  </div>

  <div class="sb-footer">
    <span style="font-size:10px;color:var(--txt3)">CIS · ANSSI · MS Baseline</span>
    <div style="display:flex;gap:6px;align-items:center">
      <button class="export-btn" onclick="exportFindings('csv')" title="Export CSV">⬇ CSV</button>
      <button class="export-btn" onclick="exportFindings('md')" title="Export Markdown">📋 MD</button>
      <div class="theme-btn" onclick="toggleTheme()" title="Changer le thème"></div>
    </div>
  </div>
</nav>

<!-- ══ MAIN ═════════════════════════════════════════════════════════════════ -->
<main class="main" id="main-content">

<!-- ════════════════════ ONGLET SÉCURITÉ ════════════════════ -->
<div class="tab-content active" id="tab-security">

  <!-- SUB : Vue d'ensemble -->
  <div id="sub-security-overview">
    <div class="page-header">
      <h2>🔒 Sécurité — Vue d'ensemble</h2>
      <p>Ce qui ne va pas, ce qui est bien, ce qu'il faut faire</p>
    </div>
    <div class="content-area">
      <!-- Métriques -->
      <div class="metrics-row">
        <div class="metric-card red" onclick="showSub('security','critical')">
          <div class="mv">{{ data.criticals }}</div>
          <div class="ml">🔴 Critiques à corriger</div>
        </div>
        <div class="metric-card amber" onclick="showSub('security','warnings')">
          <div class="mv">{{ data.warnings }}</div>
          <div class="ml">🟡 Alertes à surveiller</div>
        </div>
        <div class="metric-card green" onclick="showSub('security','compliant')">
          <div class="mv">{{ data.compliant_count }}</div>
          <div class="ml">✅ Paramètres conformes</div>
        </div>
        <div class="metric-card blue" onclick="showSub('security','conflicts')">
          <div class="mv">{{ data.conflicts_high + data.conflicts_low }}</div>
          <div class="ml">⚡ Conflits GPO</div>
        </div>
      </div>

      <!-- Graphiques -->
      <div class="charts-row">
        <div class="chart-card">
          <h3>Répartition des constatations</h3>
          <div class="chart-wrap"><canvas id="chart-donut"></canvas></div>
          <div class="donut-legend">
            <div class="dl-item"><div class="dl-dot" style="background:var(--red)"></div><span>{{ data.criticals }} critique(s)</span></div>
            <div class="dl-item"><div class="dl-dot" style="background:var(--amber)"></div><span>{{ data.warnings }} alerte(s)</span></div>
            <div class="dl-item"><div class="dl-dot" style="background:var(--blue)"></div><span>{{ data.infos }} info(s)</span></div>
            <div class="dl-item"><div class="dl-dot" style="background:var(--green)"></div><span>{{ data.compliant_count }} conforme(s)</span></div>
          </div>
        </div>
        <div class="chart-card">
          <h3>Score par catégorie</h3>
          <div class="chart-wrap"><canvas id="chart-radar"></canvas></div>
        </div>
      </div>

      <!-- Priorités : top 5 critiques -->
      {% set crit_findings = data.all_findings | selectattr('severity','eq','critical') | list %}
      {% if crit_findings %}
      <div class="section-title">🔴 Actions prioritaires <span class="st-count">{{ crit_findings|length }} à corriger</span></div>
      <div class="finding-list">
        {% for f in crit_findings[:5] %}
        <div class="finding-card critical" data-rule="{{ f.rule_id }}" data-sev="critical" data-txt="{{ f.title|lower }} {{ f.category|lower }}">
          <div class="fc-head" onclick="togFC(this)">
            <div class="fc-sev critical"></div>
            <div class="fc-main">
              <div class="fc-title">{{ f.title }}</div>
              <div class="fc-meta">
                <span>{{ f.category }}</span>
                {% if f.source_gpos %}<span>·</span>
                {% for sg in f.source_gpos[:2] %}<span class="fc-gpo-link" onclick="event.stopPropagation();openGPODetail('{{ sg.guid }}')">{{ sg.name }}</span>{% endfor %}
                {% if f.source_gpos|length > 2 %}<span>+{{ f.source_gpos|length - 2 }}</span>{% endif %}
                {% endif %}
              </div>
            </div>
            <button class="btn-explain" onclick="event.stopPropagation();explainFinding(this,'{{ f.rule_id }}','{{ f.title|replace("'","&#39;") }}','{{ f.remediation|replace("'","&#39;")|replace('"','&quot;') }}')">💬</button>
            <span class="fc-arrow">▶</span>
          </div>
          <div class="fc-body">
            <div class="fc-detail">{{ f.detail }}</div>
            <div class="fc-ref">{{ f.ref }}</div>
            <div class="fc-reco">✅ {{ f.remediation }}</div>
            {% if f.source_gpos %}<div class="fc-sources">GPO : {% for sg in f.source_gpos %}<span class="fc-gpo-link" onclick="openGPODetail('{{ sg.guid }}')">{{ sg.name }}</span>{% endfor %}</div>{% endif %}
            {% if f.action_label %}<div style="margin-top:8px;font-size:11px;padding:4px 8px;background:var(--surface2);border-radius:3px;color:var(--txt2)">🔧 {{ f.action_label }}</div>{% endif %}
            <div class="explain-zone" id="ez-{{ f.rule_id }}"></div>
          </div>
        </div>
        {% endfor %}
        {% if crit_findings|length > 5 %}
        <button class="filter-btn" style="width:100%;margin-top:4px" onclick="showSub('security','critical')">Voir tous les {{ crit_findings|length }} critiques →</button>
        {% endif %}
      </div>
      {% endif %}

      <!-- Alertes résumé -->
      {% set warn_findings = data.all_findings | selectattr('severity','eq','warning') | list %}
      {% if warn_findings %}
      <div class="section-title">🟡 Alertes <span class="st-count">{{ warn_findings|length }}</span></div>
      <div class="finding-list">
        {% for f in warn_findings[:3] %}
        <div class="finding-card warning" data-sev="warning">
          <div class="fc-head" onclick="togFC(this)">
            <div class="fc-sev warning"></div>
            <div class="fc-main">
              <div class="fc-title">{{ f.title }}</div>
              <div class="fc-meta"><span>{{ f.category }}</span></div>
            </div>
            <button class="btn-explain" onclick="event.stopPropagation();explainFinding(this,'{{ f.rule_id }}','{{ f.title|replace("'","&#39;") }}','{{ f.remediation|replace("'","&#39;")|replace('"','&quot;') }}')">💬</button>
            <span class="fc-arrow">▶</span>
          </div>
          <div class="fc-body">
            <div class="fc-detail">{{ f.detail }}</div>
            <div class="fc-ref">{{ f.ref }}</div>
            <div class="fc-reco">✅ {{ f.remediation }}</div>
            {% if f.source_gpos %}<div class="fc-sources">GPO : {% for sg in f.source_gpos %}<span class="fc-gpo-link" onclick="openGPODetail('{{ sg.guid }}')">{{ sg.name }}</span>{% endfor %}</div>{% endif %}
            <div class="explain-zone" id="ez-{{ f.rule_id }}-w"></div>
          </div>
        </div>
        {% endfor %}
        {% if warn_findings|length > 3 %}
        <button class="filter-btn" style="width:100%;margin-top:4px" onclick="showSub('security','warnings')">Voir toutes les {{ warn_findings|length }} alertes →</button>
        {% endif %}
      </div>
      {% endif %}

      {% if not data.all_findings %}
      <div class="empty-state"><div class="es-icon">🎉</div><div class="es-title">Aucun écart détecté</div><div class="es-sub">Toutes les règles CIS / ANSSI / MS Baseline sont respectées.</div></div>
      {% endif %}
    </div>
  </div>

  <!-- SUB : Critiques -->
  <div id="sub-security-critical" style="display:none">
    <div class="page-header">
      <h2>🔴 Constatations critiques</h2>
      <p>{{ data.criticals }} problème(s) à corriger en priorité</p>
    </div>
    <div class="content-area">
      <div class="toolbar">
        <div class="search-mini"><span class="si">⌕</span><input type="text" placeholder="Filtrer…" oninput="filterFindingsSub(this.value,'critical')"></div>
        <select class="gpo-source-select" id="gpo-sel-critical" onchange="filtFByGPO(this.value,'critical')">
          <option value="">Toutes les GPO</option>
          {% for gpo in data.gpo_reports %}{% if gpo.findings | selectattr('severity','eq','critical') | list %}<option value="{{ gpo.guid }}">{{ gpo.name }}</option>{% endif %}{% endfor %}
        </select>
        <button class="export-btn" onclick="exportFindings('csv')">⬇ CSV</button>
      </div>
      <div class="finding-list" id="fl-critical">
        {% for f in data.all_findings | selectattr('severity','eq','critical') | list %}
        <div class="finding-card critical" data-sev="critical" data-txt="{{ f.title|lower }} {{ f.category|lower }}" data-guids="{{ (f.source_gpos or [])|map(attribute='guid')|join(',') }}">
          <div class="fc-head" onclick="togFC(this)">
            <div class="fc-sev critical"></div>
            <div class="fc-main">
              <div class="fc-title">{{ f.title }}{% if f.get('not_configured') %}<span class="nc-tag">non configuré</span>{% endif %}</div>
              <div class="fc-meta"><span>{{ f.category }}</span><span>· {{ f.ref }}</span></div>
            </div>
            <button class="btn-explain" onclick="event.stopPropagation();explainFinding(this,'{{ f.rule_id }}','{{ f.title|replace("'","&#39;") }}','{{ f.remediation|replace("'","&#39;")|replace('"','&quot;') }}')">💬 Expliquer</button>
            <span class="fc-arrow">▶</span>
          </div>
          <div class="fc-body">
            <div class="fc-detail">{{ f.detail }}</div>
            <div class="fc-reco">✅ {{ f.remediation }}</div>
            {% if f.source_gpos %}<div class="fc-sources">GPO source : {% for sg in f.source_gpos %}<span class="fc-gpo-link" onclick="openGPODetail('{{ sg.guid }}')">{{ sg.name }}</span>{% endfor %}</div>{% endif %}
            {% if f.action_label %}<div style="margin-top:6px;font-size:11px;padding:4px 8px;background:var(--surface2);border-radius:3px;color:var(--txt2)">🔧 {{ f.action_label }}</div>{% endif %}
            <div class="explain-zone" id="ez-c-{{ f.rule_id }}"></div>
          </div>
        </div>
        {% endfor %}
        {% if not (data.all_findings | selectattr('severity','eq','critical') | list) %}
        <div class="empty-state"><div class="es-icon">✅</div><div class="es-title">Aucun problème critique</div></div>
        {% endif %}
      </div>
    </div>
  </div>

  <!-- SUB : Alertes -->
  <div id="sub-security-warnings" style="display:none">
    <div class="page-header">
      <h2>🟡 Alertes</h2>
      <p>{{ data.warnings }} alerte(s) à surveiller</p>
    </div>
    <div class="content-area">
      <div class="toolbar">
        <div class="search-mini"><span class="si">⌕</span><input type="text" placeholder="Filtrer…" oninput="filterFindingsSub(this.value,'warning')"></div>
        <select class="gpo-source-select" onchange="filtFByGPO(this.value,'warning')">
          <option value="">Toutes les GPO</option>
          {% for gpo in data.gpo_reports %}{% if gpo.findings | selectattr('severity','eq','warning') | list %}<option value="{{ gpo.guid }}">{{ gpo.name }}</option>{% endif %}{% endfor %}
        </select>
      </div>
      <div class="finding-list" id="fl-warning">
        {% for f in data.all_findings | selectattr('severity','eq','warning') | list %}
        <div class="finding-card warning" data-sev="warning" data-txt="{{ f.title|lower }} {{ f.category|lower }}" data-guids="{{ (f.source_gpos or [])|map(attribute='guid')|join(',') }}">
          <div class="fc-head" onclick="togFC(this)">
            <div class="fc-sev warning"></div>
            <div class="fc-main">
              <div class="fc-title">{{ f.title }}{% if f.get('not_configured') %}<span class="nc-tag">non configuré</span>{% endif %}</div>
              <div class="fc-meta"><span>{{ f.category }}</span><span>· {{ f.ref }}</span></div>
            </div>
            <button class="btn-explain" onclick="event.stopPropagation();explainFinding(this,'{{ f.rule_id }}','{{ f.title|replace("'","&#39;") }}','{{ f.remediation|replace("'","&#39;")|replace('"','&quot;') }}')">💬</button>
            <span class="fc-arrow">▶</span>
          </div>
          <div class="fc-body">
            <div class="fc-detail">{{ f.detail }}</div>
            <div class="fc-reco">✅ {{ f.remediation }}</div>
            {% if f.source_gpos %}<div class="fc-sources">GPO source : {% for sg in f.source_gpos %}<span class="fc-gpo-link" onclick="openGPODetail('{{ sg.guid }}')">{{ sg.name }}</span>{% endfor %}</div>{% endif %}
            <div class="explain-zone" id="ez-w-{{ f.rule_id }}"></div>
          </div>
        </div>
        {% endfor %}
      </div>
    </div>
  </div>

  <!-- SUB : Conformes -->
  <div id="sub-security-compliant" style="display:none">
    <div class="page-header">
      <h2>✅ Paramètres conformes</h2>
      <p>Ces règles sont respectées dans votre AD</p>
    </div>
    <div class="content-area">
      <div class="finding-list">
        {% for r in data.compliant_rules %}
        <div class="finding-card good">
          <div class="fc-head" onclick="togFC(this)">
            <div class="fc-sev good"></div>
            <div class="fc-main">
              <div class="fc-title">{{ r.title }}</div>
              <div class="fc-meta"><span>{{ r.category }}</span><span>· {{ r.ref }}</span></div>
            </div>
            <span class="fc-pill good">conforme</span>
            <span class="fc-arrow">▶</span>
          </div>
          <div class="fc-body">
            <div class="fc-detail">{{ r.remediation }}</div>
          </div>
        </div>
        {% endfor %}
        {% if not data.compliant_rules %}
        <div class="empty-state"><div class="es-icon">⚠️</div><div class="es-title">Aucun paramètre conforme détecté</div><div class="es-sub">Montez le SYSVOL pour une analyse complète.</div></div>
        {% endif %}
      </div>
    </div>
  </div>

  <!-- SUB : Conflits -->
  <div id="sub-security-conflicts" style="display:none">
    <div class="page-header">
      <h2>⚡ Conflits GPO</h2>
      <p>Même paramètre configuré différemment dans plusieurs GPO — la GPO de priorité la plus haute gagne</p>
    </div>
    <div class="content-area">
      <div class="info-box">Un conflit = deux GPO définissent la même clé avec des valeurs différentes. La <strong>GPO gagnante</strong> est celle liée à l'OU la plus profonde ou marquée Enforced.</div>
      <div class="toolbar">
        <button class="filter-btn on" onclick="filtConflicts('all',this)">Tous ({{ data.conflicts_high + data.conflicts_low }})</button>
        <button class="filter-btn" onclick="filtConflicts('high',this)">🔴 Sécurité ({{ data.conflicts_high }})</button>
        <button class="filter-btn" onclick="filtConflicts('low',this)">🟡 Autres ({{ data.conflicts_low }})</button>
        <div class="search-mini" style="margin-left:auto"><span class="si">⌕</span><input type="text" placeholder="Filtrer…" oninput="searchConflicts(this.value)"></div>
      </div>
      {% if data.gpo_conflicts %}
      {% for c in data.gpo_conflicts %}
      <div class="conflict-card {% if c.is_security %}high{% else %}low{% endif %}" data-sec="{{ c.is_security|lower }}" data-txt="{{ c.label|lower }}">
        <div class="cc-head" onclick="togCC(this)">
          <span style="font-size:11px">{% if c.is_security %}🔴{% else %}🟡{% endif %}</span>
          <span class="cc-key">{{ c.section_label }} → {{ c.key_short }}</span>
          <span style="font-size:10px;color:var(--txt3)">{{ c.gpo_count }} GPO</span>
          <span style="font-size:11px;color:var(--txt3);transition:transform .15s" class="cc-arr">▶</span>
        </div>
        <div class="cc-body">
          <div class="cc-winner">✅ Gagnant : <strong style="cursor:pointer;color:var(--green)" onclick="openGPODetail('{{ c.winner.gpo_guid }}')">{{ c.winner.gpo_name }}</strong> → <code>{{ c.winner.value }}</code>{% if c.winner.enforced %} <span style="color:var(--red);font-size:10px">ENFORCED</span>{% endif %}</div>
          {% for l in c.losers %}<div class="cc-loser">❌ Écrasé : <strong style="cursor:pointer" onclick="openGPODetail('{{ l.gpo_guid }}')">{{ l.gpo_name }}</strong> → <code>{{ l.value }}</code></div>{% endfor %}
        </div>
      </div>
      {% endfor %}
      {% else %}
      <div class="empty-state"><div class="es-icon">✅</div><div class="es-title">Aucun conflit détecté</div></div>
      {% endif %}
    </div>
  </div>

  <!-- SUB : Orphelines -->
  <div id="sub-security-orphans" style="display:none">
    <div class="page-header">
      <h2>◌ GPO orphelines</h2>
      <p>Non liées à une OU — inutiles ou dangereuses selon leur contenu</p>
    </div>
    <div class="content-area">
      {% if data.orphan_gpos %}
      <div class="info-box">Ces GPO existent mais ne s'appliquent sur aucune OU. Vérifiez si elles doivent être supprimées ou liées.</div>
      {% for name in data.orphan_gpos %}
      <div style="background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:12px 16px;margin-bottom:6px;display:flex;align-items:center;gap:10px">
        <span style="color:var(--amber)">◌</span>
        <span style="font-size:13px;font-weight:500">{{ name }}</span>
        <span style="font-size:11px;color:var(--txt3);margin-left:auto">Non liée à aucune OU — à supprimer ou archiver</span>
      </div>
      {% endfor %}
      {% else %}
      <div class="empty-state"><div class="es-icon">✅</div><div class="es-title">Aucune GPO orpheline</div></div>
      {% endif %}
    </div>
  </div>

</div><!-- /tab-security -->


<!-- ════════════════════ ONGLET DIAGNOSTIC ════════════════════ -->
<div class="tab-content" id="tab-diag">

  <!-- SUB : Recherche -->
  <div id="sub-diag-search">
    <div class="page-header">
      <h2>🔍 Diagnostic — Recherche GPO</h2>
      <p>Cherchez n'importe quoi : imprimante, chemin réseau, paramètre, script, RDS… Les synonymes sont automatiques.</p>
    </div>
    <div class="content-area">
      <div class="search-bar">
        <span class="search-icon">⌕</span>
        <input id="search-input" type="text"
          placeholder="Ex: RDS imprimante · print01 · startup script · SMB · proxy…"
          oninput="globalSearch(this.value)"
          onfocus="this.style.boxShadow='0 0 0 3px rgba(74,127,212,.15)'"
          onblur="this.style.boxShadow=''">
      </div>
      <div class="search-hint">💡 Plusieurs mots = ET automatique (RDS + imprimante = GPO qui touchent les deux) · Les synonymes sont inclus (RDS↔Terminal Services, imprimante↔printer…)</div>

      <div class="shortcut-group">
        <div class="shortcut-label">Raccourcis simples</div>
        <div class="shortcut-row">
          <button class="shortcut-btn" onclick="qs('imprimante')">🖨 Imprimantes</button>
          <button class="shortcut-btn" onclick="qs('lecteur réseau')">💾 Lecteurs réseau</button>
          <button class="shortcut-btn" onclick="qs('script')">📜 Scripts</button>
          <button class="shortcut-btn" onclick="qs('tâche planifiée')">⏰ Tâches</button>
          <button class="shortcut-btn" onclick="qs('service windows')">🔧 Services</button>
          <button class="shortcut-btn" onclick="qs('registre')">🗝 Registre</button>
          <button class="shortcut-btn" onclick="qs('groupe local')">👥 Groupes</button>
        </div>
      </div>
      <div class="shortcut-group">
        <div class="shortcut-label">🔗 Combinaisons diagnostic — GPO touchant plusieurs domaines</div>
        <div class="shortcut-row">
          <button class="shortcut-btn combo" onclick="qs('RDS imprimante')">🖥+🖨 RDS &amp; Imprimante</button>
          <button class="shortcut-btn combo" onclick="qs('imprimante lecteur')">🖨+💾 Imprimante &amp; Lecteur</button>
          <button class="shortcut-btn combo" onclick="qs('logon script imprimante')">📜+🖨 Script logon &amp; Imprimante</button>
          <button class="shortcut-btn combo" onclick="qs('startup script lecteur')">📜+💾 Script &amp; Lecteur</button>
          <button class="shortcut-btn combo" onclick="qs('service registre')">🔧+🗝 Service &amp; Registre</button>
          <button class="shortcut-btn combo" onclick="qs('proxy internet')">🌐 Proxy &amp; Internet</button>
        </div>
      </div>

      <div id="search-results-header" style="display:none" class="search-result-header">
        <span id="sr-count"></span>
        <span id="sr-gpos"></span>
        <span id="sr-syn"></span>
      </div>
      <div id="search-results"></div>

      <div id="search-empty" class="empty-state">
        <div class="es-icon">⌕</div>
        <div class="es-title">Tapez pour chercher</div>
        <div class="es-sub">
          Chemin UNC · Lettre de lecteur · Nom de script · Clé de registre<br>
          Nom de service · Commande · Nom de groupe · Paramètre de sécurité<br>
          <span style="color:var(--teal)">+ synonymes automatiques</span>
        </div>
      </div>
    </div>
  </div>

  <!-- SUB : Toutes les GPO -->
  <div id="sub-diag-gpolist" style="display:none">
    <div class="page-header">
      <h2>≡ Toutes les GPO</h2>
      <p>Cliquez sur une GPO pour voir tous ses paramètres et ses findings</p>
    </div>
    <div class="content-area">
      <div class="toolbar">
        <div class="search-mini"><span class="si">⌕</span><input type="text" placeholder="Rechercher une GPO…" oninput="searchGPOList(this.value)"></div>
        <button class="filter-btn on" onclick="filtGPO('all',this)">Toutes</button>
        <button class="filter-btn" onclick="filtGPO('issues',this)">Avec problèmes</button>
        <button class="filter-btn" onclick="filtGPO('wmi',this)">Filtre WMI</button>
        <button class="filter-btn" onclick="filtGPO('orphan',this)">Orphelines</button>
      </div>
      <div class="gpo-grid" id="gpo-list-area"></div>
    </div>
  </div>

  <!-- SUB : Timeline -->
  <div id="sub-diag-timeline" style="display:none">
    <div class="page-header">
      <h2>⏱ Timeline des modifications</h2>
      <p>Identifiez ce qui a changé récemment — utile quand un problème est apparu à une date précise</p>
    </div>
    <div class="content-area">
      <div class="toolbar">
        <button class="filter-btn on" onclick="filterTimeline('all',this)">Tout</button>
        <button class="filter-btn" onclick="filterTimeline(7,this)">7 jours</button>
        <button class="filter-btn" onclick="filterTimeline(30,this)">30 jours</button>
        <button class="filter-btn" onclick="filterTimeline(90,this)">90 jours</button>
        <button class="filter-btn" onclick="filterTimeline(365,this)">1 an</button>
      </div>
      <div id="timeline-content"></div>
    </div>
  </div>

  <!-- SUB : GPO Détail -->
  <div id="sub-diag-gpodetail" style="display:none">
    <div class="gpo-detail-header" id="gpo-detail-header">
      <!-- rempli par JS -->
    </div>
    <div class="content-area">
      <button class="back-btn" onclick="goBackFromDetail()">← Retour</button>
      <div id="gpo-detail-body"></div>
    </div>
  </div>

</div><!-- /tab-diag -->


<!-- ════════════════════ ONGLET INVENTAIRE ════════════════════ -->
<div class="tab-content" id="tab-inventory">

  <!-- SUB : Par OU -->
  <div id="sub-inventory-byou">
    <div class="page-header">
      <h2>⊢ Inventaire par OU</h2>
      <p>Quelles GPO s'appliquent sur quelle OU — dans l'ordre de priorité Windows réel</p>
    </div>
    <div class="content-area">
      <div class="toolbar">
        <div class="search-mini"><span class="si">⌕</span><input type="text" placeholder="Filtrer par OU…" oninput="searchOU(this.value)"></div>
      </div>
      <div id="byou-content"></div>
    </div>
  </div>

  <!-- SUB : Par type -->
  <div id="sub-inventory-bytype" style="display:none">
    <div class="page-header">
      <h2>◫ Inventaire par type de configuration</h2>
      <p>Imprimantes, lecteurs réseau, scripts, tâches… combien de GPO configurent chaque type</p>
    </div>
    <div class="content-area">
      <div id="type-grid-area"></div>
      <div id="type-detail-area"></div>
    </div>
  </div>

</div><!-- /tab-inventory -->

</main>
</div><!-- /app -->

<!-- ══ DONNÉES ══════════════════════════════════════════════════════════════ -->
<script id="gpo-json" type="application/json">{{ data.gpo_reports | tojson }}</script>
<script>
// ══════════════════════════════════════════════════════════════════════
// INIT
// ══════════════════════════════════════════════════════════════════════
let _gpos = [];
const _gpoContentIndex = {{ data.gpo_content_index | tojson }};
const _searchIndex     = {{ data.search_index | tojson }};
const _findingsData    = {{ data.all_findings | tojson }};
const _conflictsData   = {{ data.gpo_conflicts | tojson }};

_searchIndex.forEach(item => {
  item.search_blob = [item.gpo_name,item.type,item.key,item.value,item.context]
    .filter(Boolean).join(' ').toLowerCase();
});

window.addEventListener('DOMContentLoaded', () => {
  const savedTheme = localStorage.getItem('gpo-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', savedTheme);

  try { _gpos = JSON.parse(document.getElementById('gpo-json').textContent); } catch(e){}

  renderCharts();

  requestAnimationFrame(() => {
    document.getElementById('loader').classList.add('done');
    setTimeout(() => { const l=document.getElementById('loader'); if(l)l.remove(); }, 400);
  });

  const idle = typeof requestIdleCallback!=='undefined' ? requestIdleCallback : fn=>setTimeout(fn,100);
  idle(() => renderGPOList(_gpos));
  idle(() => { renderByOU(''); renderByType(); });
});

// ══════════════════════════════════════════════════════════════════════
// NAVIGATION
// ══════════════════════════════════════════════════════════════════════
let _currentTab = 'security';
let _currentSub = { security:'overview', diag:'search', inventory:'byou' };
let _prevSub = null; // pour le retour depuis GPO détail

function switchTab(tab) {
  // Désactiver tous les onglets
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.main-tab').forEach(b=>b.classList.remove('active'));
  document.querySelectorAll('.sub-nav').forEach(n=>n.style.display='none');

  document.getElementById('tab-'+tab).classList.add('active');
  document.getElementById('tab-btn-'+tab).classList.add('active');
  document.getElementById('subnav-'+tab).style.display='';

  _currentTab = tab;
  showSub(tab, _currentSub[tab]);
}

function showSub(tab, sub) {
  // Cacher toutes les sous-vues du tab
  const tabEl = document.getElementById('tab-'+tab);
  tabEl.querySelectorAll('[id^="sub-'+tab+'-"]').forEach(el=>el.style.display='none');

  const el = document.getElementById('sub-'+tab+'-'+sub);
  if(el) el.style.display='';

  _currentSub[tab] = sub;

  // Mettre à jour la sous-nav
  document.querySelectorAll('#subnav-'+tab+' .sub-item').forEach(si=>{
    si.classList.toggle('active', si.getAttribute('onclick') && si.getAttribute('onclick').includes("'"+sub+"'"));
  });

  // Lazy init
  if(tab==='inventory' && sub==='byou') renderByOU('');
  if(tab==='inventory' && sub==='bytype') renderByType();
  if(tab==='diag' && sub==='timeline') renderTimeline();
  if(tab==='diag' && sub==='gpolist') renderGPOList(_gpos);
}

function openGPODetail(guid) {
  _prevSub = {tab:_currentTab, sub:_currentSub[_currentTab]};
  if(_currentTab !== 'diag') switchTab('diag');
  showSub('diag','gpodetail');
  renderGPODetail(guid);
}

function goBackFromDetail() {
  if(_prevSub) {
    switchTab(_prevSub.tab);
    showSub(_prevSub.tab, _prevSub.sub);
    _prevSub = null;
  } else {
    showSub('diag','gpolist');
  }
}

// ══════════════════════════════════════════════════════════════════════
// THÈME
// ══════════════════════════════════════════════════════════════════════
function toggleTheme() {
  const cur = document.documentElement.getAttribute('data-theme');
  const next = cur==='dark'?'light':'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('gpo-theme', next);
  setTimeout(renderCharts, 100);
}

// ══════════════════════════════════════════════════════════════════════
// CHARTS
// ══════════════════════════════════════════════════════════════════════
let _charts={};
function renderCharts(){
  const isDark = document.documentElement.getAttribute('data-theme')==='dark';
  const gc = isDark?'rgba(255,255,255,.06)':'rgba(0,0,0,.06)';
  const tc = isDark?'#7a84a8':'#5a6285';

  const dc = document.getElementById('chart-donut');
  if(dc){
    if(_charts.donut) _charts.donut.destroy();
    _charts.donut = new Chart(dc,{
      type:'doughnut',
      data:{
        labels:['Critiques','Alertes','Infos','Conformes'],
        datasets:[{
          data:[{{ data.criticals }},{{ data.warnings }},{{ data.infos }},{{ data.compliant_count }}],
          backgroundColor:[isDark?'#e05252':'#c03030',isDark?'#d4892a':'#a86a10',isDark?'#4a7fd4':'#2655b0',isDark?'#3a9e72':'#1e7a54'],
          borderWidth:0,hoverOffset:4
        }]
      },
      options:{responsive:true,maintainAspectRatio:false,cutout:'65%',
        plugins:{legend:{display:false},tooltip:{callbacks:{label:c=>` ${c.label} : ${c.parsed}`}}}}
    });
  }

  const rc = document.getElementById('chart-radar');
  if(rc){
    if(_charts.radar) _charts.radar.destroy();
    const cats={'Mots de passe':0,'Authentif.':0,'Audit':0,'UAC':0,'Système':0,'Accès':0};
    const maxes={'Mots de passe':6,'Authentif.':7,'Audit':7,'UAC':4,'Système':6,'Accès':4};
    _findingsData.forEach(f=>{
      const t=(f.title+' '+f.category).toLowerCase();
      if(t.includes('passe')||t.includes('password')) cats['Mots de passe']++;
      else if(t.includes('ntlm')||t.includes('auth')||t.includes('kerberos')||t.includes('smb')) cats['Authentif.']++;
      else if(t.includes('audit')||t.includes('journal')) cats['Audit']++;
      else if(t.includes('uac')||t.includes('élév')) cats['UAC']++;
      else if(t.includes('système')||t.includes('service')||t.includes('pare-feu')||t.includes('wdigest')) cats['Système']++;
      else cats['Accès']++;
    });
    const labels=Object.keys(cats);
    const scores=labels.map(l=>Math.max(0,Math.round((1-cats[l]/(maxes[l]||1))*100)));
    _charts.radar = new Chart(rc,{
      type:'radar',
      data:{labels,datasets:[{data:scores,backgroundColor:isDark?'rgba(74,127,212,.12)':'rgba(38,85,176,.1)',borderColor:isDark?'#4a7fd4':'#2655b0',borderWidth:2,pointBackgroundColor:isDark?'#4a7fd4':'#2655b0',pointRadius:3}]},
      options:{responsive:true,maintainAspectRatio:false,
        scales:{r:{min:0,max:100,grid:{color:gc},ticks:{color:tc,backdropColor:'transparent',stepSize:25,font:{size:10}},pointLabels:{color:tc,font:{size:10}}}},
        plugins:{legend:{display:false}}}
    });
  }
}

// ══════════════════════════════════════════════════════════════════════
// SYNONYMES & MOTEUR DE RECHERCHE
// ══════════════════════════════════════════════════════════════════════
const SYNONYMS=[
  ['rds','terminal','remoteapp','remotefx','mstsc','rdp','bureau à distance','thinprint'],
  ['terminal','rds','remoteapp','rdp'],
  ['rdp','rds','terminal','mstsc'],
  ['imprimante','printer','print','spooler','printers','thinprint'],
  ['printer','imprimante','print','spooler'],
  ['print','imprimante','printer','spooler'],
  ['lecteur','drive','drives','réseau','partage','unc'],
  ['drive','lecteur','réseau','unc'],
  ['réseau','lecteur','drive','unc','partage'],
  ['script','scripts','logon','startup','shutdown','logoff','ps1','bat','cmd','vbs'],
  ['logon','script','ouverture de session'],
  ['startup','script','démarrage'],
  ['smb','cifs','lanman','partage','smbv1'],
  ['ntlm','lm','kerberos','authentification','ntlmv2'],
  ['kerberos','ntlm','authentification','ticket'],
  ['firewall','pare-feu','parefeu'],
  ['pare-feu','firewall'],
  ['proxy','internet','wpad','pac','ie','edge'],
  ['internet','proxy','ie','wpad'],
  ['uac','lua','elevation','élévation','token'],
  ['wdigest','lsass','credential','plaintext'],
  ['registre','registry','regedit','hklm','hkcu'],
  ['registry','registre','hklm','hkcu'],
  ['tâche','task','scheduled','planifiée'],
  ['task','tâche','planifiée'],
  ['service','services'],
  ['groupe','group','administrators','membre'],
  ['group','groupe','administrators'],
  ['gpo','stratégie','policy'],
  ['bitlocker','chiffrement','tpm'],
  ['wsus','update','windows update'],
  ['antivirus','defender','wdav'],
  ['vpn','ipsec','directaccess'],
];
const _synMap={};
SYNONYMS.forEach(([k,...syns])=>{ if(!_synMap[k])_synMap[k]=new Set(); syns.forEach(s=>_synMap[k].add(s)); });

function _expandTokens(tokens){
  const synsUsed={};
  tokens.forEach(t=>{ const s=_synMap[t]; if(s&&s.size>0) synsUsed[t]=[...s]; });
  return synsUsed;
}

let _lastQ='';
function qs(q){ document.getElementById('search-input').value=q; globalSearch(q); }

function globalSearch(q){
  _lastQ=q;
  const hdr=document.getElementById('search-results-header');
  const res=document.getElementById('search-results');
  const empty=document.getElementById('search-empty');
  const qt=q.trim();

  if(!qt||qt.length<2){
    hdr.style.display='none'; res.innerHTML=''; empty.style.display='';
    return;
  }
  empty.style.display='none';

  const rawTokens=qt.toLowerCase().split(/\s+/).filter(Boolean);
  const synsUsed=_expandTokens(rawTokens);

  // Étape 1 : entrées qui couvrent au moins un token (direct ou synonyme)
  const candidates=_searchIndex.map(item=>{
    const covered=rawTokens.filter(t=>{
      if(item.search_blob.includes(t)) return true;
      const syns=_synMap[t];
      return syns&&[...syns].some(s=>item.search_blob.includes(s));
    });
    return covered.length>0?{...item,_covered:covered}:null;
  }).filter(Boolean);

  // Étape 2 : grouper par GPO
  const byGpo={};
  candidates.forEach(item=>{
    if(!byGpo[item.gpo_guid]){
      const gMeta=_gpos.find(x=>x.guid===item.gpo_guid)||{};
      byGpo[item.gpo_guid]={
        name:item.gpo_name,guid:item.gpo_guid,
        items:[],covered:new Set(),
        links:gMeta.links||[],score:gMeta.score,
        findings:gMeta.findings||[],wmi_filter:gMeta.wmi_filter,
      };
    }
    item._covered.forEach(t=>byGpo[item.gpo_guid].covered.add(t));
    byGpo[item.gpo_guid].items.push(item);
  });

  // Étape 3 : garder uniquement les GPO couvrant TOUS les tokens
  let groups=Object.values(byGpo).filter(g=>rawTokens.every(t=>g.covered.has(t)));

  // Scoring
  groups.forEach(g=>{
    const types=new Set(g.items.map(i=>i.type));
    g._rel=g.items.length*2+types.size*5+(g.links.some(l=>l.enforced)?3:0);
  });
  groups.sort((a,b)=>b._rel-a._rel);

  // Header
  const total=groups.reduce((a,g)=>a+g.items.length,0);
  hdr.style.display='flex';
  document.getElementById('sr-count').textContent=`${total} résultat${total!==1?'s':''}`;
  document.getElementById('sr-gpos').textContent=`dans ${groups.length} GPO`;
  const synKeys=Object.keys(synsUsed);
  const synEl=document.getElementById('sr-syn');
  synEl.innerHTML=synKeys.length>0?`<span class="syn-badge">🔄 Synonymes : ${synKeys.map(k=>`${k}↔${synsUsed[k].slice(0,2).join(',')}`).join(' · ')}</span>`:'';

  if(!groups.length){
    const hints=rawTokens.map(t=>{
      const syns=_synMap[t]?[..._synMap[t]]:[];
      const n=_searchIndex.filter(i=>i.search_blob.includes(t)||syns.some(s=>i.search_blob.includes(s))).length;
      return{t,n};
    }).filter(x=>x.n>0).sort((a,b)=>b.n-a.n);
    res.innerHTML=`<div class="empty-state"><div class="es-icon">🔍</div>
      <div class="es-title">Aucun résultat pour "${_escHtml(qt)}"</div>
      ${hints.length?`<div class="es-sub">${hints.map(h=>`"<strong>${_escHtml(h.t)}</strong>" seul → ${h.n} résultat${h.n>1?'s':''}`).join(' · ')}<br><span style="color:var(--amber)">Aucune GPO ne contient tous ces termes ensemble</span></div>`:''}</div>`;
    return;
  }

  const allToks=[...rawTokens,...rawTokens.flatMap(t=>[...(_synMap[t]||[])])];

  res.innerHTML=groups.map(group=>{
    // Bandeau OU diagnostic
    const linksHtml=(group.links||[]).slice(0,4).map(l=>{
      const parts=(l.ou||'').split(',').filter(p=>p.trim().startsWith('OU=')).map(p=>p.slice(3)).reverse();
      const label=parts.join(' › ')||l.ou||'(racine)';
      return `<div class="diag-ou-row">
        <span style="color:var(--txt3)">⊢</span>
        <span>${_escHtml(label)}</span>
        ${l.enforced?'<span style="color:var(--red);font-size:10px;font-weight:700">ENFORCED</span>':''}
      </div>`;
    }).join('');

    const scoreColor=(group.score||0)>=70?'var(--green)':(group.score||0)>=40?'var(--amber)':'var(--red)';
    const critCount=(group.findings||[]).filter(f=>f.severity==='critical').length;

    const covBadges=rawTokens.map(t=>`<span class="covered-badge">✓ ${_escHtml(t)}</span>`).join('');

    // Regrouper les entrées par token
    const bodyHtml=rawTokens.length>1
      ?rawTokens.map(t=>{
        const syns=[...(_synMap[t]||[])];
        const tItems=group.items.filter(i=>i.search_blob.includes(t)||syns.some(s=>i.search_blob.includes(s)));
        if(!tItems.length)return'';
        const viaS=syns.length>0&&tItems.some(i=>!i.search_blob.includes(t));
        return`<div style="border-top:1px solid var(--border)">
          <div style="padding:5px 12px;background:var(--surface2);font-size:11px;color:var(--txt3);display:flex;align-items:center;gap:6px">
            <mark style="padding:1px 6px;border-radius:3px;font-weight:600">${_escHtml(t)}</mark>
            — ${tItems.length} entrée${tItems.length>1?'s':''}
            ${viaS?'<span style="color:var(--txt3);font-style:italic;font-size:10px">(via synonymes)</span>':''}
          </div>
          ${_renderResultRows(tItems,allToks,group.guid)}
        </div>`;
      }).join('')
      :`<div style="border-top:1px solid var(--border)">${_renderResultRows(group.items,allToks,group.guid)}</div>`;

    return`<div class="result-gpo">
      <div class="result-gpo-head" onclick="openGPODetail('${group.guid}')">
        <span style="font-size:14px">📄</span>
        <span class="result-gpo-name">${_highlight(group.name,allToks)}</span>
        <div class="covered-badges">${covBadges}</div>
        <span style="font-size:11px;color:var(--txt3)">${group.items.length} entrée${group.items.length>1?'s':''}</span>
        ${group.wmi_filter?'<span class="badge wmi" style="font-size:10px">⚙ WMI</span>':''}
        <span style="font-size:11px;color:var(--blue);flex-shrink:0">Ouvrir →</span>
      </div>
      <div class="diag-banner">
        <div class="diag-section">
          <div class="diag-label">OU liées</div>
          ${linksHtml||'<span style="font-size:10px;color:var(--amber)">Non liée</span>'}
        </div>
        <div class="diag-section" style="margin-left:auto;display:flex;gap:8px;align-items:center">
          ${group.score!=null?`<span style="font-size:11px;font-weight:600;color:${scoreColor}">Score ${group.score}/100</span>`:''}
          ${critCount>0?`<span class="badge score-bad">${critCount} critique${critCount>1?'s':''}</span>`:''}
        </div>
      </div>
      ${bodyHtml}
    </div>`;
  }).join('');
}

function _renderResultRows(items,allToks,guid){
  const shown=items.slice(0,20);
  const more=items.length-shown.length;
  const rows=shown.map(item=>`
    <tr onclick="openGPODetail('${guid}')">
      <td style="width:20px;text-align:center;padding:5px 8px">${item.type_icon}</td>
      <td class="rt-type">${_highlight(item.type,allToks)}</td>
      <td class="rt-key">${_highlight(item.key,allToks)}</td>
      <td class="rt-val">${_highlight(item.value,allToks)}</td>
      <td class="rt-ctx">${_highlight(item.context,allToks)}</td>
    </tr>`).join('');
  const moreRow=more>0?`<tr><td colspan="5" style="padding:4px 12px;font-size:11px;color:var(--txt3);font-style:italic">… ${more} entrée${more>1?'s':''} supplémentaire${more>1?'s':''}</td></tr>`:'';
  return`<table class="result-table"><tbody>${rows}${moreRow}</tbody></table>`;
}

// ══════════════════════════════════════════════════════════════════════
// GPO LISTE
// ══════════════════════════════════════════════════════════════════════
let _gpoFilter='all', _gpoSearch='';

function filtGPO(f,btn){
  _gpoFilter=f;
  document.querySelectorAll('#sub-diag-gpolist .filter-btn').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on');
  renderGPOList(_gpos);
}
function searchGPOList(q){ _gpoSearch=q.toLowerCase(); renderGPOList(_gpos); }

function renderGPOList(gpos){
  let g=[...gpos];
  if(_gpoSearch) g=g.filter(x=>x.name.toLowerCase().includes(_gpoSearch));
  if(_gpoFilter==='issues') g=g.filter(x=>x.findings?.length>0);
  if(_gpoFilter==='wmi') g=g.filter(x=>x.wmi_filter);
  if(_gpoFilter==='orphan') g=g.filter(x=>x.is_orphan);
  g.sort((a,b)=>(a.score||100)-(b.score||100));

  const area=document.getElementById('gpo-list-area');
  if(!area) return;

  area.innerHTML=g.map(gpo=>{
    const sc=gpo.score??100;
    const scClass=sc>=70?'score-good':sc>=40?'score-mid':'score-bad';
    const flg=parseInt(gpo.flags||0);
    const links=(gpo.links||[]);
    const ouList=links.slice(0,3).map(l=>{
      const parts=(l.ou||'').split(',').filter(p=>p.startsWith('OU=')).map(p=>p.slice(3)).reverse();
      return parts.join(' › ')||l.ou||'(racine)';
    }).join(', ')+(links.length>3?` +${links.length-3}`:'');

    const critCount=(gpo.findings||[]).filter(f=>f.severity==='critical').length;
    const warnCount=(gpo.findings||[]).filter(f=>f.severity==='warning').length;

    return`<div class="gpo-card" data-guid="${gpo.guid}" data-issues="${(gpo.findings||[]).length}" data-orphan="${gpo.is_orphan}" data-wmi="${!!gpo.wmi_filter}">
      <div class="gpo-card-head" onclick="openGPODetail('${gpo.guid}')">
        <div class="gpo-name" title="${_escHtml(gpo.name)}">${_escHtml(gpo.name)}</div>
        <div class="gpo-badges">
          ${!gpo.is_orphan?`<span class="badge ${scClass}">Score ${sc}</span>`:''}
          ${critCount>0?`<span class="badge score-bad">🔴 ${critCount}</span>`:''}
          ${warnCount>0?`<span class="badge score-mid">🟡 ${warnCount}</span>`:''}
          ${flg===3?'<span class="badge disabled">désactivée</span>':flg===1?'<span class="badge disabled">PC off</span>':flg===2?'<span class="badge disabled">User off</span>':''}
          ${gpo.is_orphan?'<span class="badge orphan">orpheline</span>':''}
          ${gpo.wmi_filter?'<span class="badge wmi">WMI</span>':''}
          ${links.some(l=>l.enforced)?'<span class="badge enforced">ENFORCED</span>':''}
        </div>
      </div>
      ${ouList?`<div style="padding:4px 16px 10px;font-size:11px;color:var(--txt3);font-family:'JetBrains Mono',monospace">⊢ ${_escHtml(ouList)}</div>`:''}
    </div>`;
  }).join('')||'<div class="empty-state"><div class="es-icon">🔍</div><div class="es-title">Aucune GPO correspondante</div></div>';
}

// ══════════════════════════════════════════════════════════════════════
// GPO DÉTAIL
// ══════════════════════════════════════════════════════════════════════
const ATTACK_EXAMPLES={
  'SYS-001':{attack:'Mimikatz → <code>sekurlsa::logonpasswords</code> extrait les mots de passe en clair depuis lsass',tool:'Mimikatz, ProcDump',impact:'Extraction des credentials de toutes les sessions actives'},
  'SYS-002':{attack:'EternalBlue/WannaCry : exécution de code à distance sans authentification via SMBv1',tool:'EternalBlue, Metasploit',impact:'Compromission en masse, ransomware'},
  'AUTH-002':{attack:'Capture NTLMv1 avec Responder, crack GPU en quelques heures',tool:'Responder, Hashcat',impact:'Credential theft, mouvement latéral'},
  'UAC-001':{attack:'Bypass UAC via token manipulation, élévation silencieuse sans prompt utilisateur',tool:'Bypass UAC techniques',impact:'Escalade privilèges sans interaction'},
  'PWD-001':{attack:'Brute-force / dictionnaire, mots de passe courts crackés en minutes',tool:'Hashcat, John the Ripper',impact:'Compromission comptes, accès non autorisé'},
  'PRIV-R001':{attack:'SeDebugPrivilege → injection dans lsass, dump de tous les credentials',tool:'Mimikatz',impact:'Extraction credentials de tous les utilisateurs connectés'},
  'PRIV-R005':{attack:'Driver malveillant en Ring 0 → contournement complet EDR/AV',tool:'KDU, BYOVD',impact:'Contrôle total du noyau'},
  'AUTH-001':{attack:'Rainbow tables DES sur moitiés de hash LM — cassé en secondes',tool:'Ophcrack, L0phtCrack',impact:'Tous mots de passe < 15 caractères récupérables instantanément'},
  'REGXML-001':{attack:'Pass-the-Hash via C$/ADMIN$ sur tous les postes du domaine',tool:'CrackMapExec, Impacket',impact:'Mouvement latéral trivial sur tout le parc'},
};

function renderGPODetail(guid){
  const g=_gpos.find(x=>x.guid===guid);
  if(!g) return;

  const flg=parseInt(g.flags||0);
  const flagLabel={'1':'Config. ordinateur désactivée','2':'Config. utilisateur désactivée','3':'Entièrement désactivée'}[String(flg)]||'';
  const sc=g.score??100;
  const scColor=sc>=70?'var(--green)':sc>=40?'var(--amber)':'var(--red)';

  // Header
  const hdr=document.getElementById('gpo-detail-header');
  hdr.innerHTML=`
    <h2>${_escHtml(g.name)}</h2>
    <div class="gpo-detail-meta">
      <div class="gdm-item"><span class="gdm-l">GUID</span><span class="gdm-v" style="font-size:10px">${g.guid}</span></div>
      <div class="gdm-item"><span class="gdm-l">Modifié</span><span class="gdm-v">${g.changed?g.changed.slice(0,10):'—'}</span></div>
      <div class="gdm-item"><span class="gdm-l">Créé</span><span class="gdm-v">${g.created?g.created.slice(0,10):'—'}</span></div>
      ${sc!==null?`<div class="gdm-item"><span class="gdm-l">Score</span><span class="gdm-v" style="color:${scColor};font-weight:700">${sc}/100</span></div>`:''}
      ${flagLabel?`<div class="gdm-item"><span class="gdm-l">Statut</span><span class="gdm-v" style="color:var(--amber)">${flagLabel}</span></div>`:''}
      ${g.is_orphan?`<div class="gdm-item"><span class="gdm-l">Liens</span><span class="gdm-v" style="color:var(--blue)">Orpheline</span></div>`:''}
    </div>
    ${g.wmi_filter?`<div class="wmi-alert" style="margin:12px 0 0">
      <div class="wmi-alert-title">⚙ Filtre WMI actif — ne s'applique pas sur toutes les machines</div>
      <div style="font-size:11px;color:var(--txt2)"><strong>Nom :</strong> ${_escHtml(g.wmi_filter.name||'')}${g.wmi_filter.description?` — ${_escHtml(g.wmi_filter.description)}`:''}</div>
      <div class="wmi-query">${_escHtml(g.wmi_filter.query||'')}</div>
      <div style="font-size:10px;color:var(--amber);margin-top:4px">Si la GPO ne s'applique pas sur un poste, testez : <code>Get-WmiObject -Query "..."</code></div>
    </div>`:''}`;

  let body='';

  // Findings de cette GPO
  if(g.findings?.length){
    body+=`<div class="section-title" style="color:var(--amber)">⚑ Problèmes détectés dans cette GPO <span class="st-count">${g.findings.length}</span></div>`;
    body+=`<div class="finding-list">`;
    g.findings.forEach(f=>{
      body+=`<div class="finding-card ${f.severity}">
        <div class="fc-head" onclick="togFC(this)">
          <div class="fc-sev ${f.severity}"></div>
          <div class="fc-main">
            <div class="fc-title">${_escHtml(f.title)}</div>
            <div class="fc-meta"><span>${f.category||''}</span></div>
          </div>
          <button class="btn-explain" onclick="event.stopPropagation();explainFinding(this,'${f.rule_id||''}','${(f.title||'').replace(/'/g,"&#39;")}','${(f.remediation||'').replace(/'/g,"&#39;")}')">💬</button>
          <span class="fc-pill ${f.severity}">${f.severity}</span>
          <span class="fc-arrow">▶</span>
        </div>
        <div class="fc-body">
          <div class="fc-detail">${_escHtml(f.detail||'')}</div>
          <div class="fc-reco">✅ ${_escHtml(f.remediation||'')}</div>
          <div class="explain-zone" id="ez-d-${f.rule_id}"></div>
        </div>
      </div>`;
    });
    body+=`</div>`;
  }

  // Liens OU
  if(g.links?.length){
    body+=`<div class="section-title">⊢ Appliquée sur <span class="st-count">${g.links.length} OU</span></div>`;
    body+=`<div style="background:var(--surface);border:1px solid var(--border);border-radius:6px;overflow:hidden;margin-bottom:16px">`;
    g.links.forEach((l,i)=>{
      const parts=(l.ou||'').split(',').filter(p=>p.trim().startsWith('OU=')).map(p=>p.slice(3)).reverse();
      const label=parts.join(' › ')||l.ou||'(racine)';
      body+=`<div class="ou-gpo-row">
        <span class="ou-priority">Priorité ${i+1}</span>
        <span class="ou-name">${_escHtml(label)}</span>
        ${l.enforced?'<span class="badge enforced">ENFORCED</span>':''}
        ${l.disabled?'<span class="badge disabled">lien désactivé</span>':''}
      </div>`;
    });
    body+=`</div>`;
  }

  // Paramètres
  if(g.has_content){
    body+=`<div class="section-title">Paramètres configurés</div>`;
    const secs=_gpoContentIndex[g.guid]||[];
    secs.forEach(sec=>{
      if(!sec.params?.length) return;
      body+=`<div class="param-section">
        <div class="ps-head" onclick="togPS(this)">
          <span class="ps-icon">${sec.icon||'📄'}</span>
          <span class="ps-title">${sec.title}</span>
          <span class="ps-count">${sec.params.length} param.</span>
          <span class="ps-arr">▶</span>
        </div>
        <div class="ps-body">`;
      sec.params.forEach(p=>{
        body+=`<div class="param-row">
          <span class="param-key">${_escHtml(p.label||p.key)}</span>
          <span class="param-val${p.alert?' bad':''}">${_escHtml(String(p.value||''))}</span>
          ${p.hint?`<span class="param-hint">(${_escHtml(p.hint)})</span>`:''}
        </div>`;
      });
      body+=`</div></div>`;
    });
  } else {
    body+=`<div style="color:var(--txt3);padding:20px 0;font-size:13px;text-align:center">Aucun paramètre lu depuis le SYSVOL pour cette GPO.</div>`;
  }

  document.getElementById('gpo-detail-body').innerHTML=body;
}

// ══════════════════════════════════════════════════════════════════════
// EXPLIQUER UN FINDING
// ══════════════════════════════════════════════════════════════════════
function explainFinding(btn,ruleId,title,remediation){
  const fcBody=btn.closest('.fc-head')?.nextElementSibling;
  if(!fcBody?.classList.contains('fc-body')){
    // Ouvrir le fc-body d'abord
    togFC(btn.closest('.fc-head'));
  }
  const zone=fcBody?.querySelector('.explain-zone');
  if(!zone) return;
  if(zone.dataset.loaded==='1'){
    zone.classList.toggle('open');
    return;
  }
  const ex=ATTACK_EXAMPLES[ruleId];
  zone.dataset.loaded='1';
  zone.classList.add('open');
  zone.innerHTML=`
    <div style="font-size:11px;font-weight:600;color:var(--teal);margin-bottom:8px;text-transform:uppercase;letter-spacing:.05em">💬 Contexte d'attaque</div>
    ${ex?`
      <div class="explain-attack">${ex.attack}</div>
      <div class="explain-chips">
        <span class="explain-chip tool">🛠 ${ex.tool}</span>
        <span class="explain-chip impact">💥 ${ex.impact}</span>
      </div>
    `:`<div class="explain-attack" style="color:var(--txt2)">${_escHtml(title)}</div>`}
    <div style="font-size:11px;color:var(--green)">✅ ${_escHtml(remediation)}</div>`;
}

// ══════════════════════════════════════════════════════════════════════
// FILTRES FINDINGS
// ══════════════════════════════════════════════════════════════════════
function filterFindingsSub(q,sev){
  q=q.toLowerCase();
  const listId='fl-'+(sev==='critical'?'critical':'warning');
  document.querySelectorAll(`#${listId} .finding-card`).forEach(c=>{
    const txt=c.dataset.txt||'';
    c.style.display=(!q||txt.includes(q))?'':'none';
  });
}
function filtFByGPO(guid,sev){
  const listId='fl-'+(sev==='critical'?'critical':'warning');
  document.querySelectorAll(`#${listId} .finding-card`).forEach(c=>{
    const guids=(c.dataset.guids||'').split(',');
    c.style.display=(!guid||guids.includes(guid))?'':'none';
  });
}

// ══════════════════════════════════════════════════════════════════════
// INVENTAIRE PAR OU
// ══════════════════════════════════════════════════════════════════════
let _ouFilter='';
function searchOU(q){ _ouFilter=q.toLowerCase(); renderByOU(_ouFilter); }

function _ouDepth(dn){ return(dn.match(/\bOU=/gi)||[]).length; }

function renderByOU(filter){
  // ── Collecter les OU avec leurs GPO ──────────────────────────────────
  const ouMap={};
  _gpos.forEach((g,gi)=>(g.links||[]).forEach(l=>{
    const dn=l.ou||'(racine)';
    if(filter&&!dn.toLowerCase().includes(filter))return;
    const key=dn.toLowerCase();
    if(!ouMap[key])ouMap[key]={dn,gpos:[]};
    ouMap[key].gpos.push({
      name:g.name,guid:g.guid,enforced:l.enforced,disabled:l.disabled,
      score:g.score,flags:g.flags,wmi:!!g.wmi_filter,
      changed:(g.changed||'').slice(0,10),gpoIdx:gi,
    });
  }));

  if(!Object.keys(ouMap).length){
    document.getElementById('byou-content').innerHTML=
      '<div class="empty-state"><div class="es-icon">⊢</div><div class="es-title">Aucune OU trouvée</div></div>';
    return;
  }

  // ── Extraire les segments OU d'un DN (ancêtre → feuille) ─────────────
  // "OU=Laptops,OU=Computers,OU=Corp,DC=corp,DC=local" → ['Corp','Computers','Laptops']
  function ouSegs(dn){
    return dn.split(',')
      .filter(p=>p.trim().toUpperCase().startsWith('OU='))
      .map(p=>p.trim().slice(3))
      .reverse();
  }

  // ── Construire l'arbre ───────────────────────────────────────────────
  const tree={label:'',fullDn:'',children:{},gpos:[]};

  Object.values(ouMap).forEach(({dn,gpos})=>{
    const segs=ouSegs(dn);
    if(!segs.length){ tree.gpos.push(...gpos.map(g=>({...g,ouDn:dn}))); return; }
    let node=tree;
    segs.forEach((seg,i)=>{
      const k=seg.toLowerCase();
      if(!node.children[k]){
        const dcPart=dn.split(',').filter(p=>p.trim().toUpperCase().startsWith('DC=')).join(',');
        const ouPart=segs.slice(0,i+1).reverse().map(s=>`OU=${s}`).join(',');
        node.children[k]={label:seg,fullDn:ouPart+(dcPart?','+dcPart:''),children:{},gpos:[]};
      }
      node=node.children[k];
      if(i===segs.length-1) node.gpos.push(...gpos.map(g=>({...g,ouDn:dn})));
    });
  });

  // ── Trier les GPO par priorité dans chaque nœud ──────────────────────
  function sortGpos(gpos){
    const enf=gpos.filter(g=>g.enforced).sort((a,b)=>b.gpoIdx-a.gpoIdx);
    const norm=gpos.filter(g=>!g.enforced).sort((a,b)=>b.gpoIdx-a.gpoIdx);
    return[...norm,...enf]; // enforced en dernier = priorité la plus haute
  }

  const _sc=s=>s==null?'var(--txt3)':s>=70?'var(--green)':s>=40?'var(--amber)':'var(--red)';
  const LC='var(--border2)'; // couleur des lignes de connexion

  // ── Rendu récursif d'un nœud ─────────────────────────────────────────
  function renderNode(node,depth){
    const children=Object.values(node.children).sort((a,b)=>a.label.localeCompare(b.label));
    const gpos=sortGpos(node.gpos);
    if(!gpos.length&&!children.length) return'';

    const indent=depth*22;
    const enf=gpos.filter(g=>g.enforced).length;
    const uid='ou-'+Math.random().toString(36).slice(2,8);
    let html='';

    if(node.label){
      html+=`<div style="margin-left:${indent}px;margin-bottom:5px;position:relative">
        ${depth>0?`<div style="position:absolute;left:-11px;top:0;bottom:50%;width:11px;border-left:1px solid ${LC};border-bottom:1px solid ${LC};border-bottom-left-radius:3px;pointer-events:none"></div>`:''}
        <div class="ou-card" style="margin-bottom:0">
          <div class="ou-card-head" id="${uid}-h" onclick="document.getElementById('${uid}-b').classList.toggle('open')">
            <span style="color:var(--teal);font-size:12px">${children.length?'▶':'⊢'}</span>
            <div style="flex:1;min-width:0">
              <span style="font-size:13px;font-weight:600;color:var(--txt)">${_escHtml(node.label)}</span>
              <span style="font-size:10px;color:var(--txt3);margin-left:8px;font-family:'JetBrains Mono',monospace">${_escHtml(node.fullDn)}</span>
            </div>
            <span style="font-size:11px;color:var(--txt3);flex-shrink:0;display:flex;gap:8px;align-items:center">
              ${gpos.length?`<span style="color:var(--blue)">${gpos.length} GPO</span>`:''}
              ${children.length?`<span>${children.length} sous-OU</span>`:''}
              ${enf?`<span style="color:var(--red)">${enf} ENFORCED</span>`:''}
            </span>
          </div>
          <div class="ou-card-body" id="${uid}-b">`;

      if(gpos.length){
        html+=`<div style="font-size:10px;color:var(--txt3);padding:5px 14px 6px;background:var(--surface2);border-bottom:1px solid var(--border)">
          Priorité d'application : <strong>P1 = basse</strong> → <strong>P${gpos.length} = haute (gagne les conflits)</strong>
        </div>`;
        gpos.forEach((g,i)=>{
          html+=`<div class="ou-gpo-row" style="cursor:pointer" onclick="openGPODetail('${g.guid}')">
            <span class="ou-priority">P${i+1}${g.enforced?' ⬆':''}</span>
            <span class="ou-gpo-name">${_escHtml(g.name)}</span>
            ${g.score!=null?`<span class="ou-score" style="color:${_sc(g.score)}">${g.score}/100</span>`:''}
            ${g.changed?`<span class="ou-changed">${g.changed}</span>`:''}
            ${g.enforced?'<span class="badge enforced">ENFORCED</span>':''}
            ${g.disabled?'<span class="badge disabled">lien off</span>':''}
            ${parseInt(g.flags||0)===3?'<span class="badge disabled">GPO off</span>':''}
            ${g.wmi?'<span class="badge wmi">WMI</span>':''}
          </div>`;
        });
      }
      html+=`</div></div></div>`;
    }

    // Sous-OUs avec ligne verticale de connexion parent→enfants
    if(children.length){
      html+=`<div style="margin-left:${node.label?indent+22:indent}px;position:relative">`;
      if(node.label){
        html+=`<div style="position:absolute;left:0;top:0;bottom:10px;border-left:1px dashed ${LC};pointer-events:none"></div>`;
      }
      children.forEach(child=>{ html+=renderNode(child,0); });
      html+=`</div>`;
    }
    return html;
  }

  // ── Rendu final ───────────────────────────────────────────────────────
  let html='';

  // GPO liées directement au domaine (pas dans une OU)
  if(tree.gpos.length){
    const gpos=sortGpos(tree.gpos);
    html+=`<div class="ou-card" style="margin-bottom:10px;border-left:2px solid var(--blue)">
      <div class="ou-card-head" onclick="this.nextElementSibling.classList.toggle('open')">
        <span style="font-size:14px">🌐</span>
        <div style="flex:1"><span style="font-size:13px;font-weight:600">Domaine (racine)</span>
          <span style="font-size:11px;color:var(--txt3);margin-left:8px">Ces GPO s'appliquent sur tout le domaine — priorité la plus basse</span></div>
        <span style="font-size:11px;color:var(--txt3)">${gpos.length} GPO ▶</span>
      </div>
      <div class="ou-card-body">
        <div style="font-size:10px;color:var(--txt3);padding:5px 14px 6px;background:var(--surface2);border-bottom:1px solid var(--border)">
          Priorité P1 (basse) → P${gpos.length} (haute)
        </div>
        ${gpos.map((g,i)=>`
        <div class="ou-gpo-row" style="cursor:pointer" onclick="openGPODetail('${g.guid}')">
          <span class="ou-priority">P${i+1}</span>
          <span class="ou-gpo-name">${_escHtml(g.name)}</span>
          ${g.score!=null?`<span class="ou-score" style="color:${_sc(g.score)}">${g.score}/100</span>`:''}
          ${g.changed?`<span class="ou-changed">${g.changed}</span>`:''}
          ${g.enforced?'<span class="badge enforced">ENFORCED</span>':''}
        </div>`).join('')}
      </div>
    </div>`;
  }

  // Nœuds racine de l'arbre (triés alphabétiquement)
  Object.values(tree.children).sort((a,b)=>a.label.localeCompare(b.label))
    .forEach(child=>{ html+=renderNode(child,0); });

  document.getElementById('byou-content').innerHTML=
    html||'<div class="empty-state"><div class="es-icon">⊢</div><div class="es-title">Aucune OU trouvée</div></div>';
}

// ══════════════════════════════════════════════════════════════════════
// INVENTAIRE PAR TYPE
// ══════════════════════════════════════════════════════════════════════
function renderByType(){
  const counts={};
  _gpos.forEach(g=>(_gpoContentIndex[g.guid]||[]).forEach(s=>{
    const k=s.title.split('—')[0].trim();
    if(!counts[k])counts[k]={icon:s.icon,count:0};
    counts[k].count++;
  }));
  const sorted=Object.entries(counts).sort((a,b)=>b[1].count-a[1].count);
  const max=sorted[0]?.[1].count||1;

  const gridEl=document.getElementById('type-grid-area');
  if(!gridEl)return;
  gridEl.innerHTML=`<div class="type-grid">${sorted.map(([k,v])=>`
    <div class="type-card" onclick="showTypeDetail('${_escHtml(k)}')">
      <div class="tc-icon">${v.icon||'📄'}</div>
      <div class="tc-name">${k.charAt(0).toUpperCase()+k.slice(1)}</div>
      <div class="tc-count">${v.count} GPO</div>
      <div class="tc-bar"><div class="tc-fill" style="width:${Math.round(v.count/max*100)}%"></div></div>
    </div>`).join('')}</div>`;
}

function showTypeDetail(type){
  const detail=document.getElementById('type-detail-area');
  if(!detail)return;
  const matching=_gpos.filter(g=>(_gpoContentIndex[g.guid]||[]).some(s=>s.title.split('—')[0].trim()===type));
  detail.innerHTML=`
    <div class="section-title">${type} <span class="st-count">${matching.length} GPO</span></div>
    <div class="gpo-grid">${matching.map(g=>`
      <div class="gpo-card" onclick="openGPODetail('${g.guid}')">
        <div class="gpo-card-head">
          <span class="gpo-name">${_escHtml(g.name)}</span>
          ${g.score!=null?`<span class="badge ${g.score>=70?'score-good':g.score>=40?'score-mid':'score-bad'}">${g.score}/100</span>`:''}
        </div>
      </div>`).join('')}</div>`;
  detail.scrollIntoView({behavior:'smooth'});
}

// ══════════════════════════════════════════════════════════════════════
// TIMELINE
// ══════════════════════════════════════════════════════════════════════
let _tlDays='all';
function filterTimeline(days,btn){
  _tlDays=days;
  document.querySelectorAll('#sub-diag-timeline .filter-btn').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on');
  renderTimeline();
}

function renderTimeline(){
  const now=new Date();
  const cutoff=_tlDays==='all'?null:new Date(now-_tlDays*86400000);
  const _parseDate=raw=>{
    if(!raw)return null;
    try{
      if(/^\d{14}/.test(raw))return new Date(`${raw.slice(0,4)}-${raw.slice(4,6)}-${raw.slice(6,8)}`);
      return new Date(raw.slice(0,10));
    }catch{return null;}
  };
  const withDate=_gpos.map(g=>({...g,_date:_parseDate(g.changed||g.created)}))
    .filter(g=>g._date&&!isNaN(g._date)&&(!cutoff||g._date>=cutoff));
  withDate.sort((a,b)=>b._date-a._date);

  const el=document.getElementById('timeline-content');
  if(!el)return;
  if(!withDate.length){
    el.innerHTML='<div class="empty-state"><div class="es-icon">⏱</div><div class="es-title">Aucune GPO avec date de modification dans cette période</div></div>';
    return;
  }
  const byMonth={};
  withDate.forEach(g=>{
    const k=g._date.toLocaleDateString('fr-FR',{year:'numeric',month:'long'});
    if(!byMonth[k])byMonth[k]=[];
    byMonth[k].push(g);
  });
  const _sc=s=>s==null?'var(--txt3)':s>=70?'var(--green)':s>=40?'var(--amber)':'var(--red)';
  el.innerHTML=Object.entries(byMonth).map(([month,gpos])=>`
    <div class="tl-month">
      <div class="tl-month-label">${month} <span style="font-weight:400">— ${gpos.length} GPO</span></div>
      ${gpos.map(g=>{
        const ouStr=(g.links||[]).slice(0,2).map(l=>{
          const parts=(l.ou||'').split(',').filter(p=>p.startsWith('OU=')).map(p=>p.slice(3)).reverse();
          return parts.join(' › ')||l.ou||'(racine)';
        }).join(', ')+(g.links?.length>2?` +${g.links.length-2}`:'');
        const critCount=(g.findings||[]).filter(f=>f.severity==='critical').length;
        return`<div class="tl-item" onclick="openGPODetail('${g.guid}')">
          <div class="tl-date">
            <div class="day">${g._date.toLocaleDateString('fr-FR',{day:'2-digit',month:'2-digit'})}</div>
            <div class="yr">${g._date.getFullYear()}</div>
          </div>
          <div class="tl-info">
            <div class="tl-name">${_escHtml(g.name)}</div>
            <div class="tl-ous">${ouStr||'Non liée'}</div>
          </div>
          <div class="tl-badges">
            ${g.score!=null?`<span class="badge" style="color:${_sc(g.score)}">${g.score}/100</span>`:''}
            ${critCount>0?`<span class="badge score-bad">${critCount} critique${critCount>1?'s':''}</span>`:''}
            ${g.wmi_filter?'<span class="badge wmi">WMI</span>':''}
          </div>
        </div>`;
      }).join('')}
    </div>`).join('');
}

// ══════════════════════════════════════════════════════════════════════
// CONFLITS
// ══════════════════════════════════════════════════════════════════════
function filtConflicts(mode,btn){
  document.querySelectorAll('#sub-security-conflicts .filter-btn').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on');
  document.querySelectorAll('.conflict-card').forEach(c=>{
    const isSec=c.dataset.sec==='true';
    c.style.display=(mode==='all'||(mode==='high'&&isSec)||(mode==='low'&&!isSec))?'':'none';
  });
}
function searchConflicts(q){
  q=q.toLowerCase();
  document.querySelectorAll('.conflict-card[data-txt]').forEach(c=>{
    c.style.display=(!q||c.dataset.txt.includes(q))?'':'none';
  });
}

// ══════════════════════════════════════════════════════════════════════
// EXPORT
// ══════════════════════════════════════════════════════════════════════
function exportFindings(fmt){
  if(!_findingsData?.length){alert('Aucun finding à exporter.');return;}
  let content,mime,filename;
  if(fmt==='csv'){
    const h='ID,Sévérité,Catégorie,Titre,Référence,Remédiation';
    const rows=_findingsData.map(f=>[f.rule_id||'',f.severity||'',f.category||'',
      `"${(f.title||'').replace(/"/g,'""')}"`,`"${(f.ref||'').replace(/"/g,'""')}"`,
      `"${(f.remediation||'').replace(/"/g,'""')}"`].join(','));
    content=[h,...rows].join('\n');mime='text/csv;charset=utf-8';filename='gpoctopus_findings.csv';
  } else {
    const lines=['# GPOctopus — Findings de sécurité',`> ${new Date().toLocaleDateString('fr-FR')} · ${_findingsData.length} constatations`,''];
    const sevOrd={critical:0,warning:1,info:2};
    const sorted=[..._findingsData].sort((a,b)=>(sevOrd[a.severity]??9)-(sevOrd[b.severity]??9));
    const bySev={};sorted.forEach(f=>{if(!bySev[f.severity])bySev[f.severity]=[];bySev[f.severity].push(f);});
    const sevL={critical:'🔴 Critiques',warning:'🟡 Alertes',info:'🔵 Infos'};
    Object.entries(bySev).forEach(([sev,flist])=>{
      lines.push(`## ${sevL[sev]||sev} (${flist.length})`);
      flist.forEach(f=>{
        lines.push(`\n### ${f.title}`);
        lines.push(`- **ID** : ${f.rule_id||'—'} · **Réf** : ${f.ref||'—'}`);
        if(f.detail)lines.push(`- **Détail** : ${f.detail}`);
        lines.push(`- **Remédiation** : ${f.remediation||'—'}`);
        if(f.source_gpos?.length)lines.push(`- **GPO** : ${f.source_gpos.map(g=>g.name).join(', ')}`);
      });lines.push('');
    });
    content=lines.join('\n');mime='text/markdown;charset=utf-8';filename='gpoctopus_findings.md';
  }
  const blob=new Blob(['\uFEFF'+content],{type:mime});
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a');a.href=url;a.download=filename;a.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}

// ══════════════════════════════════════════════════════════════════════
// UTILITAIRES
// ══════════════════════════════════════════════════════════════════════
function togFC(hdr){
  const b=hdr.nextElementSibling;
  if(b)b.classList.toggle('open');
  const a=hdr.querySelector('.fc-arrow');
  if(a)a.classList.toggle('open');
}
function togPS(hdr){
  const b=hdr.nextElementSibling;
  if(b)b.classList.toggle('open');
  const a=hdr.querySelector('.ps-arr');
  if(a)a.classList.toggle('open');
}
function togCC(hdr){
  const b=hdr.nextElementSibling;
  if(b)b.classList.toggle('open');
  const a=hdr.querySelector('.cc-arr');
  if(a)a.style.transform=b.classList.contains('open')?'rotate(90deg)':'';
}

function _escHtml(s){
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function _highlight(text,tokens){
  if(!text)return'';
  let s=_escHtml(String(text));
  tokens.forEach(t=>{
    if(!t)return;
    const re=new RegExp(`(${t.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')})`, 'gi');
    s=s.replace(re,'<mark>$1</mark>');
  });
  return s;
}
</script>
</body>
</html>
"""


def _make_json_safe(obj):
    """Rend un objet sérialisable en JSON — convertit les types inconnus en str."""
    if isinstance(obj, dict):
        return {k: _make_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_make_json_safe(i) for i in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)

def generate_html_report(data: dict, output_path: str):
    try:
        safe_data = _make_json_safe(data)
        tpl = Template(HTML_TEMPLATE)
        html = tpl.render(data=safe_data)
    except Exception as e:
        print(f"[!] Erreur rendu HTML : {e}")
        raise
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)
    except OSError as e:
        print(f"[!] Impossible d'écrire {output_path} : {e}")
        raise
    print(f"[+] Rapport généré : {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description='GPOctopus Audit — Analyse GPO Active Directory',
        epilog="""
Exemples :
  python3 gpoctopus.py --demo -o rapport.html
  python3 gpoctopus.py --dc 192.168.1.10 --domain corp.local --user audit --password 'P@ss!' -o rapport.html
  sudo mount -t cifs //DC01/SYSVOL /mnt/sysvol -o user=admin,domain=CORP,vers=3.0
  python3 gpoctopus.py --dc DC01 --domain corp.local --user admin --password 'P@ss!' --sysvol /mnt/sysvol -o rapport.html
        """
    )
    parser.add_argument('--dc',       help='IP ou FQDN du DC')
    parser.add_argument('--domain',   help='Domaine (ex: corp.local)')
    parser.add_argument('--user',     help='Utilisateur AD')
    parser.add_argument('--password', help='Mot de passe')
    parser.add_argument('--ssl',      action='store_true', help='LDAPS port 636')
    parser.add_argument('--sysvol',   help='Chemin local du SYSVOL monté')
    parser.add_argument('--demo',     action='store_true', help='Mode démo sans AD')
    parser.add_argument('-o', '--output', default='rapport_gpo.html', help='Fichier de sortie')
    parser.add_argument('--json',     action='store_true', help='Export JSON')
    args = parser.parse_args()

    print("=" * 60)
    print("  GPOctopus Audit — CIS · ANSSI · MS Baseline")
    print("=" * 60)

    if args.demo:
        print("[*] Mode démo")
        gpos = generate_demo_data()
    elif args.dc and args.domain and args.user and args.password:
        c = GPOCollector(args.dc, args.domain, args.user, args.password,
                         args.ssl, args.sysvol)
        gpos = c.collect_all()
        if gpos is None:
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)

    print("[*] Analyse RSOP…")
    report = analyze_gpos(gpos)
    print(f"[+] Score global : {report['global_score']}/100")
    print(f"[+] Critiques={report['criticals']}  Warnings={report['warnings']}  Conformes={report['compliant_count']}")

    if args.json:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2, default=str)
    else:
        generate_html_report(report, args.output)
    print("[+] Terminé.")


# ─── Wizard ───────────────────────────────────────────────────────────────────
import getpass
import configparser


CONFIG_FILE = Path(__file__).parent / "gpoctopus.conf"

# ─── Couleurs terminal ────────────────────────────────────────────────────────

class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"

def ok(msg):    print(f"  {C.GREEN}✔{C.RESET}  {msg}")
def err(msg):   print(f"  {C.RED}✘{C.RESET}  {C.RED}{msg}{C.RESET}")
def warn(msg):  print(f"  {C.YELLOW}⚠{C.RESET}  {C.YELLOW}{msg}{C.RESET}")
def info(msg):  print(f"  {C.BLUE}ℹ{C.RESET}  {C.DIM}{msg}{C.RESET}")
def step(msg):  print(f"\n{C.BOLD}{C.WHITE}{msg}{C.RESET}")
def sep():      print(f"  {C.DIM}{'─' * 52}{C.RESET}")

def ask(prompt, default=None, secret=False):
    """Pose une question, retourne la réponse. Supporte valeur par défaut."""
    if default:
        display = f"{C.CYAN}{prompt}{C.RESET} {C.DIM}[{default}]{C.RESET} : "
    else:
        display = f"{C.CYAN}{prompt}{C.RESET} : "

    try:
        if secret:
            val = getpass.getpass(display)
        else:
            val = input(display).strip()
    except (KeyboardInterrupt, EOFError):
        print()
        raise

    return val if val else (default or "")

def ask_yn(prompt, default="o"):
    """Question oui/non."""
    opts = "O/n" if default == "o" else "o/N"
    display = f"{C.CYAN}{prompt}{C.RESET} {C.DIM}[{opts}]{C.RESET} : "
    try:
        val = input(display).strip().lower()
    except (KeyboardInterrupt, EOFError):
        print()
        raise
    if not val:
        return default == "o"
    return val in ("o", "oui", "y", "yes")

# ─── Chargement / sauvegarde config ──────────────────────────────────────────

def load_config():
    cfg = {}
    if CONFIG_FILE.exists():
        parser = configparser.ConfigParser()
        parser.read(CONFIG_FILE)
        if "ad" in parser:
            cfg = dict(parser["ad"])
    return cfg

def save_config(cfg):
    parser = configparser.ConfigParser()
    parser["ad"] = {k: v for k, v in cfg.items() if k != "password"}
    with open(CONFIG_FILE, "w") as f:
        parser.write(f)
    CONFIG_FILE.chmod(0o600)

# ─── Tests de connectivité ────────────────────────────────────────────────────

def check_port(host, port, timeout=3):
    import socket
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        return True
    except Exception:
        return False

def check_ldap(dc, domain, user, password):
    try:
        from ldap3 import Server, Connection, NTLM, ALL
        server = Server(dc, get_info=ALL)
        conn = Connection(server, user=f"{domain}\\{user}",
                          password=password, authentication=NTLM)
        result = conn.bind()
        if result:
            conn.unbind()
        return result, None
    except Exception as e:
        return False, str(e)

def mount_sysvol(dc, domain, user, password, mount_point="/mnt/sysvol"):
    """Monte le SYSVOL. Essaie plusieurs chemins UNC et versions SMB."""
    try:
        result = subprocess.run(["mountpoint", "-q", mount_point])
        if result.returncode == 0:
            return True, "deja monte"
    except FileNotFoundError:
        pass

    os.makedirs(mount_point, exist_ok=True)

    # Certains AD exposent \\domaine\SYSVOL, d'autres \\IP\SYSVOL
    unc_candidates = list(dict.fromkeys([
        f"//{domain}/SYSVOL",
        f"//{dc}/SYSVOL",
        f"//{domain}/sysvol",
        f"//{dc}/sysvol",
    ]))

    # Trouver le binaire mount.cifs (peut ne pas être dans le PATH)
    cifs_bin = next(
        (p for p in ["/usr/sbin/mount.cifs", "/sbin/mount.cifs", "mount.cifs"]
         if subprocess.run(["test", "-x", p] if "/" in p else ["which", p],
                           capture_output=True).returncode == 0),
        "/usr/sbin/mount.cifs"  # fallback
    )

    errors = []
    for unc in unc_candidates:
        for vers in ["3.0", "2.1", "2.0"]:
            # Utiliser le binaire directement ET via sudo mount -t cifs
            for cmd in [
                # Méthode 1 : mount.cifs direct
                ["sudo", cifs_bin, unc, mount_point,
                 "-o", f"user={user},password={password},domain={domain},"
                       f"vers={vers},sec=ntlmssp"],
                # Méthode 2 : mount -t cifs (utilise PATH système)
                ["sudo", "mount", "-t", "cifs", unc, mount_point,
                 "-o", f"user={user},password={password},domain={domain},"
                       f"vers={vers},sec=ntlmssp"],
            ]:
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    return True, f"monté {unc} (SMB {vers})"
                err = result.stderr.strip() or result.stdout.strip()
                errors.append(f"{unc} SMB{vers}: {err}")
                subprocess.run(["sudo", "umount", "-l", mount_point], capture_output=True)

    return False, "\n".join(errors[-8:])  # Garder les 8 dernières erreurs

def unmount_sysvol(mount_point="/mnt/sysvol"):
    subprocess.run(["sudo", "umount", mount_point],
                   capture_output=True)

# ─── Affichage du résultat ────────────────────────────────────────────────────

def show_result(report_path):
    """Affiche un résumé du rapport après génération."""
    # Lire le rapport JSON si disponible
    json_path = report_path.replace(".html", ".json")
    if os.path.exists(json_path):
        with open(json_path) as f:
            data = json.load(f)
        sep()
        print(f"\n  {C.BOLD}Résumé de l'audit{C.RESET}")
        sep()
        score = data.get("global_score", "?")
        color = C.GREEN if score >= 70 else C.YELLOW if score >= 40 else C.RED
        print(f"  Score global   : {color}{C.BOLD}{score}/100{C.RESET}")
        print(f"  Critiques      : {C.RED}{data.get('criticals', 0)}{C.RESET}")
        print(f"  Avertissements : {C.YELLOW}{data.get('warnings', 0)}{C.RESET}")
        print(f"  Conformes      : {C.GREEN}{data.get('compliant_count', 0)}{C.RESET}")
        print(f"  GPO orphelines : {data.get('orphan_count', 0)}")

def open_report(report_path):
    """Tente d'ouvrir le rapport dans un navigateur."""
    abs_path = os.path.abspath(report_path)
    for cmd in [["xdg-open"], ["firefox"], ["chromium"], ["google-chrome"]]:
        try:
            subprocess.Popen(cmd + [abs_path],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
            return True
        except FileNotFoundError:
            continue
    return False

# ─── Wizard principal ─────────────────────────────────────────────────────────

def run_wizard():
    os.system("clear")
    print(f"""
{C.BOLD}{C.WHITE}  ╔══════════════════════════════════════════════════════╗
  ║          GPOctopus Audit — Wizard               ║
  ║     CIS Benchmarks · ANSSI · MS Baseline 2022      ║
  ╚══════════════════════════════════════════════════════╝{C.RESET}
""")

    saved = load_config()
    if saved:
        info(f"Configuration précédente trouvée : {saved.get('dc', '')} / {saved.get('domain', '')}")
        use_saved = ask_yn("  Utiliser ces paramètres ?", default="o")
        if not use_saved:
            saved = {}

    # ── Mode démo ──
    print()
    demo = ask_yn("  Lancer en mode démo (sans connexion AD) ?", default="n")
    if demo:
        step("► Mode démo")
        output = ask("  Nom du fichier de sortie", default="rapport_gpo.html")
        _run_auditor([], output, demo=True)
        return

    # ── Paramètres AD ──
    step("► Paramètres Active Directory")
    sep()

    dc      = ask("  DC (IP ou FQDN)", default=saved.get("dc", ""))
    domain  = ask("  Domaine", default=saved.get("domain", ""))
    user    = ask("  Utilisateur", default=saved.get("user", ""))
    password = ask("  Mot de passe", secret=True)

    if not all([dc, domain, user, password]):
        err("Tous les champs sont requis.")
        sys.exit(1)

    # ── Tests de connectivité ──
    step("► Vérification de la connectivité")
    sep()

    print(f"  Test port 389 (LDAP)... ", end="", flush=True)
    if check_port(dc, 389):
        ok("ouvert")
        use_ssl = False
    else:
        print()
        warn("Port 389 fermé, test port 636 (LDAPS)...")
        if check_port(dc, 636):
            ok("port 636 ouvert — utilisation de LDAPS")
            use_ssl = True
        else:
            err(f"Impossible de joindre {dc} sur les ports 389/636")
            err("Vérifiez l'IP du DC et les règles de pare-feu.")
            sys.exit(1)

    print(f"  Test authentification LDAP... ", end="", flush=True)
    ldap_ok, ldap_err = check_ldap(dc, domain, user, password)
    if ldap_ok:
        ok("authentification réussie")
    else:
        print()
        err("Authentification LDAP échouée")
        _explain_ldap_error(ldap_err)
        sys.exit(1)

    # ── SYSVOL ──
    step("► Montage SYSVOL")
    sep()

    mount_point = "/mnt/sysvol"
    info("Le SYSVOL est nécessaire pour lire les fichiers Registry.pol")
    do_mount = ask_yn("  Monter le SYSVOL automatiquement ?", default="o")

    sysvol_path = None
    if do_mount:
        # Vérifier cifs-utils
        # Chercher mount.cifs dans les chemins standards (absent du PATH de root parfois)
        MOUNT_CIFS_PATHS = [
            "mount.cifs",
            "/usr/sbin/mount.cifs",
            "/sbin/mount.cifs",
            "/usr/local/sbin/mount.cifs",
        ]
        cifs_bin = None
        for p in MOUNT_CIFS_PATHS:
            if subprocess.run(["which", p] if "/" not in p else ["test", "-x", p],
                               capture_output=True).returncode == 0:
                cifs_bin = p
                break
        cifs_ok = cifs_bin is not None
        if not cifs_ok:
            # Si cifs-utils est installé mais non configuré (status iU dans dpkg)
            dpkg_status = subprocess.run(
                ["dpkg", "-l", "cifs-utils"], capture_output=True, text=True
            ).stdout
            if "iU" in dpkg_status or "iF" in dpkg_status:
                warn("cifs-utils installé mais non configuré — configuration en cours...")
                subprocess.run(["sudo", "dpkg", "--configure", "cifs-utils"],
                               capture_output=True)
                # Re-vérifier
                for p in ["/usr/sbin/mount.cifs", "/sbin/mount.cifs"]:
                    if subprocess.run(["test", "-x", p], capture_output=True).returncode == 0:
                        cifs_bin = p
                        cifs_ok = True
                        ok(f"mount.cifs trouvé : {p}")
                        break
            if not cifs_ok:
                warn("cifs-utils non installé — tentative d'installation...")
            # Essayer apt puis yum/dnf
            for install_cmd in [
                ["sudo", "apt", "install", "-y", "cifs-utils"],
                ["sudo", "apt-get", "install", "-y", "cifs-utils"],
                ["sudo", "dnf", "install", "-y", "cifs-utils"],
                ["sudo", "yum", "install", "-y", "cifs-utils"],
            ]:
                r = subprocess.run(install_cmd, capture_output=True, text=True)
                if r.returncode == 0:
                    cifs_ok = True
                    ok("cifs-utils installé")
                    break
            if not cifs_ok:
                warn("Installation automatique impossible.")
                info("Installez manuellement : sudo apt install cifs-utils")
                info("ou depuis un paquet .deb : dpkg -i cifs-utils_*.deb")
                info("L'audit continuera sans SYSVOL (contrôles registre limités)")

        if cifs_ok:
            print(f"  Montage du SYSVOL (essai //{domain}/SYSVOL puis //{dc}/SYSVOL)... ", end="", flush=True)
            mount_ok, mount_msg = mount_sysvol(dc, domain, user, password, mount_point)
            if mount_ok:
                ok(mount_msg)
                sysvol_path = mount_point
            else:
                print()
                err("Échec du montage SYSVOL")
                _explain_mount_error(mount_msg)
                warn("L'audit continuera sans lecture des Registry.pol")
                warn("(certains contrôles registre ne seront pas évalués)")
    else:
        existing = ask("  Chemin local du SYSVOL (vide pour ignorer)",
                       default=saved.get("sysvol", ""))
        if existing and os.path.isdir(existing):
            ok(f"SYSVOL trouvé : {existing}")
            sysvol_path = existing
        elif existing:
            warn(f"Chemin introuvable : {existing} — analyse sans SYSVOL")

    # ── Fichier de sortie ──
    step("► Rapport")
    sep()

    output = ask("  Nom du fichier de sortie", default="rapport_gpo.html")
    if not output.endswith(".html"):
        output += ".html"

    # ── Sauvegarde config ──
    save_config({"dc": dc, "domain": domain, "user": user,
                 "sysvol": sysvol_path or ""})
    info("Paramètres sauvegardés pour la prochaine fois")

    # ── Lancement ──
    step("► Audit en cours...")
    sep()

    extra_args = []
    if use_ssl:
        extra_args.append("--ssl")
    if sysvol_path:
        extra_args += ["--sysvol", sysvol_path]

    success = _run_auditor(
        ["--dc", dc, "--domain", domain, "--user", user, "--password", password]
        + extra_args,
        output,
        demo=False
    )

    # ── Démontage SYSVOL ──
    if do_mount and sysvol_path:
        unmount_sysvol(mount_point)
        info("SYSVOL démonté")

    # ── Résultat ──
    if success:
        step("► Terminé")
        sep()
        show_result(output)
        sep()
        ok(f"Rapport généré : {C.BOLD}{os.path.abspath(output)}{C.RESET}")
        print()
        if ask_yn("  Ouvrir le rapport dans le navigateur ?", default="o"):
            if not open_report(output):
                info(f"Ouvrez manuellement : xdg-open {os.path.abspath(output)}")
    print()

# ─── Helpers ─────────────────────────────────────────────────────────────────

def _run_auditor(extra_args, output, demo=False):
    """Lance l'audit en appelant main() directement dans le même processus."""
    argv_backup = sys.argv[:]
    sys.argv = [sys.argv[0]]
    if demo:
        sys.argv += ["--demo"]
    sys.argv += extra_args + ["-o", output]

    import io, contextlib, traceback as _tb
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            main()
        output_txt = buf.getvalue()
        for line in output_txt.splitlines():
            if line.startswith("[+]"):
                ok(line[4:])
            elif line.startswith("[!]"):
                warn(line[4:])
            elif line.startswith("[*]"):
                info(line[4:])
            elif line.strip():
                info(line)
        return True
    except SystemExit as e:
        output_txt = buf.getvalue()
        if e.code not in (0, None):
            err("Le script a rencontré une erreur.")
            print(output_txt[-800:] if output_txt else "")
            _explain_script_error(output_txt)
            return False
        # SystemExit(0) = fin normale
        for line in output_txt.splitlines():
            if line.startswith("[+]"): ok(line[4:])
            elif line.startswith("[!]"): warn(line[4:])
            elif line.startswith("[*]"): info(line[4:])
        return True
    except KeyboardInterrupt:
        print()
        warn("Audit interrompu par l'utilisateur.")
        return False
    except Exception as e:
        err(f"Erreur inattendue : {type(e).__name__}: {e}")
        print(f"\n{C.RED}{_tb.format_exc()}{C.RESET}")
        _explain_script_error(str(e))
        return False
    finally:
        sys.argv = argv_backup

def _explain_ldap_error(error_str):
    """Traduit les erreurs LDAP en messages compréhensibles."""
    if not error_str:
        return
    e = error_str.lower()
    sep()
    if "connection refused" in e or "timed out" in e:
        info("→ Le DC n'est pas joignable. Vérifiez l'IP et les pare-feux.")
    elif "invalid credentials" in e or "49" in e:
        info("→ Identifiants incorrects. Vérifiez le nom de domaine (CORP pas corp.local)")
        info("  et que le compte n'est pas verrouillé.")
    elif "socket" in e or "name or service" in e:
        info("→ Le nom d'hôte ne se résout pas. Essayez l'adresse IP directement.")
    elif "ntlm" in e or "authentication" in e:
        info("→ Authentification NTLM rejetée. Le DC exige peut-être Kerberos.")
        info("  Essayez avec l'IP plutôt que le FQDN.")
    else:
        info(f"→ Détail technique : {error_str}")

def _explain_mount_error(error_str):
    """Traduit les erreurs de montage CIFS."""
    if not error_str:
        return
    e = error_str.lower()
    sep()
    if "permission denied" in e or "access denied" in e:
        info("→ Le compte n'a pas les droits sur le partage SYSVOL.")
        info("  Vérifiez que le compte est bien membre de Domain Users.")
    elif "no such file" in e or "not found" in e:
        info("→ Le partage SYSVOL n'est pas trouvé sur ce DC.")
        info("  Vérifiez que c'est bien un DC et non un simple serveur.")
    elif "connection refused" in e or "timed out" in e:
        info("→ Port 445 (SMB) inaccessible. Règle de pare-feu à vérifier.")
    elif "wrong fs type" in e or "cifs" in e:
        info("→ cifs-utils n'est pas installé correctement.")
        info("  Essayez : sudo apt install --reinstall cifs-utils")
    elif "invalid argument" in e:
        info("→ Essayez d'ajouter l'option ,uid=1000 au montage.")
    else:
        info(f"→ Détail : {error_str[:200]}")

def _explain_script_error(error_str):
    """Traduit les erreurs du script principal."""
    if not error_str:
        return
    e = error_str.lower()
    sep()
    if "import" in e or "modulenotfounderror" in e:
        info("→ Une dépendance Python est manquante.")
        info("  Lancez : pip3 install ldap3 jinja2 --break-system-packages")
    elif "permission" in e:
        info("→ Problème de droits. Vérifiez les permissions du dossier de sortie.")
    elif "connection" in e:
        info("→ La connexion AD a été perdue en cours d'audit.")
        info("  Relancez — cela arrive parfois sur les gros domaines.")
    else:
        info("→ Copiez l'erreur ci-dessus et collez-la dans le chat pour de l'aide.")

# ─── Entry point ─────────────────────────────────────────────────────────────

# ─── Entry point ──────────────────────────────────────────────────────────────


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Wizard si aucun argument CLI n'est passé ET qu'on est dans un terminal interactif
    # Sinon : mode script direct (arguments CLI)
    no_args = len(sys.argv) == 1
    is_tty  = sys.stdin.isatty()

    if no_args and is_tty:
        try:
            run_wizard()
        except KeyboardInterrupt:
            print("\n\n  Annulé.\n")
            sys.exit(0)
    else:
        main()
