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
        "check_key": "auditlogonEvents",       # nom exact dans GptTmpl.inf
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
]

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
        "bad_val": "4,0",
        "remediation": "RunAsPPL = 1. Protège lsass.exe comme processus protégé — Mimikatz ne peut plus lire les credentials en mémoire même avec les droits admin locaux. Requis : Secure Boot activé.",
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
    """Parse GptTmpl.inf → dict {section: {clé_lowercase: valeur}}"""
    result = {}
    content = content.replace('\r\n', '\n').replace('\r', '\n')
    if content.startswith('\ufeff'):
        content = content[1:]

    section_map = {
        "system access":    "system_access",
        "password policy":  "password_policy",
        "event audit":      "event_audit",
        "registry values":  "registry_values",
        "kerberos policy":  "kerberos_policy",
        "privilege rights": "privilege_rights",
    }
    current = None

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(';'):
            continue
        if line.startswith('[') and line.endswith(']'):
            sec = line[1:-1].lower()
            current = section_map.get(sec, sec)
            if current not in result:
                result[current] = {}
            continue
        if '=' in line and current is not None:
            key, _, val = line.partition('=')
            # Clé en minuscule, sans espaces
            result[current][key.strip().lower()] = val.strip().strip('"')

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

    return index


def build_rsop(gpos: list) -> tuple[dict, list]:
    """
    Construit le RSOP (Resultant Set of Policy) en agrégeant toutes les GPO.
    GPO priorité = ordre dans la liste (dernier = priorité la plus haute).
    Retourne (rsop_settings dict, rsop_registry list).
    """
    rsop_settings = {}
    rsop_registry = {}       # Registry.pol : (key_lower, vname_lower) -> int/str
    rsop_registry_xml = {}   # Registry.xml : (hive\key_lower, name_lower) -> int/str

    for gpo in gpos:
        # Ignorer les GPO désactivées ou orphelines
        if gpo.get('flags') == '3':  # All settings disabled
            continue

        # Fusionner les settings (dernier gagne = priorité la plus haute)
        for section, params in gpo.get('settings', {}).items():
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
                        'versionNumber', 'flags', 'whenCreated', 'whenChanged'],
        )
        gpos = []
        for entry in self.conn.entries:
            guid = str(entry.cn) if entry.cn else ''
            sysvol = str(entry.gPCFileSysPath) if entry.gPCFileSysPath else ''
            if not guid:
                continue  # GPO sans GUID — corrompue ou inaccessible
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
            })
        print(f"[+] {len(gpos)} GPO trouvées")
        return gpos

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
                },
                'system_access': {
                    'lockoutbadcount': '0',
                    'lockoutduration': '30',
                    'nolmhash': '0',
                    'lmcompatibilitylevel': '1',
                    'restrictanonymous': '0',
                    'enableguestaccount': '0',
                },
                'event_audit': {
                    'auditlogonevents': '0',
                    'auditaccountmanage': '0',
                    'auditpolicychange': '0',
                },
            },
            'registry_entries': [
                (r'hklm\system\currentcontrolset\control\securityproviders\wdigest',
                 'uselogoncredential', 4, 1),
                (r'hklm\system\currentcontrolset\services\lanmanserver\parameters',
                 'smb1', 4, 1),
            ],
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
                },
                'system_access': {
                    'nolmhash': '1',
                    'lmcompatibilitylevel': '5',
                    'enableguestaccount': '0',
                    'lockoutbadcount': '5',
                    'lockoutduration': '30',
                    'restrictanonymous': '1',
                },
                'event_audit': {
                    'auditlogonevents': '3',
                    'auditaccountmanage': '3',
                    'auditpolicychange': '3',
                },
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
            },
            'scheduled_tasks': [
                {'name': 'Sauvegarde profil', 'cmd': 'robocopy.exe',
                 'args': r'%USERPROFILE% \\backup01\profiles', 'user': 'SYSTEM', 'action': 'C'},
            ],
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
        },
        {
            'name': 'GPO_Chiffrement_BitLocker',
            'guid': '{C23D5E6F-AAAA-BBBB-CCCC-DDDDEEEEFFFF}',
            'sysvol_path': '', 'version': '8', 'flags': '0',
            'created': '2023-01-10', 'changed': '2024-08-20',
            'links': [{'ou': 'OU=Computers,DC=corp,DC=local', 'flags': 2, 'enforced': True, 'disabled': False}],
            'settings': {'password_policy': {}, 'system_access': {}, 'event_audit': {}},
            'registry_entries': [],
        },
        {
            'name': 'GPO_Legacy_XP_Obsolete',
            'guid': '{D34E6F70-1111-2222-3333-444455556666}',
            'sysvol_path': '', 'version': '1', 'flags': '0',
            'created': '2008-05-12', 'changed': '2010-02-01',
            'links': [],  # Orpheline
            'settings': {'password_policy': {}, 'system_access': {}, 'event_audit': {}},
            'registry_entries': [],
        },
        # ── GPO générant des conflits démontrables ──
        {
            'name': 'GPO_Audit_Serveurs',
            'guid': '{E45F7G81-2222-3333-4444-555566667777}',
            'sysvol_path': '', 'version': '4', 'flags': '0',
            'created': '2021-09-01', 'changed': '2023-06-15',
            'links': [{'ou': 'OU=Servers,DC=corp,DC=local', 'flags': 0, 'enforced': False, 'disabled': False}],
            'settings': {
                'password_policy': {
                    # Conflit sécurité : longueur différente de Default Domain Policy (8) et GPO_Sécurité (16)
                    'minimumpasswordlength': '12',
                    'maximumpasswordage': '180',   # Conflit avec Default (42) et Sécurité (90)
                },
                'event_audit': {
                    # Conflit audit : valeur différente de GPO_Sécurité_Postes (3)
                    'auditlogonevents':   '1',    # Succès seulement vs Succès+Échec
                    'auditaccountmanage': '2',    # Échec seulement
                },
                'system_access': {
                    'lmcompatibilitylevel': '3',   # Conflit : Default=1, Sécurité=5, ici=3
                    'lockoutbadcount': '15',        # Conflit : Default=0, Sécurité=5, ici=15
                },
            },
            'registry_entries': [
                # Conflit registre : pare-feu OFF ici vs ON dans GPO_Sécurité
                (r'hklm\software\policies\microsoft\windowsfirewall\domainprofile',
                 'enablefirewall', 4, 0),
            ],
        },
        {
            'name': 'GPO_Conformité_RGPD',
            'guid': '{F56G8H92-3333-4444-5555-666677778888}',
            'sysvol_path': '', 'version': '2', 'flags': '0',
            'created': '2022-05-20', 'changed': '2022-11-30',
            'links': [{'ou': 'OU=Workstations,DC=corp,DC=local', 'flags': 0, 'enforced': False, 'disabled': False}],
            'settings': {
                'password_policy': {
                    # Conflit : encore une valeur différente pour minimumpasswordlength
                    'minimumpasswordlength': '10',
                    'passwordhistorysize': '12',    # Conflit avec Default (5) et Sécurité (24)
                },
                'system_access': {
                    'lockoutduration': '5',         # Conflit : Sécurité=30, ici=5
                    'nolmhash': '1',                # Pas de conflit (même valeur que Sécurité)
                },
            },
            'registry_entries': [],
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
            'name':       gpo['name'],
            'guid':       gpo['guid'],
            'links':      gpo['links'],
            'link_count': len(gpo['links']),
            'flags':      gpo.get('flags', '0'),
            'created':    gpo.get('created', ''),
            'changed':    gpo.get('changed', ''),
            'findings':   per_gpo_findings,
            'score':      score,
            'is_orphan':  not gpo['links'],
            'has_content': has_content,
            # content est exclu ici — chargé à la demande via gpo_content_index
        })
        # Index de contenu séparé — chargé uniquement quand on ouvre une GPO
        gpo_content_index[gpo['guid']] = content_sections

    # 3. Redondances (même paramètre dans plusieurs GPO)
    param_seen = {}
    for gpo in gpos:
        for section, params in gpo.get('settings', {}).items():
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
    global_score = max(0, min(100, 100 - criticals * 15 - warnings * 5 - infos * 2))

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
        'search_index':      build_search_index(gpos),
    }


# ─── Template HTML ────────────────────────────────────────────────────────────

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="fr" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GPOctopus Audit — {{ data.generated_at }}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&family=Inter:wght@400;500;600&display=swap');

[data-theme="dark"]{
  --bg:#0f1117;--surface:#161b27;--surface2:#1c2133;--surface3:#222840;
  --border:#252d42;--border2:#2e3852;
  --txt:#c8cfe0;--txt2:#6b7899;--txt3:#3d4a68;
  --red:#e05252;--red-dim:rgba(224,82,82,.1);--red-glow:rgba(224,82,82,.2);
  --amber:#d4892a;--amber-dim:rgba(212,137,42,.1);
  --green:#3a9e72;--green-dim:rgba(58,158,114,.1);
  --blue:#4a7fd4;--blue-dim:rgba(74,127,212,.1);
  --purple:#8b6ddb;--teal:#2ab5a0;
  --chart1:#4a7fd4;--chart2:#e05252;--chart3:#d4892a;--chart4:#3a9e72;--chart5:#8b6ddb;
}
[data-theme="light"]{
  --bg:#f2f4f8;--surface:#ffffff;--surface2:#eef0f6;--surface3:#e5e8f0;
  --border:#d8dce8;--border2:#c4c9d8;
  --txt:#1e2336;--txt2:#4e5878;--txt3:#8890aa;
  --red:#c03030;--red-dim:rgba(192,48,48,.07);--red-glow:rgba(192,48,48,.15);
  --amber:#a86a10;--amber-dim:rgba(168,106,16,.07);
  --green:#1e7a54;--green-dim:rgba(30,122,84,.07);
  --blue:#2655b0;--blue-dim:rgba(38,85,176,.07);
  --purple:#5c3fc0;--teal:#1a8a78;
  --chart1:#2655b0;--chart2:#c03030;--chart3:#a86a10;--chart4:#1e7a54;--chart5:#5c3fc0;
}

*{box-sizing:border-box;margin:0;padding:0}
html{font-size:14px}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--txt);min-height:100vh;overflow-x:hidden}

/* ── Sidebar ── */
.sidebar{position:fixed;top:0;left:0;width:230px;height:100vh;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;z-index:200;overflow-y:auto}
.sb-logo{padding:22px 20px 16px;border-bottom:1px solid var(--border)}
.sb-logo h1{font-size:16px;font-weight:700;letter-spacing:-.4px;display:flex;align-items:center;gap:8px}
.sb-logo p{font-size:11px;color:var(--txt3);margin-top:3px}
.sb-score{margin:14px 16px;background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:12px;display:flex;align-items:center;gap:12px;border-left:2px solid var(--border2)}
.sb-score-ring{position:relative;width:56px;height:56px;flex-shrink:0}
.sb-score-ring svg{transform:rotate(-90deg)}
.sb-score-val{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.sb-score-val .n{font-size:18px;font-weight:700;font-family:'JetBrains Mono',monospace;line-height:1}
.sb-score-val .l{font-size:9px;color:var(--txt3)}
.sb-score-info{flex:1;min-width:0}
.sb-score-info .label{font-size:11px;font-weight:600}
.sb-score-info .sub{font-size:11px;color:var(--txt2);margin-top:2px}
.nav-group{padding:12px 0 4px}
.nav-label{font-size:10px;font-weight:600;color:var(--txt3);letter-spacing:.8px;text-transform:uppercase;padding:0 20px 6px}
.nav-item{display:flex;align-items:center;gap:10px;padding:8px 20px;font-size:13px;color:var(--txt2);cursor:pointer;border-left:2px solid transparent;transition:all .15s}
.nav-item:hover{color:var(--txt);background:var(--surface2)}
.nav-item.active{color:var(--txt);border-left-color:var(--blue);background:var(--surface2);font-weight:500}
.nav-icon{font-size:15px;width:18px;text-align:center;flex-shrink:0}
.nav-badge{margin-left:auto;font-size:10px;padding:0 5px;border-radius:2px;background:var(--red-dim);color:var(--red);font-weight:600;font-family:'JetBrains Mono',monospace}
.sb-footer{margin-top:auto;padding:14px 20px;border-top:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.theme-toggle{width:34px;height:18px;background:var(--surface3);border-radius:9px;cursor:pointer;position:relative;border:1px solid var(--border2)}
.theme-toggle::after{content:'';position:absolute;top:2px;left:2px;width:12px;height:12px;border-radius:50%;background:var(--txt2);transition:left .2s}
[data-theme="light"] .theme-toggle::after{left:18px;background:var(--blue)}

/* ── Main ── */
.main{margin-left:230px;padding:32px 36px;max-width:1160px}
.view{display:none;animation:fadeIn .25s ease}
.view.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
.view-header{margin-bottom:28px}
.view-title{font-size:22px;font-weight:700;letter-spacing:-.4px}
.view-sub{font-size:13px;color:var(--txt2);margin-top:4px}

/* ── Metric cards ── */
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:28px}
.mc{background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:14px 16px;position:relative;cursor:default;}
.mc:hover{background:var(--surface2)}





.mc .v{font-size:26px;font-weight:600;font-family:'JetBrains Mono',monospace;line-height:1;margin-bottom:4px}
.mc .l{font-size:11px;color:var(--txt3);letter-spacing:.2px}
.mc.red .v{color:var(--red)}.mc.amber .v{color:var(--amber)}.mc.green .v{color:var(--green)}.mc.blue .v{color:var(--blue)}

/* ── Charts ── */
.charts-row{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px}
.chart-card{background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:16px}
.chart-title{font-size:13px;font-weight:600;margin-bottom:16px;color:var(--txt)}
.chart-wrap{position:relative}

/* ── Priority list ── */
.prio-item{background:var(--surface);border:1px solid var(--border);border-radius:3px;margin-bottom:6px;overflow:hidden;cursor:pointer;}
.prio-item:hover{border-color:var(--border2);background:var(--surface2)}
.prio-item.open{border-color:var(--border2)}
.prio-head{display:flex;align-items:center;gap:12px;padding:13px 16px}
.prio-num{width:24px;height:24px;border-radius:2px;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;font-family:'JetBrains Mono',monospace;flex-shrink:0}
.prio-num.critical{background:var(--red-dim);color:var(--red)}
.prio-num.warning{background:var(--amber-dim);color:var(--amber)}
.prio-title{flex:1;font-size:13px;font-weight:500}
.prio-ref{font-size:10px;color:var(--txt3);font-family:'JetBrains Mono',monospace;margin-top:2px}
.sev-pill{font-size:10px;padding:1px 7px;border-radius:2px;font-weight:600;flex-shrink:0;font-family:'JetBrains Mono',monospace;letter-spacing:.3px}
.sev-pill.critical{background:var(--red-dim);color:var(--red)}
.sev-pill.warning{background:var(--amber-dim);color:var(--amber)}
.sev-pill.info{background:var(--blue-dim);color:var(--blue)}
.prio-arr{font-size:10px;color:var(--txt3);transition:transform .17s;flex-shrink:0}
.prio-item.open .prio-arr{transform:rotate(90deg)}
.prio-body{display:none;border-top:1px solid var(--border);padding:12px 16px;background:var(--surface2)}
.prio-item.open .prio-body{display:block}
.prio-detail{font-size:12px;color:var(--txt2);margin-bottom:8px;line-height:1.6}
.prio-reco{font-size:12px;color:var(--txt2);padding:10px 12px;background:var(--surface);border-radius:2px;border-left:3px solid var(--border2);line-height:1.6}

/* ── Findings ── */
.finding-card{background:var(--surface);border:1px solid var(--border);border-radius:3px;margin-bottom:6px;overflow:hidden;cursor:pointer;}
.finding-card:hover{border-color:var(--border2)}
.fc-head{display:flex;align-items:center;gap:10px;padding:12px 14px}
.sev-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.sev-dot.critical{background:var(--red)}.sev-dot.warning{background:var(--amber)}.sev-dot.info{background:var(--blue)}
.fc-title{flex:1;font-size:13px;font-weight:500}
.nc-tag{font-size:10px;padding:1px 6px;border-radius:4px;background:var(--amber-dim);color:var(--amber);margin-left:6px;vertical-align:middle}
.fc-arr{font-size:10px;color:var(--txt3);transition:transform .15s}
.fc-arr.open{transform:rotate(90deg)}
.fc-body{display:none;border-top:1px solid var(--border);padding:12px 14px;background:var(--surface2)}
.fc-body.open{display:block}
.fc-detail{font-size:12px;color:var(--txt2);margin-bottom:6px;line-height:1.5}
.fc-ref{font-size:11px;color:var(--txt3);font-family:'JetBrains Mono',monospace;margin-bottom:8px}
.fc-reco{font-size:12px;padding:8px 10px;background:var(--surface);border-radius:2px;border-left:3px solid var(--border2);color:var(--txt2);line-height:1.6}

/* ── Tooltip ── */
.has-tooltip{position:relative}
.tooltip{position:absolute;bottom:calc(100% + 8px);left:50%;transform:translateX(-50%);background:var(--surface3);border:1px solid var(--border2);border-radius:3px;padding:6px 10px;font-size:12px;color:var(--txt);white-space:nowrap;pointer-events:none;opacity:0;z-index:500;box-shadow:0 2px 8px rgba(0,0,0,.3);max-width:240px;white-space:normal;text-align:center}
.has-tooltip:hover .tooltip{opacity:1}

/* ── Search & filters ── */
.toolbar{display:flex;gap:10px;margin-bottom:16px;align-items:center;flex-wrap:wrap}
.search-box{position:relative;flex:1;min-width:200px}
.search-box input{width:100%;padding:8px 14px 8px 34px;background:var(--surface);border:1px solid var(--border);border-radius:3px;color:var(--txt);font-size:13px;font-family:'Inter',sans-serif;outline:none}
.search-box input:focus{border-color:var(--blue)}
.search-box input::placeholder{color:var(--txt3)}
.search-icon{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:var(--txt3);font-size:14px;pointer-events:none}
.filter-btn{padding:5px 12px;border-radius:3px;border:1px solid var(--border);background:none;cursor:pointer;font-size:12px;color:var(--txt2);font-family:'Inter',sans-serif}
.filter-btn:hover{border-color:var(--border2);color:var(--txt)}
.filter-btn.on{background:var(--blue);border-color:var(--blue);color:#fff;font-weight:500}

/* ── GPO table ── */
.gpo-table{width:100%;border-collapse:collapse}
.gpo-table th{font-size:11px;color:var(--txt3);text-transform:uppercase;letter-spacing:.4px;padding:8px 12px;text-align:left;border-bottom:1px solid var(--border);font-weight:500}
.gpo-table td{padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:middle;font-size:13px}
.gpo-table tbody tr{cursor:pointer;transition:background .1s}
.gpo-table tbody tr:hover td{background:var(--surface2)}
.gpo-table tbody tr:last-child td{border-bottom:none}
.score-bar-wrap{display:flex;align-items:center;gap:8px}
.score-bar{width:60px;height:3px;background:var(--surface3);overflow:hidden}
.score-bar-fill{height:100%;transition:width .3s}
.score-num{font-family:'JetBrains Mono',monospace;font-size:12px;min-width:28px}
.flag{font-size:10px;padding:1px 7px;border-radius:4px;margin-left:4px;font-weight:500}
.flag-orphan{background:var(--blue-dim);color:var(--blue)}
.flag-disabled{background:var(--amber-dim);color:var(--amber)}

/* ── GPO Detail ── */
.back-btn{display:inline-flex;align-items:center;gap:6px;padding:5px 12px;border:1px solid var(--border);border-radius:3px;background:none;color:var(--txt2);cursor:pointer;font-size:12px;margin-bottom:16px;font-family:'Inter',sans-serif}
.back-btn:hover{border-color:var(--border2);color:var(--txt)}
.gpo-detail-card{background:var(--surface);border:1px solid var(--border);border-radius:3px;padding:16px 20px;margin-bottom:12px}
.gpo-detail-card h3{font-size:16px;font-weight:600;margin-bottom:6px}
.gpo-meta-grid{display:flex;gap:20px;flex-wrap:wrap;font-size:12px;color:var(--txt2);font-family:'JetBrains Mono',monospace}
.gpo-meta-item span:first-child{color:var(--txt3);margin-right:4px}
.section-block{background:var(--surface);border:1px solid var(--border);border-radius:3px;margin-bottom:6px;overflow:hidden}
.section-head{display:flex;align-items:center;gap:10px;padding:11px 14px;cursor:pointer;transition:background .1s}
.section-head:hover{background:var(--surface2)}
.section-icon{font-size:15px}
.section-title{flex:1;font-size:13px;font-weight:500}
.section-count{font-size:11px;color:var(--txt3);margin-right:4px}
.section-arr{font-size:10px;color:var(--txt3);transition:transform .15s}
.section-arr.open{transform:rotate(90deg)}
.section-body{display:none;border-top:1px solid var(--border)}
.section-body.open{display:block}
.param-table{width:100%;border-collapse:collapse;font-size:12px}
.param-table td{padding:7px 14px;border-bottom:1px solid var(--border)}
.param-table tr:last-child td{border-bottom:none}
.param-table td:first-child{color:var(--txt2);width:42%}
.param-bad{color:var(--red)}
.param-alert-badge{font-size:10px;padding:1px 6px;border-radius:4px;background:var(--red-dim);color:var(--red);margin-left:6px}

/* ── Type / OU views ── */
.type-section{margin-bottom:28px}
.type-header{display:flex;align-items:center;gap:12px;margin-bottom:12px;padding-bottom:10px;border-bottom:1px solid var(--border)}
.ou-card{background:var(--surface);border:1px solid var(--border);border-radius:3px;margin-bottom:6px;overflow:hidden}
.ou-head{display:flex;align-items:center;gap:10px;padding:11px 14px;cursor:pointer;transition:background .1s}
.ou-head:hover{background:var(--surface2)}
.ou-body{display:none;border-top:1px solid var(--border);padding:8px 14px}
.ou-body.open{display:block}
.ou-gpo-row{display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid var(--border);font-size:12px}
.ou-gpo-row:last-child{border-bottom:none}

/* ── Category grid ── */
.cat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(155px,1fr));gap:10px;margin-bottom:24px}
.cat-card{background:var(--surface);border:1px solid var(--border);border-radius:3px;padding:14px;cursor:pointer;}
.cat-card:hover{border-color:var(--border2);background:var(--surface2)}
.cat-icon{font-size:22px;margin-bottom:8px}
.cat-name{font-size:13px;font-weight:500;margin-bottom:4px}
.cat-count{font-size:11px;color:var(--txt2)}
.cat-bar{height:3px;border-radius:2px;background:var(--surface3);margin-top:8px;overflow:hidden}
.cat-fill{height:100%;border-radius:2px;background:var(--blue);transition:width .4s}

/* ── Info box ── */
.info-box{background:var(--blue-dim);border:1px solid var(--blue);border-left:3px solid var(--blue);border-radius:2px;padding:10px 14px;font-size:12px;color:var(--txt2);margin-bottom:16px;line-height:1.6}
.warn-box{background:var(--amber-dim);border:1px solid var(--amber);border-left:3px solid var(--amber);border-radius:2px;padding:10px 14px;font-size:12px;color:var(--txt2);margin-bottom:8px}
.stitle{font-size:11px;font-weight:600;color:var(--txt3);text-transform:uppercase;letter-spacing:.6px;margin:18px 0 10px}
.mono-block{background:var(--surface);border:1px solid var(--border);border-radius:2px;padding:12px;font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--txt2);line-height:2}
.mono-comment{color:var(--txt3)}

/* ── Scrollbar ── */
::-webkit-scrollbar{width:4px;height:4px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--border2);border-radius:2px}

/* ── Loading animation ── */
.loader{position:fixed;inset:0;background:var(--bg);z-index:9999;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:16px}
.loader-ring{width:32px;height:32px;border:2px solid var(--border2);border-top-color:var(--blue);border-radius:50%;animation:spin .8s linear infinite}
.loader-text{font-size:13px;color:var(--txt2)}
@keyframes spin{to{transform:rotate(360deg)}}
.loader.done{animation:fadeOut .4s ease forwards}
@keyframes fadeOut{to{opacity:0;pointer-events:none}}

/* ── Stagger animation ── */
.stagger-item{opacity:0;transition:opacity .2s}
.stagger-item.visible{opacity:1}

/* ── Quick panel ── */
.qp-finding{border-bottom:1px solid var(--border);padding:14px 18px;transition:background .1s}
.qp-finding:last-child{border-bottom:none}
.qp-finding:hover{background:var(--surface2)}
.qp-finding-head{display:flex;align-items:flex-start;gap:12px;margin-bottom:8px}
.qp-title{flex:1;font-size:13px;font-weight:500;line-height:1.4}
.qp-action{display:inline-flex;align-items:center;gap:6px;font-size:11px;padding:4px 10px;border-radius:6px;font-weight:500;margin-top:6px}
.qp-action.modify{background:var(--amber-dim);color:var(--amber)}
.qp-action.create{background:var(--blue-dim);color:var(--blue)}
.qp-gpo-list{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.qp-gpo-chip{font-size:11px;padding:3px 10px;border-radius:2px;background:var(--surface3);color:var(--txt2);cursor:pointer;border:1px solid var(--border);font-family:'JetBrains Mono',monospace}
.qp-gpo-chip:hover{border-color:var(--blue);color:var(--blue)}
.qp-reco{font-size:12px;color:var(--txt2);padding:8px 10px;background:var(--surface2);border-radius:6px;border-left:2px solid var(--border2);line-height:1.6;margin-top:6px;display:none}
.qp-finding.open .qp-reco{display:block}
.qp-finding-toggle{font-size:11px;color:var(--txt3);cursor:pointer;transition:transform .15s;display:inline-block}
.qp-finding.open .qp-finding-toggle{transform:rotate(90deg)}
.mc.clickable:hover{background:var(--surface2)}

</style>
</head>
<body>

<!-- Loading -->
<div class="loader" id="loader">
  <div class="loader-ring"></div>
  <div class="loader-text">Chargement GPOctopus Audit…</div>
</div>

<nav class="sidebar">
  <div class="sb-logo">
    <h1>🐙 GPOctopus Audit</h1>
    <p>{{ data.generated_at }} · {{ data.gpo_count }} GPO</p>
  </div>

  <div class="sb-score">
    <div class="sb-score-ring">
      <svg width="56" height="56" viewBox="0 0 56 56">
        <circle cx="28" cy="28" r="22" fill="none" stroke="var(--surface3)" stroke-width="5"/>
        <circle cx="28" cy="28" r="22" fill="none"
          stroke="{% if data.global_score>=70%}var(--green){% elif data.global_score>=40%}var(--amber){% else %}var(--red){% endif %}"
          stroke-width="5" stroke-linecap="round"
          stroke-dasharray="{{ (data.global_score * 1.382)|int }} 138.2"
          id="score-arc"/>
      </svg>
      <div class="sb-score-val">
        <span class="n" style="color:{% if data.global_score>=70%}var(--green){% elif data.global_score>=40%}var(--amber){% else %}var(--red){% endif %}">{{ data.global_score }}</span>
        <span class="l">/100</span>
      </div>
    </div>
    <div class="sb-score-info">
      <div class="label" style="color:{% if data.global_score>=70%}var(--green){% elif data.global_score>=40%}var(--amber){% else %}var(--red){% endif %}">
        {% if data.global_score>=70%}Satisfaisant{% elif data.global_score>=40%}À améliorer{% else %}Insuffisant{% endif %}
      </div>
      <div class="sub">{{ data.criticals }} critique(s) · {{ data.warnings }} alerte(s)</div>
    </div>
  </div>

  <div class="nav-group">
    <div class="nav-label">Vue d'ensemble</div>
    <div class="nav-item active" onclick="nav('dashboard',this)"><span class="nav-icon">◈</span>Tableau de bord</div>
    <div class="nav-item" onclick="nav('priorities',this)">
      <span class="nav-icon">▲</span>Priorités
      {% if data.criticals > 0 %}<span class="nav-badge">{{ data.criticals }}</span>{% endif %}
    </div>
  </div>
  <div class="nav-group">
    <div class="nav-label">Analyse</div>
    <div class="nav-item" onclick="nav('search',this)"><span class="nav-icon">⌕</span>Recherche GPO</div>
    <div class="nav-item" onclick="nav('findings',this)"><span class="nav-icon">⚑</span>Constatations RSOP</div>
    <div class="nav-item" onclick="nav('gpolist',this)"><span class="nav-icon">≡</span>GPO par GPO</div>
    <div class="nav-item" onclick="nav('bytype',this)"><span class="nav-icon">◫</span>Par type</div>
    <div class="nav-item" onclick="nav('byou',this)"><span class="nav-icon">⊢</span>Par OU</div>
  </div>
  <div class="nav-group">
    <div class="nav-label">Résultats</div>
    <div class="nav-item" onclick="nav('compliant',this)"><span class="nav-icon">✓</span>Conformes ({{ data.compliant_count }})</div>
    <div class="nav-item" onclick="nav('conflicts',this)">
      <span class="nav-icon">⚡</span>Conflits GPO
      {% if data.conflicts_high > 0 %}<span class="nav-badge">{{ data.conflicts_high }}</span>{% endif %}
    </div>
    <div class="nav-item" onclick="nav('orphans',this)"><span class="nav-icon">◌</span>Orphelines ({{ data.orphan_count }})</div>
  </div>

  <div class="sb-footer">
    <span style="font-size:11px;color:var(--txt3)">GPOctopus Audit · CIS · ANSSI · MS Baseline</span>
    <div class="theme-toggle has-tooltip" onclick="toggleTheme()" title="">
      <span class="tooltip">Basculer thème</span>
    </div>
  </div>
</nav>

<main class="main">

<!-- ══ DASHBOARD ══ -->
<div id="view-dashboard" class="view active">
  <div class="view-header">
    <div class="view-title">Tableau de bord</div>
    <div class="view-sub">{{ data.gpo_count }} GPO analysées · CIS Benchmarks · ANSSI · MS Security Baseline</div>
  </div>

  <div class="metrics">
    <div class="mc red clickable has-tooltip" onclick="openQuickPanel('critical')" style="cursor:pointer">
      <div class="v">{{ data.criticals }}</div><div class="l">Critiques</div>
      <div style="font-size:10px;color:var(--txt3);margin-top:4px">Cliquer pour voir →</div>
      <span class="tooltip">Cliquez pour voir les problèmes critiques et les GPO à modifier</span>
    </div>
    <div class="mc amber clickable has-tooltip" onclick="openQuickPanel('warning')" style="cursor:pointer">
      <div class="v">{{ data.warnings }}</div><div class="l">Avertissements</div>
      <div style="font-size:10px;color:var(--txt3);margin-top:4px">Cliquer pour voir →</div>
      <span class="tooltip">Cliquez pour voir les avertissements et les GPO à modifier</span>
    </div>
    <div class="mc clickable has-tooltip" onclick="openQuickPanel('info')" style="cursor:pointer">
      <div class="v">{{ data.infos }}</div><div class="l">Informatifs</div>
      <div style="font-size:10px;color:var(--txt3);margin-top:4px">Cliquer pour voir →</div>
      <span class="tooltip">Paramètres non configurés — cliquez pour voir les détails</span>
    </div>
    <div class="mc green clickable has-tooltip" onclick="openQuickPanel('compliant')" style="cursor:pointer">
      <div class="v">{{ data.compliant_count }}</div><div class="l">Conformes</div>
      <div style="font-size:10px;color:var(--txt3);margin-top:4px">Cliquer pour voir →</div>
      <span class="tooltip">Cliquez pour voir les contrôles conformes</span>
    </div>
    <div class="mc blue clickable has-tooltip" onclick="openQuickPanel('orphan')" style="cursor:pointer">
      <div class="v">{{ data.orphan_count }}</div><div class="l">Orphelines</div>
      <div style="font-size:10px;color:var(--txt3);margin-top:4px">Cliquer pour voir →</div>
      <span class="tooltip">GPO non liées à une OU — cliquez pour voir la liste</span>
    </div>
    <div class="mc clickable has-tooltip" onclick="nav('conflicts',document.querySelector('[onclick*=conflicts]'))" style="cursor:pointer">
      <div class="v" style="color:{% if data.conflicts_high > 0 %}var(--red){% else %}var(--amber){% endif %}">{{ data.gpo_conflicts|length }}</div>
      <div class="l">Conflits GPO</div>
      <div style="font-size:10px;color:var(--txt3);margin-top:4px">{{ data.conflicts_high }} critique(s) →</div>
      <span class="tooltip">Même paramètre, valeurs différentes dans plusieurs GPO — l'ordre d'application détermine ce qui s'applique</span>
    </div>
    <div class="mc clickable has-tooltip" onclick="openQuickPanel('all')" style="cursor:pointer">
      <div class="v">{{ data.gpo_count }}</div><div class="l">GPO totales</div>
      <div style="font-size:10px;color:var(--txt3);margin-top:4px">Cliquer pour voir →</div>
      <span class="tooltip">Cliquez pour voir toutes les GPO et les doublons</span>
    </div>
  </div>

  <!-- Panel rapide findings -->
  <div id="quick-panel" style="display:none;margin-bottom:24px">
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:3px;overflow:hidden">
      <div style="display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid var(--border)">
        <span id="qp-title" style="font-size:14px;font-weight:600"></span>
        <div style="display:flex;gap:8px;align-items:center">
          <button class="filter-btn on" onclick="openQuickPanel(_qpSev)" style="font-size:11px;padding:4px 10px">Actualiser</button>
          <button onclick="document.getElementById('quick-panel').style.display='none'" style="background:none;border:none;color:var(--txt3);cursor:pointer;font-size:16px">✕</button>
        </div>
      </div>
      <div id="qp-content" style="padding:0"></div>
    </div>
  </div>

  <div class="charts-row">
    <div class="chart-card">
      <div class="chart-title">Répartition des constatations</div>
      <div class="chart-wrap" style="height:180px"><canvas id="chart-donut"></canvas></div>
    </div>
    <div class="chart-card">
      <div class="chart-title">Score par catégorie</div>
      <div class="chart-wrap" style="height:180px"><canvas id="chart-radar"></canvas></div>
    </div>
  </div>

  <div class="stitle">Types de contenu dans vos GPO</div>
  <div class="cat-grid" id="cat-grid"></div>

  {% if data.criticals > 0 %}
  <div style="margin-top:20px">
    <div class="stitle">Actions prioritaires</div>
    <div id="dash-priorities"></div>
    <button class="filter-btn on" style="margin-top:10px" onclick="nav('priorities',document.querySelector('[onclick*=priorities]'))">Voir toutes les priorités →</button>
  </div>
  {% endif %}
</div>

<!-- ══ PRIORITIES ══ -->
<div id="view-priorities" class="view">
  <div class="view-header">
    <div class="view-title">Priorités d'action</div>
    <div class="view-sub">Classées par impact — corrigez dans cet ordre</div>
  </div>
  <div id="priority-list"></div>
</div>

<!-- ══ SEARCH ══ -->
<div id="view-search" class="view">
  <div class="view-header">
    <div class="view-title">⌕ Recherche dans toutes les GPO</div>
    <div class="view-sub">Cherchez un paramètre, une imprimante, un script, un chemin réseau, un service… dans l'ensemble de vos GPO</div>
  </div>

  <div style="margin-bottom:20px">
    <div style="position:relative">
      <span style="position:absolute;left:14px;top:50%;transform:translateY(-50%);color:var(--txt3);font-size:18px;pointer-events:none">⌕</span>
      <input id="search-main-input" type="text"
        placeholder="Ex: \\\\print01, startup.ps1, minimumpasswordlength, SMB, proxy, 192.168…"
        style="width:100%;padding:14px 14px 14px 44px;background:var(--surface);border:1px solid var(--border2);border-radius:3px;color:var(--txt);font-size:14px;font-family:'Inter',sans-serif;outline:none;transition:border-color .15s"
        oninput="globalSearch(this.value)"
        onfocus="this.style.borderColor='var(--blue)'"
        onblur="this.style.borderColor='var(--border2)'"
      >
    </div>

    <!-- Filtres rapides -->
    <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:12px" id="search-quick-filters">
      <span style="font-size:11px;color:var(--txt3);align-self:center;margin-right:4px">Raccourcis :</span>
      <button class="filter-btn" onclick="quickSearch('imprimante')">🖨 Imprimantes</button>
      <button class="filter-btn" onclick="quickSearch('lecteur réseau')">💾 Lecteurs</button>
      <button class="filter-btn" onclick="quickSearch('script')">📜 Scripts</button>
      <button class="filter-btn" onclick="quickSearch('tâche planifiée')">⏰ Tâches</button>
      <button class="filter-btn" onclick="quickSearch('service windows')">🔧 Services</button>
      <button class="filter-btn" onclick="quickSearch('registre')">🗝 Registre</button>
      <button class="filter-btn" onclick="quickSearch('groupe local')">👥 Groupes</button>
      <button class="filter-btn" onclick="quickSearch('lien ou')">⊢ Liens OU</button>
    </div>
  </div>

  <!-- Filtres par type -->
  <div id="search-type-filters" style="display:none;margin-bottom:16px">
    <div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center">
      <span style="font-size:11px;color:var(--txt3)">Filtrer par type :</span>
      <button class="filter-btn on" onclick="filtSearchType('all',this)">Tous</button>
      <span id="search-type-btns"></span>
    </div>
  </div>

  <!-- Résultats -->
  <div id="search-results-header" style="display:none;margin-bottom:12px">
    <span id="search-count" style="font-size:13px;color:var(--txt2)"></span>
    <span id="search-gpo-count" style="font-size:12px;color:var(--txt3);margin-left:8px"></span>
  </div>

  <div id="search-results"></div>

  <!-- État initial -->
  <div id="search-empty-state" style="text-align:center;padding:60px 20px;color:var(--txt3)">
    <div style="font-size:48px;margin-bottom:16px">⌕</div>
    <div style="font-size:15px;font-weight:500;margin-bottom:8px">Recherchez dans toutes vos GPO</div>
    <div style="font-size:13px;line-height:1.8">
      Chemin UNC d'imprimante · Lettre de lecteur · Nom de script<br>
      Clé de registre · Nom de service · Commande de tâche planifiée<br>
      Nom de groupe · Variable d'environnement · Paramètre de sécurité
    </div>
  </div>
</div>

<!-- ══ FINDINGS ══ -->
<div id="view-findings" class="view">
  <div class="view-header">
    <div class="view-title">Constatations RSOP</div>
    <div class="view-sub">Résultat après fusion de toutes les GPO — ce qui s'applique réellement</div>
  </div>
  <div class="info-box">
    Le <strong>RSOP</strong> simule ce que Windows applique après avoir fusionné toutes vos GPO.
    <span style="background:var(--amber-dim);color:var(--amber);font-size:10px;padding:1px 6px;border-radius:4px;margin-left:4px">non configuré</span>
    = paramètre absent, valeur par défaut Windows appliquée.
  </div>
  <div class="toolbar">
    <div class="search-box">
      <span class="search-icon">⌕</span>
      <input type="text" placeholder="Rechercher une constatation…" oninput="searchFindings(this.value)">
    </div>
    <button class="filter-btn on" onclick="filtF('all',this)">Tous ({{ data.total_findings }})</button>
    <button class="filter-btn" onclick="filtF('critical',this)">Critique ({{ data.criticals }})</button>
    <button class="filter-btn" onclick="filtF('warning',this)">Avert. ({{ data.warnings }})</button>
    <button class="filter-btn" onclick="filtF('info',this)">Info ({{ data.infos }})</button>
  </div>
  <div id="findings-list">
  {% for f in data.all_findings %}
  <div class="finding-card stagger-item" data-sev="{{ f.severity }}" data-txt="{{ f.title|lower }} {{ f.category|lower }} {{ f.ref|lower }}">
    <div class="fc-head" onclick="togFC(this)">
      <div class="sev-dot {{ f.severity }}"></div>
      <div>
        <div class="fc-title">{{ f.title }}{% if f.get('not_configured') %}<span class="nc-tag">non configuré</span>{% endif %}</div>
        <div style="font-size:11px;color:var(--txt3);margin-top:1px">{{ f.category }}</div>
      </div>
      <span class="sev-pill {{ f.severity }}" style="margin-left:auto;margin-right:8px">{{ f.severity }}</span>
      <div class="fc-arr">▶</div>
    </div>
    <div class="fc-body">
      <div class="fc-detail">{{ f.detail }}</div>
      <div class="fc-ref">{{ f.ref }}</div>
      <div class="fc-reco">{{ f.remediation }}</div>
    </div>
  </div>
  {% endfor %}
  {% if not data.all_findings %}
  <div style="text-align:center;padding:48px;color:var(--txt3)">🎉 Aucun écart détecté</div>
  {% endif %}
  </div>
</div>

<!-- ══ GPO LIST ══ -->
<div id="view-gpolist" class="view">
  <div class="view-header">
    <div class="view-title">GPO par GPO</div>
    <div class="view-sub">Cliquez sur une GPO pour voir son contenu complet</div>
  </div>
  <div class="toolbar">
    <div class="search-box">
      <span class="search-icon">⌕</span>
      <input type="text" placeholder="Rechercher une GPO…" oninput="searchGPO(this.value)">
    </div>
    <button class="filter-btn on" onclick="filtG('all',this)">Toutes</button>
    <button class="filter-btn" onclick="filtG('issues',this)">Problèmes</button>
    <button class="filter-btn" onclick="filtG('empty',this)">Vides</button>
    <button class="filter-btn" onclick="filtG('orphan',this)">Orphelines</button>
  </div>
  <div id="gpo-list-area"></div>
</div>

<!-- ══ GPO DETAIL ══ -->
<div id="view-gpodetail" class="view">
  <button class="back-btn" onclick="nav('gpolist',document.querySelector('[onclick*=gpolist]'))">← Retour à la liste</button>
  <div id="gpo-detail-content"></div>
</div>

<!-- ══ BY TYPE ══ -->
<div id="view-bytype" class="view">
  <div class="view-header">
    <div class="view-title">Par type de contenu</div>
    <div class="view-sub">Toutes vos GPO regroupées par ce qu'elles configurent</div>
  </div>
  <div id="bytype-content"></div>
</div>

<!-- ══ BY OU ══ -->
<div id="view-byou" class="view">
  <div class="view-header">
    <div class="view-title">Par unité organisationnelle</div>
    <div class="view-sub">Quelles GPO s'appliquent sur quelle OU</div>
  </div>
  <div class="toolbar">
    <div class="search-box">
      <span class="search-icon">⌕</span>
      <input type="text" placeholder="Rechercher une OU…" oninput="searchOU(this.value)">
    </div>
  </div>
  <div id="byou-content"></div>
</div>

<!-- ══ COMPLIANT ══ -->
<div id="view-compliant" class="view">
  <div class="view-header">
    <div class="view-title">Contrôles conformes</div>
    <div class="view-sub">Ces paramètres sont correctement configurés dans votre RSOP</div>
  </div>
  {% for r in data.compliant_rules %}
  <div class="finding-card stagger-item">
    <div class="fc-head" onclick="togFC(this)">
      <div class="sev-dot" style="background:var(--green)"></div>
      <div>
        <div class="fc-title">{{ r.title }}</div>
        <div style="font-size:11px;color:var(--txt3);margin-top:1px">{{ r.category }}</div>
      </div>
      <span class="sev-pill" style="background:var(--green-dim);color:var(--green);margin-left:auto;margin-right:8px">conforme</span>
      <div class="fc-arr">▶</div>
    </div>
    <div class="fc-body">
      <div class="fc-ref">{{ r.ref }}</div>
    </div>
  </div>
  {% endfor %}
</div>

<!-- ══ CONFLICTS ══ -->
<div id="view-conflicts" class="view">
  <div class="view-header">
    <div class="view-title">⚡ Conflits GPO</div>
    <div class="view-sub">Même paramètre configuré avec des valeurs différentes dans plusieurs GPO — l'ordre d'application détermine ce qui s'applique réellement</div>
  </div>

  {% if data.gpo_conflicts %}
  {% if data.conflicts_high > 0 %}
  <div class="warn-box" style="border-color:var(--red);background:var(--red-dim);margin-bottom:16px">
    <strong style="color:var(--red)">⚡ {{ data.conflicts_high }} conflit(s) sur des paramètres de sécurité sensibles</strong> —
    la GPO gagnante peut masquer une mauvaise configuration appliquée dans une autre GPO.
    Vérifiez l'ordre d'application et supprimez la valeur dans la GPO perdante.
  </div>
  {% endif %}

  <div class="info-box">
    <strong>Comment lire un conflit :</strong> la GPO <strong>gagnante</strong> est celle dont la valeur s'applique réellement (priorité la plus haute ou Enforced).
    Les GPO <strong>perdantes</strong> configurent le même paramètre avec une valeur différente — leurs valeurs sont écrasées silencieusement.
    Un conflit n'est pas toujours une erreur, mais il indique souvent une GPO oubliée ou une configuration incohérente.
  </div>

  <div class="toolbar">
    <div class="search-box">
      <span class="search-icon">⌕</span>
      <input type="text" placeholder="Rechercher un conflit…" oninput="searchConflicts(this.value)">
    </div>
    <button class="filter-btn on"  onclick="filtConflicts('all',this)">Tous ({{ data.gpo_conflicts|length }})</button>
    <button class="filter-btn"     onclick="filtConflicts('high',this)">Sécurité ({{ data.conflicts_high }})</button>
    <button class="filter-btn"     onclick="filtConflicts('low',this)">Autres ({{ data.conflicts_low }})</button>
  </div>

  <div id="conflicts-list">
  {% for c in data.gpo_conflicts %}
  <div class="finding-card stagger-item conflict-card"
       data-sec="{{ 'true' if c.is_security else 'false' }}"
       data-txt="{{ c.key_short }} {{ c.section_label|lower }} {{ c.label|lower }}">
    <div class="fc-head" onclick="togFC(this)">
      <div class="sev-dot" style="background:{% if c.is_security %}var(--red){% else %}var(--amber){% endif %}"></div>
      <div style="flex:1">
        <div class="fc-title">{{ c.key_short }}</div>
        <div style="font-size:11px;color:var(--txt3);margin-top:1px">
          {{ c.section_label }} · {{ c.gpo_count }} GPO en conflit
          {% if c.enforced_wins %}<span style="color:var(--amber);margin-left:6px">⚑ Enforced prioritaire</span>{% endif %}
        </div>
      </div>
      <span class="sev-pill {% if c.is_security %}critical{% else %}warning{% endif %}" style="margin-right:8px">
        {% if c.is_security %}sécurité{% else %}configuration{% endif %}
      </span>
      <div class="fc-arr">▶</div>
    </div>
    <div class="fc-body">
      <!-- Valeurs en conflit -->
      <div style="margin-bottom:12px">
        <div style="font-size:11px;font-weight:600;color:var(--txt3);text-transform:uppercase;letter-spacing:.4px;margin-bottom:8px">Valeurs en conflit</div>
        <div style="display:flex;flex-wrap:wrap;gap:8px">
          {% for v in c.conflict_values %}
          <span style="font-size:12px;padding:4px 10px;border-radius:6px;font-family:'JetBrains Mono',monospace;
                       background:{% if v == c.winner.value %}var(--green-dim){% else %}var(--red-dim){% endif %};
                       color:{% if v == c.winner.value %}var(--green){% else %}var(--red){% endif %};
                       border:1px solid {% if v == c.winner.value %}var(--green){% else %}var(--red){% endif %}">
            {% if v == c.winner.value %}✔ {{ v }} (appliquée){% else %}✘ {{ v }} (écrasée){% endif %}
          </span>
          {% endfor %}
        </div>
      </div>

      <!-- GPO gagnante -->
      <div style="margin-bottom:8px">
        <div style="font-size:11px;font-weight:600;color:var(--txt3);text-transform:uppercase;letter-spacing:.4px;margin-bottom:6px">GPO gagnante</div>
        <div style="display:flex;align-items:center;gap:8px;padding:8px 12px;background:var(--green-dim);border-radius:2px;border:1px solid var(--green)">
          <span style="color:var(--green)">✔</span>
          <span style="font-size:13px;font-weight:500;cursor:pointer;color:var(--green)" onclick="showGPODetail('{{ c.winner.gpo_guid }}')">{{ c.winner.gpo_name }}</span>
          <span style="font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--txt2);margin-left:4px">= {{ c.winner.value }}</span>
          {% if c.winner.enforced %}<span style="font-size:10px;padding:1px 6px;border-radius:4px;background:var(--amber-dim);color:var(--amber)">ENFORCED</span>{% endif %}
        </div>
      </div>

      <!-- GPO perdantes -->
      <div style="margin-bottom:10px">
        <div style="font-size:11px;font-weight:600;color:var(--txt3);text-transform:uppercase;letter-spacing:.4px;margin-bottom:6px">GPO perdante(s) — valeur écrasée</div>
        {% for loser in c.losers %}
        <div style="display:flex;align-items:center;gap:8px;padding:7px 12px;background:var(--red-dim);border-radius:2px;border:1px solid var(--red);margin-bottom:4px">
          <span style="color:var(--red)">✘</span>
          <span style="font-size:13px;font-weight:500;cursor:pointer;color:var(--red)" onclick="showGPODetail('{{ loser.gpo_guid }}')">{{ loser.gpo_name }}</span>
          <span style="font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--txt2);margin-left:4px">= {{ loser.value }}</span>
          {% if loser.enforced %}<span style="font-size:10px;padding:1px 6px;border-radius:4px;background:var(--amber-dim);color:var(--amber)">ENFORCED</span>{% endif %}
        </div>
        {% endfor %}
      </div>

      <!-- Chemin complet -->
      <div style="font-size:11px;color:var(--txt3);font-family:'JetBrains Mono',monospace;padding:6px 0;border-top:1px solid var(--border)">
        {{ c.section_label }} → {{ c.key }}
      </div>

      <!-- Recommandation -->
      <div class="fc-reco" style="margin-top:8px">
        {% if c.is_security %}
        ⚠ Paramètre de sécurité sensible — vérifiez que la valeur appliquée ({{ c.winner.value }}, GPO "{{ c.winner.gpo_name }}") est bien celle souhaitée.
        Supprimez ce paramètre de la/les GPO perdante(s) pour éliminer l'ambiguïté.
        {% else %}
        Vérifiez si la valeur dans la GPO perdante est intentionnelle.
        Si non, supprimez-la pour éviter toute confusion lors d'une future modification de priorité GPO.
        {% endif %}
        {% if c.enforced_wins %}
        La GPO gagnante est Enforced — elle s'applique en priorité absolue quelle que soit la hiérarchie OU.
        {% endif %}
      </div>
    </div>
  </div>
  {% endfor %}
  </div>

  {% else %}
  <div style="text-align:center;padding:60px;color:var(--txt3)">
    🎉 Aucun conflit GPO détecté — vos GPO sont cohérentes entre elles.
  </div>
  {% endif %}
</div>

<!-- ══ ORPHANS ══ -->
<div id="view-orphans" class="view">
  <div class="view-header">
    <div class="view-title">GPO orphelines & redondances</div>
    <div class="view-sub">GPO non liées et paramètres définis dans plusieurs GPO</div>
  </div>
  {% if data.orphan_gpos %}
  <div class="stitle">GPO non liées ({{ data.orphan_gpos|length }})</div>
  {% for name in data.orphan_gpos %}
  <div class="warn-box"><strong style="color:var(--amber)">◌ {{ name }}</strong> — Non liée à aucune OU. À supprimer ou archiver.</div>
  {% endfor %}
  {% endif %}
  {% if data.redundant_params %}
  <div class="stitle" style="margin-top:20px">Paramètres définis dans plusieurs GPO</div>
  {% for key, names in data.redundant_params.items() %}
  <div class="ou-card">
    <div class="ou-head" onclick="this.nextElementSibling.classList.toggle('open')">
      <span style="color:var(--amber)">⚠</span>
      <span style="flex:1;font-size:12px;font-family:'JetBrains Mono',monospace">{{ key }}</span>
      <span style="font-size:11px;color:var(--txt3)">{{ names|length }} GPO ▶</span>
    </div>
    <div class="ou-body" style="font-size:12px;color:var(--txt2)">{{ names|join(', ') }}</div>
  </div>
  {% endfor %}
  {% endif %}
  <div class="stitle" style="margin-top:20px">Commandes utiles</div>
  <div class="mono-block">
    <span class="mono-comment"># RSOP complet sur un poste</span><br>
    gpresult /H C:\rsop.html /F<br><br>
    <span class="mono-comment"># Vérifier SMBv1</span><br>
    Get-SmbServerConfiguration | Select EnableSMB1Protocol<br><br>
    <span class="mono-comment"># Vérifier WDigest</span><br>
    Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest<br><br>
    <span class="mono-comment"># Vérifier LocalAccountTokenFilterPolicy</span><br>
    Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
  </div>
</div>

</main>

<!-- Data -->
<script id="gpo-json" type="application/json">{{ data.gpo_reports | tojson }}</script>

<script>
// ── Init ──────────────────────────────────────────────────────────────────
let _gpos = [];
const CAT_ICONS={'sécurité':'🔒','imprimantes':'🖨','lecteurs':'💾','raccourcis':'🔗','tâches':'⏰','scripts':'📜','groupes':'👥','vars env':'⚙','services':'🔧','audit avancé':'🔍','registre XML':'📋','fichiers':'📁','reg.machine':'🗝','reg.user':'🗝'};

window.addEventListener('DOMContentLoaded', () => {
  // Restaurer thème en premier — évite le flash de thème incorrect
  const saved = localStorage.getItem('gpo-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);

  try { _gpos = JSON.parse(document.getElementById('gpo-json').textContent); } catch(e){}

  // Rendu immédiat : dashboard uniquement (ce que l'utilisateur voit en premier)
  renderCharts();
  renderCatGrid();
  renderDashPriorities();
  triggerStagger();

  // Masquer le loader dès que le dashboard est prêt
  requestAnimationFrame(() => {
    document.getElementById('loader').classList.add('done');
    setTimeout(() => {
      const l = document.getElementById('loader');
      if (l) l.remove();
    }, 400);
  });

  // Différer les rendus lourds — exécutés quand le navigateur est idle
  const _idle = typeof requestIdleCallback !== 'undefined'
    ? requestIdleCallback
    : (fn) => setTimeout(fn, 100);

  _idle(() => {
    renderPriorities();
    renderGPOList(_gpos);
  });
  _idle(() => {
    renderByType();
    renderByOU('');
    populateCompareSelects();
  });
});

function triggerStagger() {
  const items = document.querySelectorAll('.stagger-item');
  items.forEach((el, i) => {
    setTimeout(() => el.classList.add('visible'), 50 + i * 40);
  });
}

// ── Theme ──
function toggleTheme() {
  const cur = document.documentElement.getAttribute('data-theme');
  const next = cur === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('gpo-theme', next);
  // Redessiner les charts avec les nouvelles couleurs
  setTimeout(renderCharts, 100);
}

// ── Navigation ──
// Suivi des vues déjà initialisées (évite double-rendu)
const _viewsReady = new Set(['dashboard']);

function nav(id, el) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('view-' + id).classList.add('active');
  if (el) el.classList.add('active');

  // Rendu lazy : initialiser la vue seulement à la première visite
  if (!_viewsReady.has(id)) {
    _viewsReady.add(id);
    if (id === 'gpolist')     renderGPOList(_gpos);
    if (id === 'bytype')      renderByType();
    if (id === 'byou')        renderByOU('');
    if (id === 'priorities')  renderPriorities();
  }

  // Ré-animer les stagger items
  setTimeout(() => {
    document.querySelectorAll('#view-' + id + ' .stagger-item').forEach((el, i) => {
      el.classList.remove('visible');
      setTimeout(() => el.classList.add('visible'), 30 + i * 35);
    });
  }, 50);
}

// ── Charts ──
let _charts = {};
function renderCharts() {
  const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
  const gridColor = isDark ? 'rgba(255,255,255,0.07)' : 'rgba(0,0,0,0.07)';
  const tickColor = isDark ? '#7a84a8' : '#5a6285';

  // Donut
  const dCtx = document.getElementById('chart-donut');
  if (dCtx) {
    if (_charts.donut) _charts.donut.destroy();
    const criticals = parseInt('{{ data.criticals }}');
    const warnings = parseInt('{{ data.warnings }}');
    const infos = parseInt('{{ data.infos }}');
    const compliant = parseInt('{{ data.compliant_count }}');
    _charts.donut = new Chart(dCtx, {
      type: 'doughnut',
      data: {
        labels: ['Critiques', 'Avertissements', 'Informatifs', 'Conformes'],
        datasets: [{
          data: [criticals, warnings, infos, compliant],
          backgroundColor: [
            isDark ? '#ff5f5f' : '#d63c3c',
            isDark ? '#ffaa40' : '#c47a00',
            isDark ? '#5b9ef9' : '#2460c4',
            isDark ? '#3dd68c' : '#1a7a50',
          ],
          borderWidth: 0,
          hoverOffset: 6,
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false, cutout: '65%',
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: {
            label: ctx => ` ${ctx.label} : ${ctx.parsed}`
          }}
        }
      }
    });
  }

  // Radar par catégorie
  const rCtx = document.getElementById('chart-radar');
  if (rCtx) {
    if (_charts.radar) _charts.radar.destroy();
    const cats = {'Mots de passe':0,'Authentification':0,'Audit':0,'UAC':0,'Système':0,'Accès':0};
    const maxes = {'Mots de passe':6,'Authentification':7,'Audit':7,'UAC':4,'Système':6,'Accès':4};
    // Calculer les scores par catégorie depuis les findings
    document.querySelectorAll('.finding-card[data-sev]').forEach(c => {
      const txt = c.dataset.txt || '';
      if (txt.includes('mot de passe') || txt.includes('password')) cats['Mots de passe']++;
      else if (txt.includes('authentif') || txt.includes('ntlm') || txt.includes('ldap') || txt.includes('smb')) cats['Authentification']++;
      else if (txt.includes('audit') || txt.includes('journal') || txt.includes('log')) cats['Audit']++;
      else if (txt.includes('uac') || txt.includes('élévation') || txt.includes('token')) cats['UAC']++;
      else if (txt.includes('système') || txt.includes('service') || txt.includes('pare-feu') || txt.includes('wdigest') || txt.includes('print')) cats['Système']++;
      else cats['Accès']++;
    });
    const labels = Object.keys(cats);
    const scores = labels.map(l => Math.max(0, Math.round((1 - cats[l] / (maxes[l]||1)) * 100)));
    _charts.radar = new Chart(rCtx, {
      type: 'radar',
      data: {
        labels,
        datasets: [{
          data: scores,
          backgroundColor: isDark ? 'rgba(91,158,249,0.15)' : 'rgba(36,96,196,0.12)',
          borderColor: isDark ? '#5b9ef9' : '#2460c4',
          borderWidth: 2, pointBackgroundColor: isDark ? '#5b9ef9' : '#2460c4',
          pointRadius: 3,
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        scales: {
          r: {
            min: 0, max: 100,
            grid: { color: gridColor },
            ticks: { color: tickColor, backdropColor: 'transparent', stepSize: 25, font: { size: 10 } },
            pointLabels: { color: tickColor, font: { size: 11 } }
          }
        },
        plugins: { legend: { display: false } }
      }
    });
  }
}

// ── Category grid ──
function renderCatGrid() {
  const counts = {};
  _gpos.forEach(g => (_gpoContentIndex[g.guid]||[]).forEach(s => {
    const k = s.title.split('—')[0].trim().toLowerCase();
    counts[k] = (counts[k]||0) + 1;
  }));
  const sorted = Object.entries(counts).sort((a,b) => b[1]-a[1]);
  const max = sorted[0]?.[1] || 1;
  document.getElementById('cat-grid').innerHTML = sorted.map(([k,v]) => `
    <div class="cat-card stagger-item" onclick="filtByType('${k}')">
      <div class="cat-icon">${CAT_ICONS[k]||'📄'}</div>
      <div class="cat-name">${k.charAt(0).toUpperCase()+k.slice(1)}</div>
      <div class="cat-count">${v} GPO</div>
      <div class="cat-bar"><div class="cat-fill" style="width:${Math.round(v/max*100)}%"></div></div>
    </div>`).join('');
}

// ── Priorities ──
function _buildPriorityHTML(max) {
  const fl = document.getElementById('findings-list');
  if (!fl) return [];
  const items = [];
  let i = 1;
  ['critical','warning'].forEach(sev => {
    fl.querySelectorAll(`.finding-card[data-sev="${sev}"]`).forEach(c => {
      if (max && i > max) return;
      const t = c.querySelector('.fc-title')?.textContent.replace('non configuré','').trim()||'';
      const d = c.querySelector('.fc-detail')?.textContent||'';
      const r = c.querySelector('.fc-reco')?.textContent||'';
      const ref = c.querySelector('.fc-ref')?.textContent||'';
      items.push({ i: i++, sev, t, d, r, ref });
    });
  });
  return items;
}

function renderPriorities() {
  const items = _buildPriorityHTML(null);
  document.getElementById('priority-list').innerHTML = items.map(p => `
    <div class="prio-item stagger-item" onclick="this.classList.toggle('open')">
      <div class="prio-head">
        <div class="prio-num ${p.sev}">${p.i}</div>
        <div style="flex:1">
          <div class="prio-title">${p.t}</div>
          <div class="prio-ref">${p.ref}</div>
        </div>
        <span class="sev-pill ${p.sev}">${p.sev}</span>
        <span class="prio-arr">▶</span>
      </div>
      <div class="prio-body">
        <div class="prio-detail">${p.d}</div>
        <div class="prio-reco">${p.r}</div>
      </div>
    </div>`).join('') || '<div style="padding:40px;text-align:center;color:var(--txt3)">Aucune action prioritaire 🎉</div>';
}

function renderDashPriorities() {
  const items = _buildPriorityHTML(3);
  document.getElementById('dash-priorities').innerHTML = items.map(p => `
    <div class="prio-item stagger-item" onclick="this.classList.toggle('open')">
      <div class="prio-head">
        <div class="prio-num ${p.sev}">${p.i}</div>
        <div style="flex:1"><div class="prio-title">${p.t}</div></div>
        <span class="sev-pill ${p.sev}">${p.sev}</span>
        <span class="prio-arr">▶</span>
      </div>
      <div class="prio-body">
        <div class="prio-detail">${p.d}</div>
        <div class="prio-reco">${p.r}</div>
      </div>
    </div>`).join('');
}

// ── GPO List ──
let _gpoFilter = 'all', _gpoSearch = '';
function renderGPOList(gpos) {
  const el = document.getElementById('gpo-list-area');
  if (!gpos.length) { el.innerHTML = '<div style="color:var(--txt3);padding:20px">Aucune GPO</div>'; return; }
  const flagsMap = {'1':'user désact.','2':'ordi. désact.','3':'désactivée'};
  el.innerHTML = `<table class="gpo-table"><thead><tr>
    <th>Nom</th><th>Score</th><th>Problèmes</th><th>Liens</th><th>Modifié</th>
  </tr></thead><tbody>` + gpos.map(g => {
    const s = g.score ?? 100;
    const sc = s>=70?'var(--green)':s>=40?'var(--amber)':'var(--red)';
    const f = flagsMap[String(g.flags)] ? `<span class="flag flag-disabled">${flagsMap[String(g.flags)]}</span>` : '';
    const o = g.is_orphan ? '<span class="flag flag-orphan">orpheline</span>' : '';
    const issues = g.findings?.length||0;
    const issHtml = issues ? `<span style="color:var(--amber)">${issues} problème(s)</span>` : `<span style="color:var(--txt3)">—</span>`;
    return `<tr onclick="showGPODetail('${g.guid}')">
      <td><span style="font-weight:500">${g.name}</span>${f}${o}</td>
      <td><div class="score-bar-wrap">
        <div class="score-bar"><div class="score-bar-fill" style="width:${s}%;background:${sc}"></div></div>
        <span class="score-num" style="color:${sc}">${s}</span>
      </div></td>
      <td>${issHtml}</td>
      <td style="color:var(--txt3)">${g.link_count||0}</td>
      <td style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--txt3)">${g.changed?g.changed.slice(0,10):'—'}</td>
    </tr>`;
  }).join('') + '</tbody></table>';
}

function filtG(f, btn) {
  _gpoFilter = f;
  document.querySelectorAll('#view-gpolist .filter-btn').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on');
  applyGPOFilter();
}
function searchGPO(q) { _gpoSearch = q.toLowerCase(); applyGPOFilter(); }
function applyGPOFilter() {
  let g = _gpos;
  if (_gpoSearch) g = g.filter(x => x.name.toLowerCase().includes(_gpoSearch));
  if (_gpoFilter==='issues') g = g.filter(x => x.findings?.length);
  if (_gpoFilter==='empty') g = g.filter(x => !x.has_content);
  if (_gpoFilter==='orphan') g = g.filter(x => x.is_orphan);
  renderGPOList(g);
}

// ── GPO Detail ──
function showGPODetail(guid) {
  const g = _gpos.find(x => x.guid===guid);
  if (!g) return;
  nav('gpodetail', null);
  const flagsMap = {'1':'config. utilisateur désactivée','2':'config. ordinateur désactivée','3':'entièrement désactivée'};
  let html = `<div class="gpo-detail-card">
    <h3>${g.name}</h3>
    <div class="gpo-meta-grid" style="margin-top:8px">
      <span><span>GUID</span>${g.guid}</span>
      <span><span>Liens</span>${g.link_count||0}</span>
      <span><span>Modifié</span>${g.changed?g.changed.slice(0,10):'—'}</span>
      ${flagsMap[String(g.flags)]?`<span style="color:var(--amber)">${flagsMap[String(g.flags)]}</span>`:''}
      ${g.is_orphan?'<span style="color:var(--blue)">Non liée à une OU</span>':''}
    </div>
  </div>`;

  if (g.findings?.length) {
    html += `<div class="stitle" style="color:var(--amber)">Problèmes détectés dans cette GPO</div>`;
    g.findings.forEach(f => {
      html += `<div class="finding-card"><div class="fc-head" onclick="togFC(this)">
        <div class="sev-dot ${f.severity}"></div>
        <div style="flex:1"><div class="fc-title">${f.title}</div></div>
        <span class="sev-pill ${f.severity}" style="margin-right:8px">${f.severity}</span>
        <div class="fc-arr">▶</div>
      </div><div class="fc-body">
        <div class="fc-detail">${f.detail}</div>
        <div class="fc-reco">${f.remediation}</div>
      </div></div>`;
    });
  }

  if (g.links?.length) {
    html += `<div class="stitle">Appliquée sur</div>`;
    g.links.slice(0, 10).forEach(l => {
      html += `<div style="font-size:12px;color:var(--txt2);font-family:'JetBrains Mono',monospace;padding:5px 0;border-bottom:1px solid var(--border)">${l.ou}${l.enforced?'<span style="color:var(--amber);margin-left:8px;font-size:10px">ENFORCED</span>':''}</div>`;
    });
    if (g.links.length > 10) html += `<div style="font-size:11px;color:var(--txt3);padding:4px 0">... et ${g.links.length-10} autres</div>`;
  }

  if (g.has_content) {
    html += `<div class="stitle">Paramètres configurés</div>`;
    const _gContent = _gpoContentIndex[g.guid] || [];
    _gContent.forEach(sec => {
      if (!sec.params?.length) return;
      html += `<div class="section-block">
        <div class="section-head" onclick="togSec(this)">
          <span class="section-icon">${sec.icon||'📄'}</span>
          <span class="section-title">${sec.title}</span>
          <span class="section-count">${sec.params.length} param.</span>
          <span class="section-arr">▶</span>
        </div>
        <div class="section-body">
          <table class="param-table">${sec.params.map(p=>`<tr>
            <td>${p.label||p.key}</td>
            <td>
              <span class="${p.alert?'param-bad':''}">${p.value||''}</span>
              ${p.hint?`<span style="color:var(--txt3);font-size:11px;margin-left:4px">(${p.hint})</span>`:''}
              ${p.alert?`<span class="param-alert-badge has-tooltip">${p.alert}<span class="tooltip">${p.alert}</span></span>`:''}
            </td>
          </tr>`).join('')}</table>
        </div>
      </div>`;
    });
  } else {
    html += `<div style="color:var(--txt3);padding:20px 0;font-size:13px">Aucun paramètre lu depuis le SYSVOL pour cette GPO.</div>`;
  }
  document.getElementById('gpo-detail-content').innerHTML = html;
}

// ── By Type ──
function filtByType(type) {
  nav('bytype', document.querySelector('[onclick*=bytype]'));
  setTimeout(() => {
    const el = document.querySelector(`[data-type="${type}"]`);
    if (el) el.scrollIntoView({ behavior:'smooth', block:'start' });
  }, 150);
}
function renderByType() {
  const types = {};
  _gpos.forEach(g => (_gpoContentIndex[g.guid]||[]).forEach(sec => {
    const k = sec.title;
    if (!types[k]) types[k] = { icon: sec.icon, gpos: [] };
    types[k].gpos.push(g);
  }));
  document.getElementById('bytype-content').innerHTML =
    Object.entries(types).sort((a,b)=>b[1].gpos.length-a[1].gpos.length).map(([title,{icon,gpos}]) => `
      <div class="type-section" data-type="${title.split('—')[0].trim().toLowerCase()}">
        <div class="type-header">
          <span style="font-size:20px">${icon||'📄'}</span>
          <span style="font-size:15px;font-weight:600">${title}</span>
          <span style="font-size:12px;color:var(--txt2);margin-left:auto">${gpos.length} GPO</span>
        </div>
        <table class="gpo-table"><thead><tr><th>GPO</th><th>Aperçu</th><th>Modifié</th></tr></thead>
        <tbody>${gpos.map(g=>{
          const sec = (_gpoContentIndex[g.guid]||[]).find(s=>s.title===title);
          const preview = sec?.params?.slice(0,3).map(p=>p.key||p.label).join(', ')||'';
          return `<tr onclick="showGPODetail('${g.guid}')">
            <td style="font-weight:500">${g.name}</td>
            <td style="color:var(--txt2);font-size:12px">${preview}${(sec?.params?.length||0)>3?'…':''}</td>
            <td style="font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--txt3)">${g.changed?g.changed.slice(0,10):'—'}</td>
          </tr>`;
        }).join('')}</tbody></table>
      </div>`).join('') || '<div style="color:var(--txt3);padding:20px">Aucun contenu disponible.</div>';
}

// ── By OU ──
function renderByOU(filter) {
  const ous = {};
  _gpos.forEach(g => (g.links||[]).forEach(l => {
    const ou = l.ou||'(racine)';
    if (filter && !ou.toLowerCase().includes(filter)) return;
    if (!ous[ou]) ous[ou] = [];
    ous[ou].push({ name:g.name, guid:g.guid, enforced:l.enforced, disabled:l.disabled });
  }));
  document.getElementById('byou-content').innerHTML =
    Object.entries(ous).sort((a,b)=>b[1].length-a[1].length).map(([ou,gpos]) => `
      <div class="ou-card">
        <div class="ou-head" onclick="togOU(this)">
          <span style="color:var(--teal);font-size:12px">⊢</span>
          <span style="flex:1;font-size:12px;font-family:'JetBrains Mono',monospace">${ou}</span>
          <span style="font-size:11px;color:var(--txt3)">${gpos.length} GPO ▶</span>
        </div>
        <div class="ou-body">${gpos.map(g=>`
          <div class="ou-gpo-row">
            <span style="color:var(--blue);cursor:pointer" onclick="showGPODetail('${g.guid}')">${g.name}</span>
            ${g.enforced?'<span class="flag flag-disabled">enforced</span>':''}
            ${g.disabled?'<span class="flag" style="background:var(--surface3);color:var(--txt2)">lien désactivé</span>':''}
          </div>`).join('')}
        </div>
      </div>`).join('') || '<div style="color:var(--txt3);padding:20px">Aucune OU trouvée.</div>';
}
function searchOU(q) { renderByOU(q.toLowerCase()); }

// ── Conflict filters ──
function filtConflicts(mode, btn) {
  document.querySelectorAll('#view-conflicts .filter-btn').forEach(b => b.classList.remove('on'));
  btn.classList.add('on');
  document.querySelectorAll('.conflict-card').forEach(c => {
    const isSec = c.dataset.sec === 'true';
    let show = true;
    if (mode === 'high') show = isSec;
    if (mode === 'low')  show = !isSec;
    c.style.display = show ? '' : 'none';
  });
}
function searchConflicts(q) {
  q = q.toLowerCase();
  document.querySelectorAll('.conflict-card[data-txt]').forEach(c => {
    c.style.display = (!q || c.dataset.txt.includes(q)) ? '' : 'none';
  });
}

// ── Compare ──
function populateCompareSelects() {}

// ── Quick Panel ──
let _qpSev = 'critical';
const _findingsData    = {{ data.all_findings | tojson }};
const _compliantData   = {{ data.compliant_rules | tojson }};
const _orphanData      = {{ data.orphan_gpos | tojson }};
const _duplicatesData  = {{ data.true_duplicates | tojson }};
const _conflictsData   = {{ data.gpo_conflicts | tojson }};
const _searchIndex     = {{ data.search_index | tojson }};
const _gpoContentIndex = {{ data.gpo_content_index | tojson }};

// Construire search_blob côté client une seule fois (évite de le sérialiser dans le HTML)
_searchIndex.forEach(item => {
  item.search_blob = [item.gpo_name, item.type, item.key, item.value, item.context]
    .filter(Boolean).join(' ').toLowerCase();
});

// ── Moteur de recherche global ──────────────────────────────────────────────
let _searchTypeFilter = 'all';
let _lastQuery = '';

function quickSearch(q) {
  document.getElementById('search-main-input').value = q;
  nav('search', document.querySelector('[onclick*="nav(\'search\'"]') ||
      document.querySelector('.nav-item:nth-child(1)'));
  globalSearch(q);
}

function globalSearch(q) {
  // Ne pas trimmer ici — garder les espaces pour permettre la saisie multi-mots.
  // Le trim se fait uniquement sur les tokens lors du split.
  _lastQuery = q;

  // Sync les deux champs UNIQUEMENT si la valeur est vraiment différente
  // (évite de réinjecter une valeur trimée qui ferait sauter le curseur)
  const mainInput = document.getElementById('search-main-input');
  if (mainInput && document.activeElement !== mainInput && mainInput.value !== q) mainInput.value = q;

  const emptyState  = document.getElementById('search-empty-state');
  const resultsDiv  = document.getElementById('search-results');
  const headerDiv   = document.getElementById('search-results-header');
  const typeFilters = document.getElementById('search-type-filters');

  const qTrimmed = q.trim();

  if (!qTrimmed || qTrimmed.length < 2) {
    emptyState.style.display  = '';
    resultsDiv.innerHTML      = '';
    headerDiv.style.display   = 'none';
    typeFilters.style.display = 'none';
    _searchTypeFilter = 'all';
    return;
  }
  emptyState.style.display = 'none';

  const tokens = qTrimmed.toLowerCase().split(/\s+/).filter(Boolean);

  // ── Logique ET inter-catégories ─────────────────────────────────────────
  // 1 token  : ET dans la même entrée (standard)
  // N tokens : ET au niveau GPO — chaque token doit matcher AU MOINS UNE
  //            entrée dans la GPO, mais pas forcément la même.
  //            Ex: "RDS imprimante" → GPO contenant RDS ET imprimante
  //            (même si c'est dans deux paramètres différents)

  // Étape 1 : entrées qui matchent au moins un token
  const candidates = _searchIndex
    .map(item => {
      const matched = tokens.filter(t => item.search_blob.includes(t));
      return matched.length > 0 ? { ...item, _matched: matched } : null;
    })
    .filter(Boolean);

  // Étape 2 : grouper par GPO, union des tokens couverts
  const byGpo = {};
  candidates.forEach(item => {
    if (!byGpo[item.gpo_guid]) {
      byGpo[item.gpo_guid] = { name: item.gpo_name, guid: item.gpo_guid,
                                items: [], covered: new Set() };
    }
    item._matched.forEach(t => byGpo[item.gpo_guid].covered.add(t));
    byGpo[item.gpo_guid].items.push(item);
  });

  // Étape 3 : ne garder que les GPO couvrant TOUS les tokens
  let gpoGroups = Object.values(byGpo).filter(g =>
    tokens.every(t => g.covered.has(t))
  );

  // Filtre par type
  if (_searchTypeFilter !== 'all') {
    gpoGroups = gpoGroups
      .map(g => ({ ...g, items: g.items.filter(i => i.type === _searchTypeFilter) }))
      .filter(g => g.items.length > 0);
  }

  // Comptage par type (pour les boutons filtres)
  const typeCounts = {};
  gpoGroups.forEach(g => g.items.forEach(item => {
    typeCounts[item.type] = (typeCounts[item.type] || 0) + 1;
  }));

  if (Object.keys(typeCounts).length > 1) {
    typeFilters.style.display = '';
    document.getElementById('search-type-btns').innerHTML =
      Object.entries(typeCounts).sort((a,b) => b[1]-a[1]).map(([type, count]) => {
        const icon = (_searchIndex.find(i => i.type === type) || {}).type_icon || '📄';
        const on = _searchTypeFilter === type ? ' on' : '';
        return `<button class="filter-btn${on}" onclick="setSearchType('${type.replace(/'/g,"\'")}',this)">${icon} ${type} (${count})</button>`;
      }).join('');
  } else {
    typeFilters.style.display = 'none';
  }

  // Header
  const totalItems = gpoGroups.reduce((a, g) => a + g.items.length, 0);
  headerDiv.style.display = '';
  const modeHint = tokens.length > 1
    ? `<span style="font-size:11px;color:var(--teal);margin-left:10px"
           title="Chaque mot doit apparaître quelque part dans la GPO — pas forcément dans le même paramètre">
         ⊕ ET inter-catégories
       </span>`
    : '';
  document.getElementById('search-count').innerHTML =
    `${totalItems} résultat${totalItems !== 1 ? 's' : ''}${modeHint}`;
  document.getElementById('search-gpo-count').textContent =
    `dans ${gpoGroups.length} GPO`;

  if (!gpoGroups.length) {
    const best = tokens
      .map(t => ({ t, n: _searchIndex.filter(i => i.search_blob.includes(t)).length }))
      .sort((a,b) => b.n - a.n)[0];
    const hint = best && best.n > 0
      ? `<div style="font-size:12px;margin-top:8px;color:var(--txt3)">
           "<strong style="color:var(--blue)">${_escHtml(best.t)}</strong>" seul donne ${best.n} résultat${best.n>1?'s':''} —
           aucune GPO ne contient tous les termes ensemble.
         </div>` : '';
    resultsDiv.innerHTML = `
      <div style="text-align:center;padding:40px;color:var(--txt3)">
        <div style="font-size:32px;margin-bottom:12px">🔍</div>
        <div style="font-size:14px">Aucune GPO ne contient "<strong style="color:var(--txt)">${_escHtml(q)}</strong>"</div>
        ${hint}
      </div>`;
    return;
  }

  // Trier par pertinence (le plus d'entrées matchées en premier)
  gpoGroups.sort((a,b) => b.items.length - a.items.length);

  const renderRows = (items) => {
    const shown = items.slice(0, 20);
    const more  = items.length - shown.length;
    const rows  = shown.map(item => {
      return `<tr style="cursor:pointer" onclick="showGPODetail('${item.gpo_guid}')">
        <td style="padding:6px 10px;border-bottom:1px solid var(--border);width:24px;text-align:center;font-size:14px">${item.type_icon}</td>
        <td style="padding:6px 10px;border-bottom:1px solid var(--border);font-size:11px;color:var(--txt3);white-space:nowrap;width:170px">${_highlight(item.type, tokens)}</td>
        <td style="padding:6px 10px;border-bottom:1px solid var(--border);font-size:13px;font-weight:500;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_highlight(item.key, tokens)}</td>
        <td style="padding:6px 10px;border-bottom:1px solid var(--border);font-size:12px;font-family:'JetBrains Mono',monospace;color:var(--txt2);max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_highlight(item.value, tokens)}</td>
        <td style="padding:6px 10px;border-bottom:1px solid var(--border);font-size:11px;color:var(--txt3);max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${_highlight(item.context, tokens)}</td>
      </tr>`;
    }).join('');
    const moreRow = more > 0
      ? `<tr><td colspan="5" style="padding:5px 10px;font-size:11px;color:var(--txt3);font-style:italic">… ${more} entrée${more>1?'s':''} supplémentaire${more>1?'s':''}</td></tr>`
      : '';
    return `<table style="width:100%;border-collapse:collapse"><tbody>${rows}${moreRow}</tbody></table>`;
  };

  resultsDiv.innerHTML = gpoGroups.map(group => {
    // En mode multi-token : séparer les résultats par token pour montrer
    // "pourquoi cette GPO a matché chaque terme"
    const bodyHtml = tokens.length > 1
      ? tokens.map(t => {
          const tItems = group.items.filter(i => i._matched.includes(t));
          if (!tItems.length) return '';
          return `<div style="border-top:1px solid var(--border)">
            <div style="padding:5px 12px;background:var(--surface2);font-size:11px;color:var(--txt3)">
              <mark style="background:rgba(91,158,249,.2);color:var(--blue);border-radius:3px;padding:1px 6px;font-weight:600">${_escHtml(t)}</mark>
              — ${tItems.length} entrée${tItems.length>1?'s':''}
            </div>
            ${renderRows(tItems)}
          </div>`;
        }).join('')
      : `<div style="border-top:1px solid var(--border)">${renderRows(group.items)}</div>`;

    return `
      <div style="background:var(--surface);border:1px solid var(--border);border-radius:3px;margin-bottom:8px;overflow:hidden">
        <div style="display:flex;align-items:center;gap:10px;padding:10px 14px;background:var(--surface2);cursor:pointer"
             onclick="showGPODetail('${group.guid}')">
          <span style="font-size:14px">📄</span>
          <span style="font-size:13px;font-weight:600;flex:1">${_highlight(group.name, tokens)}</span>
          <span style="font-size:11px;color:var(--txt3)">${group.items.length} entrée${group.items.length>1?'s':''}</span>
          <span style="font-size:11px;color:var(--blue)">Ouvrir →</span>
        </div>
        ${bodyHtml}
      </div>`;
  }).join('');
}

function setSearchType(type, btn) {
  _searchTypeFilter = type;
  document.querySelectorAll('#search-type-btns .filter-btn').forEach(b => b.classList.remove('on'));
  document.querySelector('#search-type-filters .filter-btn').classList.remove('on');
  btn.classList.add('on');
  globalSearch(_lastQuery);
}

function filtSearchType(type, btn) {
  _searchTypeFilter = type;
  document.querySelectorAll('#search-type-filters .filter-btn').forEach(b => b.classList.remove('on'));
  btn.classList.add('on');
  globalSearch(_lastQuery);
}

function _escHtml(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function _highlight(text, tokens) {
  if (!text) return '';
  let s = _escHtml(String(text));
  tokens.forEach(t => {
    if (!t) return;
    const re = new RegExp(`(${t.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')})`, 'gi');
    s = s.replace(re, '<mark style="background:rgba(91,158,249,.3);color:var(--txt);border-radius:2px;padding:0 1px">$1</mark>');
  });
  return s;
}

function openQuickPanel(mode) {
  _qpSev = mode;
  const panel   = document.getElementById('quick-panel');
  const titleEl = document.getElementById('qp-title');
  const cnt     = document.getElementById('qp-content');

  // Fermer si on reclique sur le même
  if (panel.style.display === 'block' && panel.dataset.mode === mode) {
    panel.style.display = 'none';
    panel.dataset.mode = '';
    return;
  }
  panel.dataset.mode = mode;

  const labels = {
    critical:  '🔴 Problèmes critiques',
    warning:   '🟡 Avertissements',
    info:      '🔵 Informatifs',
    compliant: '✅ Contrôles conformes',
    orphan:    '◌ GPO orphelines',
    all:       '📋 Toutes les GPO + doublons',
  };
  titleEl.textContent = labels[mode] || mode;

  // ── Findings (critical / warning / info) ──
  if (['critical', 'warning', 'info'].includes(mode)) {
    const findings = _findingsData.filter(f => f.severity === mode);
    if (!findings.length) {
      cnt.innerHTML = '<div style="padding:24px;text-align:center;color:var(--txt3)">Aucune constatation de ce niveau 🎉</div>';
    } else {
      cnt.innerHTML = findings.map((f, i) => {
        const sourceGpos = f.source_gpos || [];
        const actionType = f.action_type || 'create';
        const actionLabel = f.action_label || 'Créer une nouvelle GPO';
        const gpoChips = sourceGpos.map(g =>
          `<span class="qp-gpo-chip" onclick="showGPODetail('${g.guid}')">${g.name}</span>`
        ).join('');
        return `<div class="qp-finding" id="qpf-${mode}-${i}">
          <div class="qp-finding-head">
            <div class="sev-dot ${f.severity}" style="margin-top:4px;flex-shrink:0"></div>
            <div style="flex:1">
              <div class="qp-title">${f.title}</div>
              <div style="font-size:10px;color:var(--txt3);font-family:'JetBrains Mono',monospace;margin-top:2px">${f.ref}</div>
            </div>
            <span class="qp-finding-toggle" onclick="document.getElementById('qpf-${mode}-${i}').classList.toggle('open')">▶</span>
          </div>
          ${actionType === 'modify' ? `
            <div class="qp-action modify">✏ ${actionLabel}</div>
            ${gpoChips ? `<div class="qp-gpo-list">${gpoChips}</div>` : ''}
          ` : `
            <div class="qp-action create">＋ ${actionLabel}</div>
            <div style="font-size:11px;color:var(--txt3);margin-top:4px">Ce paramètre n'est pas encore configuré dans vos GPO — créez une GPO dédiée</div>
          `}
          <div class="qp-reco">${f.remediation}</div>
        </div>`;
      }).join('');
    }
  }

  // ── Conformes ──
  else if (mode === 'compliant') {
    if (!_compliantData.length) {
      cnt.innerHTML = '<div style="padding:24px;text-align:center;color:var(--txt3)">Aucun contrôle conforme détecté</div>';
    } else {
      cnt.innerHTML = _compliantData.map(r => `
        <div class="qp-finding">
          <div class="qp-finding-head">
            <div class="sev-dot" style="background:var(--green);margin-top:4px;flex-shrink:0"></div>
            <div style="flex:1">
              <div class="qp-title">${r.title}</div>
              <div style="font-size:10px;color:var(--txt3);font-family:'JetBrains Mono',monospace;margin-top:2px">${r.ref} · ${r.category}</div>
            </div>
            <span style="font-size:11px;padding:2px 8px;border-radius:2px;background:var(--green-dim);color:var(--green)">✓ OK</span>
          </div>
        </div>`).join('');
    }
  }

  // ── Orphelines ──
  else if (mode === 'orphan') {
    if (!_orphanData.length) {
      cnt.innerHTML = '<div style="padding:24px;text-align:center;color:var(--txt3)">Aucune GPO orpheline 🎉</div>';
    } else {
      cnt.innerHTML = `
        <div style="padding:10px 18px;background:var(--amber-dim);border-bottom:1px solid var(--border);font-size:12px;color:var(--amber)">
          Ces GPO ne sont liées à aucune OU — elles ne s'appliquent à personne. À supprimer ou archiver.
        </div>` +
        _orphanData.map(name => `
        <div class="qp-finding" style="display:flex;align-items:center;gap:12px">
          <span style="color:var(--amber)">◌</span>
          <span style="flex:1;font-size:13px;font-weight:500">${name}</span>
          <span style="font-size:11px;color:var(--txt3)">Non liée</span>
        </div>`).join('');
    }
  }

  // ── Toutes les GPO + doublons ──
  else if (mode === 'all') {
    const dupHtml = _duplicatesData.length ? `
      <div style="padding:12px 18px;background:var(--amber-dim);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px">
        <span style="font-size:16px">⚠</span>
        <div>
          <div style="font-size:13px;font-weight:600;color:var(--amber)">${_duplicatesData.length} paramètre(s) redondants détectés</div>
          <div style="font-size:12px;color:var(--txt2);margin-top:1px">Même paramètre, même valeur dans 2+ GPO — peut être simplifié</div>
        </div>
      </div>` +
      _duplicatesData.slice(0, 25).map((d, i) => {
        const chips = d.gpos.map(n => {
          const g = _gpos.find(x => x.name === n);
          return `<span class="qp-gpo-chip" ${g ? `onclick="showGPODetail('${g.guid}')" title="Ouvrir ${n}"` : ''}>${n}</span>`;
        }).join('');
        return `<div class="qp-finding" id="qpd-${i}">
          <div class="qp-finding-head" onclick="document.getElementById('qpd-${i}').classList.toggle('open')" style="cursor:pointer">
            <div style="width:28px;height:28px;border-radius:50%;background:var(--amber-dim);display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:var(--amber);flex-shrink:0">${d.gpos.length}</div>
            <div style="flex:1;min-width:0">
              <div style="font-size:12px;font-weight:500;font-family:'JetBrains Mono',monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${d.key}</div>
              <div style="font-size:11px;color:var(--txt3);margin-top:1px">valeur : ${d.value} · ${d.section}</div>
            </div>
            <span class="qp-finding-toggle">▶</span>
          </div>
          <div class="qp-reco">
            <div style="font-size:12px;color:var(--txt2);margin-bottom:8px">Présent dans <strong style="color:var(--txt)">${d.gpos.length} GPO</strong> avec la même valeur :</div>
            <div class="qp-gpo-list">${chips}</div>
            <div style="margin-top:10px;padding:7px 10px;background:var(--amber-dim);border-radius:6px;font-size:12px;color:var(--amber)">
              → Conserver dans la GPO de priorité la plus haute, supprimer des autres.
            </div>
          </div>
        </div>`;
      }).join('') +
      (_duplicatesData.length > 25 ? `<div style="padding:10px 18px;font-size:12px;color:var(--txt3)">... et ${_duplicatesData.length - 25} autres doublons</div>` : '')
    : '<div style="padding:12px 18px;background:var(--green-dim);border-bottom:1px solid var(--border);font-size:12px;color:var(--green)">✓ Aucun paramètre redondant détecté</div>';

    const gpoListHtml = _gpos.slice(0, 30).map(g => {
      const s = g.score ?? 100;
      const sc = s>=70?'var(--green)':s>=40?'var(--amber)':'var(--red)';
      const issues = g.findings?.length || 0;
      return `<div class="qp-finding" style="display:flex;align-items:center;gap:12px;cursor:pointer" onclick="showGPODetail('${g.guid}')">
        <span style="font-size:12px;color:${sc};font-family:'JetBrains Mono',monospace;min-width:28px">${s}</span>
        <span style="flex:1;font-size:13px;font-weight:500">${g.name}</span>
        ${issues ? `<span style="font-size:11px;color:var(--amber)">${issues} pb</span>` : ''}
        ${g.is_orphan ? '<span class="flag flag-orphan">orpheline</span>' : ''}
      </div>`;
    }).join('') + (_gpos.length > 30 ? `<div style="padding:10px 18px;font-size:12px;color:var(--txt3)">... et ${_gpos.length - 30} autres GPO</div>` : '');

    cnt.innerHTML = dupHtml + `<div style="padding:10px 18px;font-size:11px;font-weight:600;color:var(--txt3);text-transform:uppercase;letter-spacing:.5px;border-top:1px solid var(--border)">Toutes les GPO (${_gpos.length})</div>` + gpoListHtml;
  }

  panel.style.display = 'block';
}

// ── Filters ──
function filtF(sev, btn) {
  document.querySelectorAll('#view-findings .filter-btn').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on');
  document.querySelectorAll('.finding-card[data-sev]').forEach(c => {
    c.style.display = (sev==='all' || c.dataset.sev===sev) ? '' : 'none';
  });
}
function searchFindings(q) {
  q = q.toLowerCase();
  document.querySelectorAll('.finding-card[data-txt]').forEach(c => {
    c.style.display = (!q || c.dataset.txt.includes(q)) ? '' : 'none';
  });
}

// ── Toggle helpers ──
function togFC(hdr) {
  const b = hdr.nextElementSibling, a = hdr.querySelector('.fc-arr');
  b.classList.toggle('open'); a.classList.toggle('open');
}
function togSec(hdr) {
  const b = hdr.nextElementSibling, a = hdr.querySelector('.section-arr');
  b.classList.toggle('open'); a.classList.toggle('open');
}
function togOU(hdr) { hdr.nextElementSibling.classList.toggle('open'); }
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
