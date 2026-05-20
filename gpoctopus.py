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

# ─── Règles d'audit ─────────────────────────────────────────────────────────
# Structure étendue :
#   "ref"           : références exactes CIS / ANSSI / MS Baseline
#   "rec_value"     : valeur recommandée (affichée dans la remédiation)
#   "absent_sev"    : sévérité si le paramètre est absent des GPO
#                     None = ignorer si absent (valeur par défaut Windows acceptable)
#                     "critical"/"warning"/"info" = remonter même si absent
#   "default_ok"    : True si la valeur par défaut Windows est sûre (pas de finding si absent)

AUDIT_RULES = [
    # ══ MOTS DE PASSE ══════════════════════════════════════════════════════════
    {
        "id": "PWD-001",
        "title": "Longueur minimale du mot de passe insuffisante",
        "severity": "critical",
        "absent_sev": "warning",    # Défaut Windows = 7 chars — insuffisant
        "ref": "CIS 1.1.1 · ANSSI R-03 · MS Baseline v22H2",
        "rec_value": "≥ 14 caractères (CIS), ≥ 12 (ANSSI), ≥ 14 (MS Baseline)",
        "category": "Mots de passe",
        "check_key": "minimumpasswordlength",
        "section": "password_policy",
        "threshold": 14,
        "operator": "lt",
        "detail_ok": "Longueur minimale correctement configurée (≥ 14 caractères)",
        "remediation": "Valeur recommandée : ≥ 14 caractères\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies de compte\n                  └─ Stratégie de mot de passe\n                      └─ Longueur minimale du mot de passe → 14 (ou plus)\n\n⚠ S'applique uniquement à la Default Domain Policy pour les comptes du domaine.\nLes comptes locaux sont gérés par la stratégie locale de chaque machine.",
    },
    {
        "id": "PWD-002",
        "title": "Historique des mots de passe trop court",
        "severity": "critical",
        "absent_sev": "warning",    # Défaut Windows = 0 — aucun historique
        "ref": "CIS 1.1.2 · ANSSI R-03 · MS Baseline v22H2",
        "rec_value": "≥ 24 entrées (CIS/MS), ≥ 12 (ANSSI)",
        "category": "Mots de passe",
        "check_key": "passwordhistorysize",
        "section": "password_policy",
        "threshold": 24,
        "operator": "lt",
        "detail_ok": "Historique des mots de passe correct (≥ 24)",
        "remediation": "Valeur recommandée : ≥ 24\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies de compte\n                  └─ Stratégie de mot de passe\n                      └─ Conserver l'historique des mots de passe → 24\n\n⚠ Doit être combiné avec MinimumPasswordAge ≥ 1 jour pour être efficace.",
    },
    {
        "id": "PWD-003",
        "title": "Complexité du mot de passe désactivée",
        "severity": "critical",
        "absent_sev": "warning",    # Défaut Windows = désactivé sur les postes de travail
        "ref": "CIS 1.1.5 · ANSSI R-03 · MS Baseline v22H2",
        "rec_value": "Activé (= 1)",
        "category": "Mots de passe",
        "check_key": "passwordcomplexity",
        "section": "password_policy",
        "threshold": 1,
        "operator": "ne",
        "detail_ok": "Complexité du mot de passe activée",
        "remediation": "Valeur recommandée : Activé\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies de compte\n                  └─ Stratégie de mot de passe\n                      └─ Le mot de passe doit respecter des exigences de complexité → Activé\n\nExige que le mot de passe contienne des caractères de 3 catégories parmi :\nmajuscules, minuscules, chiffres, caractères spéciaux — et ne contienne pas le nom de compte.",
    },
    {
        "id": "PWD-004",
        "title": "Durée maximale du mot de passe excessive ou illimitée",
        "severity": "warning",
        "absent_sev": None,         # Défaut Windows = 42 jours — acceptable
        "ref": "CIS 1.1.3 · ANSSI R-03",
        "rec_value": "Entre 60 et 365 jours (CIS recommande ≤ 365, ANSSI ≤ 90)",
        "category": "Mots de passe",
        "check_key": "maximumpasswordage",
        "section": "password_policy",
        "threshold": 365,
        "operator": "gt_or_zero",
        "detail_ok": "Durée maximale du mot de passe dans les limites recommandées",
        "remediation": "Valeur recommandée : Entre 60 et 365 jours (ANSSI recommande 90 jours)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies de compte\n                  └─ Stratégie de mot de passe\n                      └─ Durée de vie maximale du mot de passe → 90 jours\n\n⚠ Valeur 0 = illimité = un mot de passe compromis reste valide indéfiniment.",
    },
    {
        "id": "PWD-006",
        "title": "Durée minimale du mot de passe = 0 (changement immédiat possible)",
        "severity": "warning",
        "absent_sev": None,         # Défaut Windows = 0 — mais sans historique ça ne change rien
        "ref": "CIS 1.1.4 · ANSSI R-03",
        "rec_value": "≥ 1 jour",
        "category": "Mots de passe",
        "check_key": "minimumpasswordage",
        "section": "password_policy",
        "threshold": 1,
        "operator": "lt",
        "detail_ok": "Durée minimale du mot de passe correctement configurée",
        "remediation": "Valeur recommandée : ≥ 1 jour\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies de compte\n                  └─ Stratégie de mot de passe\n                      └─ Durée de vie minimale du mot de passe → 1 jour\n\nSans cette valeur, un utilisateur peut changer son mot de passe 24 fois d'affilée\npour retrouver l'ancien et contourner l'historique.",
    },

    # ══ AUTHENTIFICATION RÉSEAU ════════════════════════════════════════════════
    {
        "id": "AUTH-001",
        "title": "Stockage des hash LAN Manager activé",
        "severity": "critical",
        "absent_sev": "critical",   # Défaut Windows Server 2008+ = 1 (stockage activé sur anciens OS)
        "ref": "CIS 2.3.11.2 · ANSSI R-05 · MS Baseline v22H2",
        "rec_value": "NoLMHash = 1 (ne pas stocker)",
        "category": "Authentification",
        "check_key": "nolmhash",
        "section": "system_access",
        "threshold": 1,
        "operator": "ne",
        "detail_ok": "Stockage des hash LM désactivé",
        "remediation": "Valeur recommandée : Activé (= 1)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies locales\n                  └─ Options de sécurité\n                      └─ Sécurité réseau : ne pas stocker de valeur de hachage LAN Manager\n                         lors de la prochaine modification du mot de passe → Activé",
    },
    {
        "id": "AUTH-002",
        "title": "NTLMv1 autorisé (LmCompatibilityLevel insuffisant)",
        "severity": "critical",
        "absent_sev": "critical",   # Défaut Windows = 3 — NTLMv2 envoyé mais LM/NTLM acceptés en entrée
        "ref": "CIS 2.3.11.7 · ANSSI R-06 · MS Baseline v22H2",
        "rec_value": "5 = envoyer NTLMv2 uniquement, refuser LM et NTLM",
        "category": "Authentification",
        "check_key": "lmcompatibilitylevel",
        "section": "system_access",
        "threshold": 5,
        "operator": "lt",
        "detail_ok": "Niveau NTLM correctement configuré (NTLMv2 uniquement)",
        "remediation": "Valeur recommandée : 5 (Envoyer uniquement les réponses NTLMv2, refuser LM et NTLM)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies locales\n                  └─ Options de sécurité\n                      └─ Sécurité réseau : niveau d'authentification LAN Manager → 5\n\nNiveaux disponibles :\n  0 = Envoyer réponses LM et NTLM (le pire)\n  3 = Envoyer uniquement NTLMv2 (défaut Windows)\n  5 = Envoyer NTLMv2 uniquement, refuser LM et NTLM en entrée (recommandé)\n\n⚠ Tester avant déploiement — les NAS/photocopieurs anciens peuvent ne supporter que NTLMv1.",
    },
    {
        "id": "AUTH-003",
        "title": "Seuil de verrouillage de compte désactivé ou trop élevé",
        "severity": "warning",
        "absent_sev": "warning",    # Défaut Windows = 0 = pas de verrouillage — brute force illimité
        "ref": "CIS 1.2.1 · ANSSI R-04 · MS Baseline v22H2",
        "rec_value": "Entre 5 et 10 tentatives",
        "category": "Authentification",
        "check_key": "lockoutbadcount",
        "section": "system_access",
        "threshold": 10,
        "operator": "gt_or_zero",
        "detail_ok": "Seuil de verrouillage correctement configuré",
        "remediation": "Valeur recommandée : Entre 5 et 10 tentatives\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies de compte\n                  └─ Stratégie de verrouillage du compte\n                      └─ Seuil de verrouillage du compte → 5 à 10 tentatives\n\n⚠ Valeur 0 = aucun verrouillage = attaque par force brute illimitée possible.",
    },
    {
        "id": "AUTH-004",
        "title": "Durée de verrouillage de compte trop courte",
        "severity": "warning",
        "absent_sev": None,         # Pas pertinent si AUTH-003 n'est pas configuré
        "ref": "CIS 1.2.2 · ANSSI R-04 · MS Baseline v22H2",
        "rec_value": "≥ 15 minutes",
        "category": "Authentification",
        "check_key": "lockoutduration",
        "section": "system_access",
        "threshold": 15,
        "operator": "lt",
        "detail_ok": "Durée de verrouillage correctement configurée",
        "remediation": "Valeur recommandée : ≥ 15 minutes (ou 0 pour verrouillage permanent jusqu'à déblocage admin)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies de compte\n                  └─ Stratégie de verrouillage du compte\n                      └─ Durée du verrouillage du compte → 15 (ou 0 pour manuel)",
    },

    # ══ DROITS & ACCÈS ═════════════════════════════════════════════════════════
    {
        "id": "PRIV-001",
        "title": "Accès réseau anonyme non restreint",
        "severity": "critical",
        "absent_sev": "warning",    # Défaut Windows = 0 — anonymes peuvent énumérer SAM
        "ref": "CIS 2.3.10.2 · ANSSI R-10 · MS Baseline v22H2",
        "rec_value": "1 (restreint) ou 2 (restreint strict)",
        "category": "Droits & Privilèges",
        "check_key": "restrictanonymous",
        "section": "system_access",
        "threshold": 1,
        "operator": "lt",
        "detail_ok": "Accès anonyme correctement restreint",
        "remediation": "Valeur recommandée : 1 (restreint) ou 2 (restreint strict)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies locales\n                  └─ Options de sécurité\n                      └─ Accès réseau : ne pas autoriser l'énumération anonyme des comptes SAM → Activé\n                      └─ Accès réseau : ne pas autoriser l'énumération anonyme des partages et comptes SAM → Activé",
    },
    {
        "id": "PRIV-002",
        "title": "Compte Invité activé",
        "severity": "warning",
        "absent_sev": None,         # Défaut Windows = désactivé — OK
        "ref": "CIS 2.3.1.2 · MS Baseline v22H2",
        "rec_value": "0 (désactivé)",
        "category": "Droits & Privilèges",
        "check_key": "enableguestaccount",
        "section": "system_access",
        "threshold": 0,
        "operator": "ne",
        "detail_ok": "Compte Invité désactivé",
        "remediation": "Valeur recommandée : Désactivé\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies locales\n                  └─ Options de sécurité\n                      └─ Comptes : statut du compte Invité → Désactivé",
    },

    # ══ REGISTRE (Registry.pol) ════════════════════════════════════════════════
    {
        "id": "SYS-001",
        "title": "WDigest activé — mots de passe en clair dans lsass",
        "severity": "critical",
        "absent_sev": None,         # Défaut Win10/Server2016+ = 0 — OK nativement
        "ref": "KB2871997 · ANSSI R-08 · MS Baseline v22H2",
        "rec_value": "UseLogonCredential = 0",
        "category": "Système",
        "check_key": None,
        "section": "registry",
        "reg_key": r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
        "reg_value": "UseLogonCredential",
        "reg_expected": 0,
        "detail_ok": "WDigest désactivé — mots de passe non stockés en clair",
        "remediation": "Valeur recommandée : UseLogonCredential = 0\n\n📍 Chemin GPO — 2 méthodes possibles :\n\nMéthode 1 — Préférences de registre (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Préférences\n      └─ Paramètres Windows\n          └─ Registre → Nouveau → Élément de registre\n              Ruche  : HKEY_LOCAL_MACHINE\n              Chemin : SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\n              Valeur : UseLogonCredential\n              Type   : REG_DWORD\n              Données: 0\n\nMéthode 2 — Modèles d'administration (si le template est disponible) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Modèles d'administration\n          └─ MS Security Guide\n              └─ WDigest Authentication → Désactivé",
    },
    {
        "id": "SYS-002",
        "title": "SMBv1 non désactivé explicitement par GPO",
        "severity": "warning",
        "absent_sev": "warning",    # Défaut variable selon la version de Windows — mieux vaut l'expliciter
        "ref": "MS ADV170012 · ANSSI R-07 · CIS 18.3.3",
        "rec_value": "SMB1 = 0",
        "category": "Système",
        "check_key": None,
        "section": "registry",
        "reg_key": r"HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        "reg_value": "SMB1",
        "reg_expected": 0,
        "detail_ok": "SMBv1 explicitement désactivé par GPO",
        "remediation": "Valeur recommandée : SMB1 = 0\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Préférences\n      └─ Paramètres Windows\n          └─ Registre → Nouveau → Élément de registre\n              Ruche  : HKEY_LOCAL_MACHINE\n              Chemin : SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\n              Valeur : SMB1\n              Type   : REG_DWORD\n              Données: 0\n\nAlternative PowerShell (DC) :\n  Set-SmbServerConfiguration -EnableSMB1Protocol $false\n\n⚠ Vérifier d'abord les équipements legacy (NAS, photocopieurs, scanners réseau) qui\npeuvent dépendre de SMBv1. Utiliser l'audit SMB avant désactivation :\n  Get-SmbSession | Where-Object {$_.Dialect -eq '1.0'}",
    },
    {
        "id": "SYS-003",
        "title": "Pare-feu Windows désactivé par GPO",
        "severity": "critical",
        "absent_sev": None,         # Défaut Windows = activé — OK
        "ref": "CIS 9.1.1 · ANSSI R-11 · MS Baseline v22H2",
        "rec_value": "EnableFirewall = 1",
        "category": "Système",
        "check_key": None,
        "section": "registry",
        "reg_key": r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile",
        "reg_value": "EnableFirewall",
        "reg_expected": 1,
        "detail_ok": "Pare-feu Windows activé par GPO",
        "remediation": "Valeur recommandée : EnableFirewall = 1 (Activé) — ne jamais désactiver\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Pare-feu Windows avec sécurité avancée\n                  └─ Pare-feu Windows avec sécurité avancée\n                      └─ Profil de domaine → État du pare-feu : Activé\n\nPour ajouter des exceptions (ne pas désactiver le pare-feu) :\nConfiguration ordinateur\n  └─ Paramètres de sécurité\n      └─ Pare-feu Windows avec sécurité avancée\n          └─ Règles de trafic entrant → Nouvelle règle",
    },
    {
        "id": "SYS-004",
        "title": "AutoPlay/AutoRun non désactivé par GPO",
        "severity": "warning",
        "absent_sev": "warning",    # Défaut Windows = activé — risque USB
        "ref": "CIS 18.9.8.1 · ANSSI R-14 · MS Baseline v22H2",
        "rec_value": "NoDriveTypeAutoRun = 255 (tous lecteurs)",
        "category": "Système",
        "check_key": None,
        "section": "registry",
        "reg_key": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "reg_value": "NoDriveTypeAutoRun",
        "reg_expected": 255,
        "detail_ok": "AutoRun désactivé sur tous les lecteurs",
        "remediation": "Valeur recommandée : 255 (désactiver sur tous les types de lecteurs)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Modèles d'administration\n          └─ Composants Windows\n              └─ Stratégies de lecture automatique\n                  └─ Désactiver la lecture automatique → Activé → Tous les lecteurs\n\nOu via registre (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Préférences → Registre\n      Ruche  : HKEY_LOCAL_MACHINE\n      Chemin : SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\n      Valeur : NoDriveTypeAutoRun\n      Type   : REG_DWORD\n      Données: 255 (0xFF)",
    },
    {
        "id": "SYS-005",
        "title": "Credential Guard / VBS non configuré par GPO",
        "severity": "info",
        "absent_sev": "info",       # Recommandé mais pas toujours possible (matériel requis)
        "ref": "CIS 18.9.12.1 · ANSSI R-08 · MS Baseline v22H2",
        "rec_value": "EnableVirtualizationBasedSecurity = 1",
        "category": "Système",
        "check_key": None,
        "section": "registry",
        "reg_key": r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard",
        "reg_value": "EnableVirtualizationBasedSecurity",
        "reg_expected": 1,
        "detail_ok": "Credential Guard / VBS activé",
        "remediation": "Valeur recommandée : EnableVirtualizationBasedSecurity = 1\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Modèles d'administration\n          └─ Système\n              └─ Device Guard\n                  └─ Activer la sécurité basée sur la virtualisation → Activé\n                      └─ Sélectionner le niveau de sécurité de la plateforme : Démarrage sécurisé et protection DMA\n\nPrérequis matériels obligatoires :\n  • CPU 64 bits avec virtualisation (Intel VT-x / AMD-V)\n  • UEFI (pas de BIOS legacy)\n  • Secure Boot activé\n  • TPM 2.0\n  • Windows 10/11 ou Server 2016+",
    },

    # ══ AUDIT ══════════════════════════════════════════════════════════════════
    {
        "id": "AUDIT-001",
        "title": "Audit des connexions/déconnexions non configuré",
        "severity": "warning",
        "absent_sev": "warning",    # Sans audit, aucune traçabilité des connexions
        "ref": "CIS 17.5.1 · ANSSI R-09 · MS Baseline v22H2",
        "rec_value": "AuditLogonEvents = 3 (Succès + Échec)",
        "category": "Audit",
        "check_key": "auditlogonevents",
        "section": "event_audit",
        "threshold": 0,
        "operator": "eq",
        "detail_ok": "Audit des connexions activé (Succès + Échec)",
        "remediation": "Valeur recommandée : 3 (Succès + Échec)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies locales\n                  └─ Stratégie d'audit\n                      └─ Auditer les événements de connexion → Succès et Échec\n\nÉvénements générés :\n  4624 — Connexion réussie\n  4625 — Échec de connexion (brute force)\n  4634/4647 — Déconnexion\n  4648 — Connexion avec credentials explicites (pass-the-hash)\n\nPour l'audit avancé (recommandé) :\nConfiguration ordinateur\n  └─ Paramètres Windows → Paramètres de sécurité\n      └─ Configuration avancée de la stratégie d'audit\n          └─ Ouverture/fermeture de session → Auditer l'ouverture de session",
    },
    {
        "id": "AUDIT-002",
        "title": "Audit de la gestion des comptes non configuré",
        "severity": "warning",
        "absent_sev": "warning",
        "ref": "CIS 17.2.1 · ANSSI R-09 · MS Baseline v22H2",
        "rec_value": "AuditAccountManage = 3 (Succès + Échec)",
        "category": "Audit",
        "check_key": "auditaccountmanage",
        "section": "event_audit",
        "threshold": 0,
        "operator": "eq",
        "detail_ok": "Audit de gestion des comptes activé",
        "remediation": "Valeur recommandée : 3 (Succès + Échec)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies locales\n                  └─ Stratégie d'audit\n                      └─ Auditer la gestion des comptes → Succès et Échec\n\nÉvénements générés :\n  4720 — Création d'un compte utilisateur (backdoor potentielle)\n  4732 — Ajout à un groupe (élévation de privilèges)\n  4740 — Verrouillage de compte (attaque brute force)\n  4728 — Ajout au groupe Administrateurs du domaine",
    },
    {
        "id": "AUDIT-003",
        "title": "Audit des modifications de stratégie non configuré",
        "severity": "warning",
        "absent_sev": "warning",
        "ref": "CIS 17.7.1 · ANSSI R-09 · MS Baseline v22H2",
        "rec_value": "AuditPolicyChange = 3 (Succès + Échec)",
        "category": "Audit",
        "check_key": "auditpolicychange",
        "section": "event_audit",
        "threshold": 0,
        "operator": "eq",
        "detail_ok": "Audit des modifications de stratégie activé",
        "remediation": "Valeur recommandée : 3 (Succès + Échec)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies locales\n                  └─ Stratégie d'audit\n                      └─ Auditer les modifications de stratégie → Succès et Échec\n\nÉvénements générés :\n  4719 — Modification de la stratégie d'audit (tentative de désactivation)\n  4704 — Attribution de droits utilisateur\n  4706 — Nouvelle approbation de domaine créée",
    },
    {
        "id": "AUDIT-004",
        "title": "Audit des accès aux objets non configuré",
        "severity": "info",
        "absent_sev": "info",
        "ref": "CIS 17.6.1 · ANSSI R-09",
        "rec_value": "AuditObjectAccess = 3 (Succès + Échec)",
        "category": "Audit",
        "check_key": "auditobjectaccess",
        "section": "event_audit",
        "threshold": 0,
        "operator": "eq",
        "detail_ok": "Audit des accès aux objets activé",
        "remediation": "Valeur recommandée : 3 (Succès + Échec)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies locales\n                  └─ Stratégie d'audit\n                      └─ Auditer l'accès aux objets → Succès et Échec\n\n⚠ Activer l'audit sur les objets individuellement via leurs SACL (liste de contrôle d'accès\nsystème) — sinon aucun événement n'est généré même avec la stratégie activée.\nÉvénements : 4663 (accès fichier), 4657 (modification registre)",
    },
    {
        "id": "AUDIT-005",
        "title": "Audit avancé non prioritaire sur l'audit legacy",
        "severity": "info",
        "absent_sev": None,
        "ref": "CIS 17.1.1 · ANSSI R-09",
        "rec_value": "SCENoApplyLegacyAuditPolicy = 1",
        "category": "Audit",
        "check_key": "scenoapplylegacyauditpolicy",
        "section": "registry_values",
        "threshold": 1,
        "operator": "ne",
        "detail_ok": "Audit avancé prioritaire sur l'audit legacy",
        "remediation": "Valeur recommandée : SCENoApplyLegacyAuditPolicy = 1\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Préférences\n      └─ Paramètres Windows\n          └─ Registre\n              Ruche  : HKEY_LOCAL_MACHINE\n              Chemin : SYSTEM\\CurrentControlSet\\Control\\Lsa\n              Valeur : SCENoApplyLegacyAuditPolicy\n              Type   : REG_DWORD\n              Données: 1\n\nPermet l'utilisation des stratégies d'audit avancées (audit.csv) sans conflit avec les\nparamètres d'audit legacy de la stratégie de sécurité.",
    },
    {
        "id": "AUDIT-006",
        "title": "Audit de l'utilisation des privilèges non configuré",
        "severity": "info",
        "absent_sev": "info",
        "ref": "CIS 17.8.1 · ANSSI R-09",
        "rec_value": "AuditPrivilegeUse = 1 (Succès minimum)",
        "category": "Audit",
        "check_key": "auditprivilegeusse",
        "section": "event_audit",
        "threshold": 0,
        "operator": "eq",
        "detail_ok": "Audit d'utilisation des privilèges activé",
        "remediation": "Valeur recommandée : 1 (Succès minimum)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies locales\n                  └─ Stratégie d'audit\n                      └─ Auditer l'utilisation des privilèges → Succès\n\nDétecte l'utilisation de :\n  SeDebugPrivilege — accès mémoire processus (Mimikatz)\n  SeTakeOwnershipPrivilege — prise de propriété d'objets\n  SeBackupPrivilege — lecture de fichiers sensibles",
    },
    {
        "id": "AUDIT-007",
        "title": "Audit des événements système non configuré",
        "severity": "info",
        "absent_sev": "info",
        "ref": "CIS 17.9.1 · ANSSI R-09",
        "rec_value": "AuditSystemEvents = 1 (Succès minimum)",
        "category": "Audit",
        "check_key": "auditsystemevents",
        "section": "event_audit",
        "threshold": 0,
        "operator": "eq",
        "detail_ok": "Audit des événements système activé",
        "remediation": "Valeur recommandée : 1 (Succès minimum)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies locales\n                  └─ Stratégie d'audit\n                      └─ Auditer les événements système → Succès\n\nÉvénements générés :\n  4616 — Modification de l'heure système (tentative d'anti-forensics)\n  1102 — Journal d'audit effacé (attaque en cours)\n  4608/4609 — Démarrage/arrêt de Windows",
    },
    {
        "id": "LOG-001",
        "title": "Taille du journal Sécurité insuffisante",
        "severity": "warning",
        "absent_sev": "warning",    # Défaut Windows = 20 Mo — très insuffisant
        "ref": "CIS 18.9.27.1 · ANSSI R-09 · MS Baseline v22H2",
        "rec_value": "≥ 1 048 576 Ko (1 Go) — MS Baseline recommande 4 Go",
        "category": "Audit",
        "check_key": "maximumlogsize",
        "section": "security log",
        "threshold": 1048576,
        "operator": "lt",
        "detail_ok": "Taille du journal Sécurité suffisante",
        "remediation": "Valeur recommandée : ≥ 1 048 576 Ko (1 Go) — MS Baseline recommande 4 Go\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Journal des événements\n                  └─ Taille maximale du journal de sécurité → 1 048 576 (Ko)\n\nConfigurer aussi la politique de rétention :\n  └─ Méthode de conservation du journal de sécurité\n      → Remplacer les événements selon les besoins (recommandé)\n\n⚠ Avec le défaut Windows (20 Mo), un AD actif écrase les événements en quelques heures —\nimpossible de retrouver les traces d'une attaque survenue 24h plus tôt.",
    },

    # ══ KERBEROS ═══════════════════════════════════════════════════════════════
    {
        "id": "KRB-001",
        "title": "Durée de vie des tickets Kerberos trop longue",
        "severity": "warning",
        "absent_sev": None,         # Défaut Windows = 10h — acceptable
        "ref": "CIS 2.3.9.1 · ANSSI R-06 · MS Baseline v22H2",
        "rec_value": "MaxTicketAge ≤ 10 heures",
        "category": "Kerberos",
        "check_key": "maxtickerage",
        "section": "kerberos_policy",
        "threshold": 10,
        "operator": "gt",
        "detail_ok": "Durée de vie des tickets Kerberos correcte",
        "remediation": "Valeur recommandée : ≤ 10 heures\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies de compte\n                  └─ Stratégie Kerberos\n                      └─ Durée de vie maximale du ticket de service → 10 heures",
    },
    {
        "id": "KRB-002",
        "title": "Tolérance d'horloge Kerberos trop élevée",
        "severity": "warning",
        "absent_sev": None,         # Défaut Windows = 5 min — OK
        "ref": "CIS 2.3.9.3 · ANSSI R-06 · MS Baseline v22H2",
        "rec_value": "MaxClockSkew ≤ 5 minutes",
        "category": "Kerberos",
        "check_key": "maxclockskew",
        "section": "kerberos_policy",
        "threshold": 5,
        "operator": "gt",
        "detail_ok": "Tolérance d'horloge Kerberos correcte",
        "remediation": "Valeur recommandée : ≤ 5 minutes\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies de compte\n                  └─ Stratégie Kerberos\n                      └─ Tolérance maximale pour la synchronisation des horloges → 5 minutes\n\n⚠ S'assurer que NTP est correctement configuré sur tous les postes du domaine,\nsinon les authentifications Kerberos échoueront.",
    },
    {
        "id": "KRB-003",
        "title": "Renouvellement des tickets Kerberos trop long",
        "severity": "info",
        "absent_sev": None,         # Défaut Windows = 7 jours — acceptable
        "ref": "CIS 2.3.9.2 · ANSSI R-06",
        "rec_value": "MaxRenewAge ≤ 7 jours",
        "category": "Kerberos",
        "check_key": "maxrenewage",
        "section": "kerberos_policy",
        "threshold": 7,
        "operator": "gt",
        "detail_ok": "Durée de renouvellement des tickets Kerberos correcte",
        "remediation": "Valeur recommandée : ≤ 7 jours\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies de compte\n                  └─ Stratégie Kerberos\n                      └─ Durée de vie maximale pour le renouvellement d'un ticket utilisateur → 7 jours",
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
        "remediation": "Valeur recommandée : EnableLUA = 1 (Activé)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies locales\n                  └─ Options de sécurité\n                      └─ Contrôle de compte d'utilisateur : exécuter tous les administrateurs\n                         en mode d'approbation Administrateur → Activé\n\n⚠ UAC désactivé = tout programme malveillant s'exécute avec les droits SYSTEM sans demande\nde confirmation. C'est l'une des protections les plus fondamentales de Windows.",
    },
    {
        "id": "UAC-002",
        "title": "Admins sans demande de confirmation UAC (ConsentPromptBehaviorAdmin = 0)",
        "severity": "critical",
        "ref": "CIS 2.3.17.2 · ANSSI R-38",
        "category": "UAC & Élévation de privilèges",
        "regval_key": "machine\\software\\microsoft\\windows\\currentversion\\policies\\system\\consentpromptbehavioradmin",
        "bad_val": "4,0",
        "remediation": "Valeur recommandée : 2 (Demander les informations d'identification) ou 5 (Demander confirmation)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies locales\n                  └─ Options de sécurité\n                      └─ Contrôle de compte d'utilisateur : comportement de l'invite d'élévation\n                         pour les administrateurs en mode d'approbation Administrateur\n\nValeurs :\n  0 = Élever sans demander (le pire — CRITIQUE)\n  1 = Demander les credentials sur le bureau sécurisé\n  2 = Demander les credentials (recommandé CIS/ANSSI)\n  5 = Demander confirmation (MS Baseline)",
    },
    {
        "id": "SMB-001",
        "title": "Signature SMB non requise côté client (RequireSecuritySignature = 0)",
        "severity": "warning",
        "ref": "CIS 2.3.8.1 · ANSSI PA-022",
        "category": "Authentification réseau",
        "regval_key": "machine\\system\\currentcontrolset\\services\\lanmanworkstation\\parameters\\requiresecuritysignature",
        "bad_val": "4,0",
        "remediation": "Valeur recommandée : RequireSecuritySignature = 1 (côté client ET serveur)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies locales\n                  └─ Options de sécurité\n                      └─ Serveur réseau Microsoft : communications signées numériquement (toujours)\n                         → Activé\n                      └─ Client réseau Microsoft : communications signées numériquement (toujours)\n                         → Activé\n\n⚠ Tester avant déploiement — les équipements réseau anciens (NAS, imprimantes)\npeuvent ne pas supporter la signature SMB obligatoire.",
    },
    {
        "id": "LDAP-001",
        "title": "Intégrité LDAP client désactivée (LDAPClientIntegrity = 0)",
        "severity": "critical",
        "ref": "CIS 2.3.11.8 · MS ADV190023 · ANSSI R-06",
        "category": "Authentification réseau",
        "regval_key": "machine\\system\\currentcontrolset\\services\\ldap\\ldapclientintegrity",
        "bad_val": "4,0",
        "remediation": "Valeur recommandée : LDAPClientIntegrity = 2 (Signature requise)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies locales\n                  └─ Options de sécurité\n                      └─ Contrôleur de domaine : conditions requises pour la signature du serveur LDAP\n                         → Exiger la signature\n\nNiveaux :\n  0 = Aucune signature (CRITIQUE — LDAP relay possible)\n  1 = Négocier la signature (insuffisant)\n  2 = Exiger la signature (recommandé CIS/MS/ANSSI)",
    },
    {
        "id": "PRINT-001",
        "title": "Installation drivers imprimantes non restreinte aux admins (PrintNightmare)",
        "severity": "critical",
        "ref": "CVE-2021-34527 · MS KB5005010",
        "category": "Services & Composants système",
        "regval_key": "machine\\system\\currentcontrolset\\control\\print\\providers\\lanman print services\\servers\\addprinterdrivers",
        "bad_val": "4,0",
        "remediation": "Valeur recommandée : AddPrinterDrivers = 1 (Administrateurs uniquement)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies locales\n                  └─ Options de sécurité\n                      └─ Périphériques : empêcher les utilisateurs d'installer des pilotes d'imprimantes\n                         → Activé\n\nEt appliquer le patch MS KB5005010 (CVE-2021-34527 — PrintNightmare).\n\nPour Point and Print :\nConfiguration ordinateur\n  └─ Modèles d'administration → Imprimantes\n      └─ Restrictions de Point and Print → Activé\n          └─ Lors de l'installation de pilotes pour une nouvelle connexion : Afficher un avertissement et une élévation",
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
        "remediation": "Valeur recommandée : FilterAdministratorToken = 1 (Activé)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Préférences\n      └─ Paramètres Windows\n          └─ Registre → Nouveau → Élément de registre\n              Ruche  : HKEY_LOCAL_MACHINE\n              Chemin : SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\n              Valeur : FilterAdministratorToken\n              Type   : REG_DWORD\n              Données: 1\n\nApplique le mode approbation administrateur même au compte RID 500 (Administrateur intégré).",
    },
    {
        "id": "UAC-004",
        "title": "Jeton d'accès réseau plein pour les comptes locaux (LocalAccountTokenFilterPolicy = 1)",
        "severity": "critical",
        "ref": "MS KB951016 · ANSSI R-38",
        "category": "UAC & Élévation de privilèges",
        "regval_key": "machine\\software\\microsoft\\windows\\currentversion\\policies\\system\\localaccounttokenfilterpolicy",
        "bad_val": "4,1",
        "remediation": "Valeur recommandée : LocalAccountTokenFilterPolicy = 0\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Préférences\n      └─ Paramètres Windows\n          └─ Registre → Nouveau → Élément de registre\n              Ruche  : HKEY_LOCAL_MACHINE\n              Chemin : SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\n              Valeur : LocalAccountTokenFilterPolicy\n              Type   : REG_DWORD\n              Données: 0\n\nValeur 1 = les comptes locaux admins obtiennent un token élevé via réseau → Pass-the-Hash\nsur tous les postes avec le même mot de passe admin local.\nCombiner avec LAPS pour des mots de passe uniques par machine.",
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
        "remediation": "Valeur recommandée : RestrictSendingNTLMTraffic = 2 (Refuser tout)\nEn phase de déploiement : commencer par 1 (Audit) puis passer à 2\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Modèles d'administration\n          └─ Réseau\n              └─ Sécurité Lanman\n                  └─ Restreindre NTLM : trafic NTLM sortant vers des serveurs distants\n                      → Refuser tout (valeur 2)\n                      → Ou : Auditer tout (valeur 1) pour commencer\n\n⚠ Activer d'abord l'audit pour identifier les applications qui utilisent encore NTLM\navant de bloquer. Consulter le journal d'événements (EventID 8001-8004).",
    },
    {
        "id": "LDAP-002",
        "title": "Intégrité LDAP non au niveau maximum (LDAPClientIntegrity ≠ 2)",
        "severity": "warning",
        "ref": "CIS 2.3.11.8 · MS ADV190023",
        "category": "Authentification réseau",
        "regval_key": "machine\\system\\currentcontrolset\\services\\ldap\\ldapclientintegrity",
        "bad_val": "4,1",
        "remediation": "Valeur recommandée : LDAPClientIntegrity = 2\n\n📍 Même chemin que LDAP-001 — passer directement à la valeur 2 (Exiger la signature)\nplutôt que de rester à 1 (Négocier).",
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
        "remediation": "Valeur recommandée : RunAsPPL = 1 (Processus protégé)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Modèles d'administration\n          └─ Système\n              └─ Local Security Authority\n                  └─ Configurer la protection LSASS → Activé\n                     → Processus protégé avec vérification UEFI : Activé\n\nOu via registre :\nConfiguration ordinateur\n  └─ Préférences → Registre\n      Ruche  : HKEY_LOCAL_MACHINE\n      Chemin : SYSTEM\\CurrentControlSet\\Control\\Lsa\n      Valeur : RunAsPPL\n      Type   : REG_DWORD\n      Données: 1\n\nPrérequis : Secure Boot activé. Protège lsass.exe contre Mimikatz même avec droits admin.",
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
        "remediation": "Valeur recommandée : PasswordExpiryWarning ≥ 14 jours\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Préférences\n      └─ Paramètres Windows\n          └─ Registre → Nouveau → Élément de registre\n              Ruche  : HKEY_LOCAL_MACHINE\n              Chemin : SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\n              Valeur : PasswordExpiryWarning\n              Type   : REG_DWORD\n              Données: 14 (jours)",
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
        "remediation": "Valeur recommandée : EveryoneIncludesAnonymous = 0\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies locales\n                  └─ Options de sécurité\n                      └─ Accès réseau : les autorisations de tout le monde s'appliquent\n                         aux utilisateurs anonymes → Désactivé",
    },
    {
        "id": "ANON-002",
        "title": "Partages accessibles anonymement non restreints",
        "severity": "warning",
        "ref": "CIS 2.3.10.4 · ANSSI R-10",
        "category": "Droits & Accès réseau",
        "regval_key": "machine\\system\\currentcontrolset\\services\\lanmanserver\\parameters\\restrictnullsessaccess",
        "bad_val": "4,0",
        "remediation": "Valeur recommandée : RestrictNullSessAccess = 1 (Restreint)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies locales\n                  └─ Options de sécurité\n                      └─ Accès réseau : restreindre l'accès anonyme aux canaux nommés et aux partages\n                         → Activé",
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
        "remediation": "Valeur recommandée : UserAuthentication = 1 (NLA requis)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Modèles d'administration\n          └─ Composants Windows\n              └─ Services Bureau à distance\n                  └─ Hôte de session Bureau à distance\n                      └─ Sécurité\n                          └─ Exiger l'authentification de l'utilisateur pour les connexions\n                             distantes en utilisant NLA → Activé\n\nNLA exige l'authentification AD avant d'établir la session RDP — empêche l'exploitation\nde vulnérabilités RDP pré-authentification (BlueKeep CVE-2019-0708, DejaBlue).",
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
        "remediation": "Valeur recommandée : EnableScriptBlockLogging = 1 (Activé)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Modèles d'administration\n          └─ Composants Windows\n              └─ Windows PowerShell\n                  └─ Activer la journalisation de bloc de script PowerShell → Activé\n\nActiver aussi la transcription :\n  └─ Activer la transcription PowerShell → Activé\n      └─ Répertoire de sortie de la transcription : \\\\serveur\\logs\\powershell\\\n\nÉvénements générés dans le journal Microsoft-Windows-PowerShell/Operational :\n  4104 — Contenu du script exécuté (détecte Empire, Cobalt Strike, etc.)",
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
        "remediation": "Valeur recommandée : SupportedEncryptionTypes = 2147483644 (AES128 + AES256 uniquement)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies locales\n                  └─ Options de sécurité\n                      └─ Sécurité réseau : configurer les types de chiffrement autorisés pour Kerberos\n                          → Cocher uniquement : AES128_HMAC_SHA1 et AES256_HMAC_SHA1\n\n⚠ Désactiver DES et RC4. Vérifier la compatibilité des comptes de service avant\n(certains services anciens nécessitent RC4 — les identifier via l'attribut msDS-SupportedEncryptionTypes).",
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
    {
        "id": "REGXML-008",
        "title": "Pare-feu Windows désactivé — profil standard/privé",
        "severity": "critical",
        "ref": "CIS 9.2.1 · ANSSI R-11",
        "category": "Services & Composants système",
        "hive_key": "hklm\\software\\policies\\microsoft\\windowsfirewall\\standardprofile",
        "name": "enablefirewall",
        "bad_int": 0,
        "operator": "eq",
        "remediation": (
            "EnableFirewall = 1 pour le profil Standard.\n"
            "Le profil Standard s'applique hors du domaine (WiFi public, télétravail).\n"
            "Le désactiver expose les postes nomades sans aucune protection réseau.\n\n"
            "📍 Chemin GPO :\nConfiguration ordinateur → Préférences → Registre\n"
            "  Ruche : HKEY_LOCAL_MACHINE\n"
            "  Chemin : SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\StandardProfile\n"
            "  Valeur : EnableFirewall = 1"
        ),
    },
    {
        "id": "REGXML-009",
        "title": "Windows Defender désactivé via préférences registre (DisableAntiSpyware = 1)",
        "severity": "critical",
        "ref": "CIS 18.9.47.4 · ANSSI R-13 · MS Baseline v22H2",
        "category": "Services & Composants système",
        "hive_key": "hklm\\software\\policies\\microsoft\\windows defender",
        "name": "disableantispyware",
        "bad_int": 1,
        "operator": "eq",
        "remediation": (
            "DisableAntiSpyware = 0 (ou supprimer la clé).\n"
            "Windows Defender désactivé via GPO = aucune protection antivirus sur le parc.\n"
            "Cette clé est souvent posée par des malwares ou des admins qui déploient un autre AV\n"
            "sans vérifier la désactivation propre de Defender.\n\n"
            "📍 Chemin GPO :\nConfiguration ordinateur → Préférences → Registre\n"
            "  Ruche : HKEY_LOCAL_MACHINE\n"
            "  Chemin : SOFTWARE\\Policies\\Microsoft\\Windows Defender\n"
            "  Valeur : DisableAntiSpyware = 0"
        ),
    },
    {
        "id": "REGXML-010",
        "title": "Protection temps réel Defender désactivée (DisableRealtimeMonitoring = 1)",
        "severity": "critical",
        "ref": "CIS 18.9.47.9 · ANSSI R-13",
        "category": "Services & Composants système",
        "hive_key": "hklm\\software\\policies\\microsoft\\windows defender\\real-time protection",
        "name": "disablerealtimemonitoring",
        "bad_int": 1,
        "operator": "eq",
        "remediation": (
            "DisableRealtimeMonitoring = 0.\n"
            "La protection temps réel est la défense principale de Defender.\n"
            "Sans elle, les fichiers malveillants ne sont pas scannés à l'exécution.\n\n"
            "📍 Chemin GPO :\nConfiguration ordinateur → Préférences → Registre\n"
            "  Ruche : HKEY_LOCAL_MACHINE\n"
            "  Chemin : SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\n"
            "  Valeur : DisableRealtimeMonitoring = 0"
        ),
    },
    {
        "id": "REGXML-011",
        "title": "Surveillance comportementale Defender désactivée",
        "severity": "warning",
        "ref": "CIS 18.9.47.9 · ANSSI R-13",
        "category": "Services & Composants système",
        "hive_key": "hklm\\software\\policies\\microsoft\\windows defender\\real-time protection",
        "name": "disablebehaviormonitoring",
        "bad_int": 1,
        "operator": "eq",
        "remediation": (
            "DisableBehaviorMonitoring = 0.\n"
            "La surveillance comportementale détecte les comportements suspects même sans signature.\n"
            "La désactiver réduit significativement la capacité de détection des menaces avancées.\n\n"
            "📍 Chemin GPO :\nConfiguration ordinateur → Préférences → Registre\n"
            "  Ruche : HKEY_LOCAL_MACHINE\n"
            "  Chemin : SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\n"
            "  Valeur : DisableBehaviorMonitoring = 0"
        ),
    },
    {
        "id": "REGXML-012",
        "title": "NLA (Network Level Auth) RDP désactivé via préférences registre",
        "severity": "critical",
        "ref": "CIS 18.9.65.3.9 · ANSSI R-12 · MS Baseline v22H2",
        "category": "Accès à distance",
        "hive_key": "hklm\\software\\policies\\microsoft\\windows nt\\terminal services",
        "name": "userauthentication",
        "bad_int": 0,
        "operator": "eq",
        "remediation": (
            "UserAuthentication = 1 (NLA requis).\n"
            "NLA force l'authentification AD avant d'établir la session RDP.\n"
            "Sans NLA, les vulnérabilités pré-authentification RDP (BlueKeep CVE-2019-0708) sont exploitables.\n\n"
            "📍 Chemin GPO :\nConfiguration ordinateur → Préférences → Registre\n"
            "  Ruche : HKEY_LOCAL_MACHINE\n"
            "  Chemin : SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\n"
            "  Valeur : UserAuthentication = 1"
        ),
    },
    {
        "id": "REGXML-013",
        "title": "Chiffrement RDP insuffisant via préférences registre (MinEncryptionLevel < 3)",
        "severity": "warning",
        "ref": "CIS 18.9.65.3.3 · ANSSI R-12",
        "category": "Accès à distance",
        "hive_key": "hklm\\software\\policies\\microsoft\\windows nt\\terminal services",
        "name": "minencryptionlevel",
        "bad_int": 3,
        "operator": "lt",
        "remediation": (
            "MinEncryptionLevel = 3 (Élevé) ou 4 (FIPS).\n"
            "Niveaux : 1=Faible, 2=Compatible client, 3=Élevé (recommandé), 4=FIPS.\n\n"
            "📍 Chemin GPO :\nConfiguration ordinateur → Préférences → Registre\n"
            "  Ruche : HKEY_LOCAL_MACHINE\n"
            "  Chemin : SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services\n"
            "  Valeur : MinEncryptionLevel = 3"
        ),
    },
]
AUDIT_RULES_PRIVRIGHTS = [
    {
        "id": "PRIV-R001",
        "title": "SeDebugPrivilege accordé à des comptes non-Administrateurs",
        "severity": "critical",
        "ref": "CIS 2.2.15 · ANSSI R-38",
        "category": "Droits & Privilèges",
        "right_key": "sedebugprivilege",
        "allowed_groups": {"*s-1-5-32-544"},
        "remediation": "Valeur recommandée : SeDebugPrivilege = *S-1-5-32-544 (Administrateurs uniquement)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies locales\n                  └─ Attribution des droits utilisateur\n                      └─ Déboguer les programmes → Administrateurs uniquement\n\n⚠ Retirer tout autre compte ou groupe. Ce droit permet de lire la mémoire de n'importe\nquel processus — Mimikatz l'utilise pour extraire les credentials de lsass.exe.",
    },
    {
        "id": "PRIV-R002",
        "title": "SeTcbPrivilege (Act as part of OS) accordé",
        "severity": "critical",
        "ref": "CIS 2.2.11 · ANSSI R-38",
        "category": "Droits & Privilèges",
        "right_key": "setcbprivilege",
        "empty_only": True,
        "remediation": "Valeur recommandée : SeTcbPrivilege = (vide — aucun compte)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies locales\n                  └─ Attribution des droits utilisateur\n                      └─ Agir comme faisant partie du système d'exploitation → (vide)\n\nCe droit permet à un processus de s'authentifier comme n'importe quel utilisateur.\nAucun compte ne devrait l'avoir dans un environnement sécurisé.",
    },
    {
        "id": "PRIV-R003",
        "title": "SeTakeOwnershipPrivilege accordé au-delà des Admins",
        "severity": "warning",
        "ref": "CIS 2.2.48 · ANSSI R-38",
        "category": "Droits & Privilèges",
        "right_key": "setakeownershipprivilege",
        "allowed_groups": {"*s-1-5-32-544"},
        "remediation": "Valeur recommandée : SeTakeOwnershipPrivilege = *S-1-5-32-544 (Administrateurs)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies locales\n                  └─ Attribution des droits utilisateur\n                      └─ Prendre possession de fichiers ou d'autres objets → Administrateurs uniquement",
    },
    {
        "id": "PRIV-R004",
        "title": "SeBackupPrivilege accordé au-delà des Admins/Backup Operators",
        "severity": "warning",
        "ref": "CIS 2.2.10 · ANSSI R-38",
        "category": "Droits & Privilèges",
        "right_key": "sebackupprivilege",
        "allowed_groups": {"*s-1-5-32-544", "*s-1-5-32-551"},
        "remediation": "Valeur recommandée : SeBackupPrivilege = *S-1-5-32-544, *S-1-5-32-551\n(Administrateurs + Opérateurs de sauvegarde uniquement)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies locales\n                  └─ Attribution des droits utilisateur\n                      └─ Sauvegarder des fichiers et des répertoires\n                          → Administrateurs, Opérateurs de sauvegarde uniquement\n\nCe droit permet de lire tout fichier indépendamment des ACL — utilisé pour exfiltrer\nla ruche SAM et récupérer tous les hashes de mots de passe locaux.",
    },
    {
        "id": "PRIV-R005",
        "title": "SeLoadDriverPrivilege accordé au-delà des Admins",
        "severity": "critical",
        "ref": "CIS 2.2.30 · ANSSI R-38",
        "category": "Droits & Privilèges",
        "right_key": "seloaddriverprivilege",
        "allowed_groups": {"*s-1-5-32-544"},
        "remediation": "Valeur recommandée : SeLoadDriverPrivilege = *S-1-5-32-544 (Administrateurs uniquement)\n\n📍 Chemin GPO (Configuration ordinateur) :\nConfiguration ordinateur\n  └─ Stratégies\n      └─ Paramètres Windows\n          └─ Paramètres de sécurité\n              └─ Stratégies locales\n                  └─ Attribution des droits utilisateur\n                      └─ Charger et décharger les pilotes de périphériques\n                          → Administrateurs uniquement\n\n⚠ Charger un driver malveillant donne un accès Ring 0 (noyau) = contournement total\nde tous les EDR/antivirus. Technique BYOVD (Bring Your Own Vulnerable Driver).",
    },
]


def evaluate_privright_rules(privright_settings: dict) -> list:
    """Évalue les règles Privilege Rights depuis [Privilege Rights] de GptTmpl.inf."""

    # Table de résolution SID → nom lisible (SIDs courants Windows)
    SID_NAMES = {
        's-1-5-32-544':  'Administrateurs',
        's-1-5-32-545':  'Utilisateurs',
        's-1-5-32-546':  'Invités',
        's-1-5-32-547':  'Utilisateurs avec pouvoirs',
        's-1-5-32-548':  'Opérateurs de compte',
        's-1-5-32-549':  'Opérateurs de serveur',
        's-1-5-32-550':  'Opérateurs d\'impression',
        's-1-5-32-551':  'Opérateurs de sauvegarde',
        's-1-5-32-552':  'Réplicateurs',
        's-1-5-32-554':  'Accès compatible pré-Win2000',
        's-1-5-32-555':  'Utilisateurs du Bureau à distance',
        's-1-5-32-556':  'Opérateurs réseau de configuration',
        's-1-5-32-557':  'Créateurs de confiance entrants',
        's-1-5-32-558':  'Utilisateurs du moniteur de performance',
        's-1-5-32-559':  'Utilisateurs du journal des perf.',
        's-1-5-32-560':  'Accès auth. Windows',
        's-1-5-32-561':  'Utilisateurs du journal des événements',
        's-1-5-32-562':  'Accès COM distribué',
        's-1-5-32-569':  'Opérateurs de chiffrement',
        's-1-5-32-573':  'Lecteurs du journal des événements',
        's-1-5-32-574':  'Propriétaires du certificat',
        's-1-5-32-575':  'Utilisateurs de la stratégie RDS',
        's-1-5-32-576':  'Serveurs d\'accès à distance RDS',
        's-1-5-32-577':  'Serveurs de virtualisation RDS',
        's-1-5-32-578':  'Administrateurs Hyper-V',
        's-1-5-32-579':  'Opérateurs d\'accès auth.',
        's-1-5-32-580':  'Utilisateurs DCOM gérés',
        's-1-5-4':       'Service interactif',
        's-1-5-6':       'Service',
        's-1-5-9':       'Contrôleurs de domaine d\'entreprise',
        's-1-5-11':      'Utilisateurs authentifiés',
        's-1-5-18':      'Système local',
        's-1-5-19':      'Service local',
        's-1-5-20':      'Service réseau',
        's-1-5-21':      '(Compte de domaine)',
        's-1-1-0':       'Tout le monde',
        's-1-2-0':       'Local',
        's-1-3-0':       'Créateur propriétaire',
        's-1-5-7':       'Utilisateur anonyme',
    }

    def _resolve_sid(sid_raw: str) -> str:
        """Résout un SID en nom lisible. Format entrée : *S-1-5-32-544 ou S-1-5-32-544"""
        clean = sid_raw.strip().lstrip('*').lower()
        # Tenter une correspondance exacte
        if clean in SID_NAMES:
            return SID_NAMES[clean]
        # Tenter une correspondance de préfixe (comptes de domaine)
        for k, v in SID_NAMES.items():
            if clean.startswith(k + '-') or clean == k:
                return v
        # Retourner le SID brut si non résolu
        return sid_raw.strip().lstrip('*')

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
        detail = ""
        if rule.get("empty_only"):
            if assigned:
                violated = True
                # Résoudre les SIDs pour l'affichage
                names = [_resolve_sid(v) for v in raw.split(',') if v.strip()]
                detail = f"Droit accordé à : {', '.join(names)}"
        elif "allowed_groups" in rule:
            allowed = {g.lower() for g in rule["allowed_groups"]}
            extra = assigned - allowed
            if extra:
                violated = True
                # Résoudre les SIDs non autorisés
                names = [_resolve_sid(v) for v in raw.split(',')
                         if v.strip() and v.strip().lower() not in allowed]
                all_names = [_resolve_sid(v) for v in raw.split(',') if v.strip()]
                detail = (f"Droits accordés à : {', '.join(all_names)}\n"
                          f"Comptes non autorisés : {', '.join(names)}")
        if violated:
            findings.append({
                "rule_id":     rule["id"],
                "title":       rule["title"],
                "severity":    rule["severity"],
                "ref":         rule["ref"],
                "category":    rule["category"],
                "remediation": rule["remediation"],
                "detail":      detail,
                "not_configured": False,
            })
    return findings


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


def parse_psscripts_ini(content: str, is_user: bool = False) -> dict:
    """Parse psscripts.ini — scripts PowerShell GPO.
    Même format que scripts.ini :
    - Fichier machine : sections [Startup] et [Shutdown]
    - Fichier utilisateur : sections [Logon] et [Logoff]
    """
    if is_user:
        # psscripts.ini utilisateur contient [Logon] et [Logoff]
        return parse_scripts('', '', content, content)
    else:
        # psscripts.ini machine contient [Startup] et [Shutdown]
        return parse_scripts(content, content, '', '')


def parse_software_xml(content: str) -> list:
    """Parse Machine/Preferences/Applications/Applications.xml — installation logiciels."""
    if not ET or not content:
        return []
    items = []
    try:
        root = ET.fromstring(content)
        for app in root.iter():
            tag = app.tag.split('}')[-1] if '}' in app.tag else app.tag
            if tag not in ('Application', 'Package'):
                continue
            props = next((c for c in app if (c.tag.split('}')[-1] if '}' in c.tag else c.tag).lower() == 'properties'), None)
            if props is None:
                props = app
            name      = _xml_attr(props, 'name', 'productName', 'Name')
            path      = _xml_attr(props, 'path', 'msiPath', 'packagePath')
            action    = _xml_attr(props, 'action', 'Action')
            version   = _xml_attr(props, 'version', 'productVersion')
            publisher = _xml_attr(props, 'publisher', 'manufacturer')
            action_map = {'I': 'Installer', 'U': 'Mettre à jour', 'R': 'Réparer', 'D': 'Désinstaller',
                          '0': 'Installer', '1': 'Mettre à jour', '2': 'Réparer', '3': 'Désinstaller'}
            items.append({
                'name':      name or path or '(sans nom)',
                'path':      path,
                'action':    action_map.get(action, action or 'Installer'),
                'version':   version,
                'publisher': publisher,
            })
    except Exception:
        pass
    return items


def parse_ini_files_xml(content: str) -> list:
    """Parse Machine/Preferences/IniFiles/IniFiles.xml — modification fichiers .ini."""
    if not ET or not content:
        return []
    items = []
    try:
        root = ET.fromstring(content)
        for f in root.iter():
            tag = f.tag.split('}')[-1] if '}' in f.tag else f.tag
            if tag != 'Ini':
                continue
            props = next((c for c in f if (c.tag.split('}')[-1] if '}' in c.tag else c.tag).lower() == 'properties'), None)
            if props is None:
                props = f
            items.append({
                'path':    _xml_attr(props, 'path', 'filePath'),
                'section': _xml_attr(props, 'section', 'sectionName'),
                'property':_xml_attr(props, 'property', 'propertyName'),
                'value':   _xml_attr(props, 'value', 'propertyValue'),
                'action':  _xml_attr(props, 'action', 'Action'),
            })
    except Exception:
        pass
    return items


def parse_datasources_xml(content: str) -> list:
    """Parse Machine/Preferences/DataSources/DataSources.xml — sources ODBC."""
    if not ET or not content:
        return []
    items = []
    try:
        root = ET.fromstring(content)
        for ds in root.iter():
            tag = ds.tag.split('}')[-1] if '}' in ds.tag else ds.tag
            if tag != 'DataSource':
                continue
            props = next((c for c in ds if (c.tag.split('}')[-1] if '}' in c.tag else c.tag).lower() == 'properties'), None)
            if props is None:
                props = ds
            items.append({
                'name':   _xml_attr(props, 'dsn', 'name', 'dsnName'),
                'driver': _xml_attr(props, 'driver', 'driverName'),
                'server': _xml_attr(props, 'server', 'serverName'),
                'db':     _xml_attr(props, 'database', 'databaseName'),
                'action': _xml_attr(props, 'action', 'Action'),
                'scope':  _xml_attr(props, 'userDSN', 'type') or 'Système',
            })
    except Exception:
        pass
    return items


def parse_internet_settings_xml(content: str) -> list:
    """Parse User/Preferences/InternetSettings/InternetSettings.xml — proxy IE."""
    if not ET or not content:
        return []
    items = []
    try:
        root = ET.fromstring(content)
        for s in root.iter():
            tag = s.tag.split('}')[-1] if '}' in s.tag else s.tag
            if tag not in ('InternetSettings', 'Internet'):
                continue
            props = next((c for c in s if (c.tag.split('}')[-1] if '}' in c.tag else c.tag).lower() == 'properties'), None)
            if props is None:
                props = s
            proxy  = _xml_attr(props, 'proxyServer', 'proxy')
            bypass = _xml_attr(props, 'proxyOverride', 'bypass')
            enable = _xml_attr(props, 'enableProxy', 'proxyEnable')
            home   = _xml_attr(props, 'startPage', 'homePage')
            if proxy or home:
                items.append({
                    'proxy':   proxy,
                    'bypass':  bypass,
                    'enabled': enable in ('1', 'true', 'True'),
                    'home':    home,
                })
    except Exception:
        pass
    return items


def parse_network_shares_xml(content: str) -> list:
    """Parse Machine/Preferences/NetworkShares/NetworkShares.xml."""
    if not ET or not content:
        return []
    items = []
    try:
        root = ET.fromstring(content)
        for ns in root.iter():
            tag = ns.tag.split('}')[-1] if '}' in ns.tag else ns.tag
            if tag != 'NetShare':
                continue
            props = next((c for c in ns if (c.tag.split('}')[-1] if '}' in c.tag else c.tag).lower() == 'properties'), None)
            if props is None:
                props = ns
            action_map = {'C': 'Créer', 'R': 'Remplacer', 'U': 'Mettre à jour', 'D': 'Supprimer'}
            action = _xml_attr(props, 'action', 'Action')
            items.append({
                'name':    _xml_attr(props, 'name', 'shareName'),
                'path':    _xml_attr(props, 'path', 'localPath'),
                'comment': _xml_attr(props, 'comment', 'description'),
                'limit':   _xml_attr(props, 'userLimit', 'maxUsers'),
                'action':  action_map.get(action, action or 'Créer'),
            })
    except Exception:
        pass
    return items


def parse_folders_xml(content: str) -> list:
    """Parse Machine/Preferences/Folders/Folders.xml — création/suppression dossiers."""
    if not ET or not content:
        return []
    items = []
    try:
        root = ET.fromstring(content)
        for f in root.iter():
            tag = f.tag.split('}')[-1] if '}' in f.tag else f.tag
            if tag != 'Folder':
                continue
            props = next((c for c in f if (c.tag.split('}')[-1] if '}' in c.tag else c.tag).lower() == 'properties'), None)
            if props is None:
                props = f
            action_map = {'C': 'Créer', 'R': 'Remplacer', 'U': 'Mettre à jour', 'D': 'Supprimer'}
            action = _xml_attr(props, 'action', 'Action')
            items.append({
                'path':     _xml_attr(props, 'path', 'targetPath'),
                'action':   action_map.get(action, action or 'Créer'),
                'readonly': _xml_attr(props, 'readOnly') in ('1', 'true'),
                'hidden':   _xml_attr(props, 'hidden') in ('1', 'true'),
                'archive':  _xml_attr(props, 'archive') in ('1', 'true'),
            })
    except Exception:
        pass
    return items


def parse_regional_xml(content: str) -> list:
    """Parse User/Preferences/Regional/Regional.xml — paramètres régionaux."""
    if not ET or not content:
        return []
    items = []
    try:
        root = ET.fromstring(content)
        for r in root.iter():
            tag = r.tag.split('}')[-1] if '}' in r.tag else r.tag
            if tag not in ('Regional', 'RegionalOptions'):
                continue
            props = next((c for c in r if (c.tag.split('}')[-1] if '}' in c.tag else c.tag).lower() == 'properties'), None)
            if props is None:
                props = r
            locale = _xml_attr(props, 'name', 'locale', 'userLocale')
            tz     = _xml_attr(props, 'timeZone', 'timezone')
            if locale or tz:
                items.append({'locale': locale, 'timezone': tz})
    except Exception:
        pass
    return items


def parse_network_options_xml(content: str) -> list:
    """Parse User/Preferences/NetworkOptions/NetworkOptions.xml — VPN/connexions."""
    if not ET or not content:
        return []
    items = []
    try:
        root = ET.fromstring(content)
        for n in root.iter():
            tag = n.tag.split('}')[-1] if '}' in n.tag else n.tag
            if tag not in ('Vpn', 'DialUp', 'Connection'):
                continue
            props = next((c for c in n if (c.tag.split('}')[-1] if '}' in c.tag else c.tag).lower() == 'properties'), None)
            if props is None:
                props = n
            items.append({
                'name':   _xml_attr(props, 'name', 'connectionName'),
                'type':   tag,
                'server': _xml_attr(props, 'serverAddress', 'phoneNumber'),
                'action': _xml_attr(props, 'action', 'Action'),
            })
    except Exception:
        pass
    return items


def parse_admx_registry(registry_entries: list) -> list:
    """
    Décode les clés de registre brutes (Registry.pol) en paramètres ADMX lisibles.
    Utilise une table de correspondance des clés ADMX les plus courantes.
    Retourne une liste de {key, name, value, label, category, alert}
    """
    # Table : (clé_registre_lower, nom_valeur_lower) → (label_fr, catégorie, hint_valeur)
    ADMX_MAP = {
        # ── Windows Update / WSUS ──
        ('software\\policies\\microsoft\\windows\\windowsupdate\\au', 'nonautomaticupdates'):
            ('Windows Update : Mises à jour automatiques désactivées', 'Windows Update', '1=désactivé'),
        ('software\\policies\\microsoft\\windows\\windowsupdate\\au', 'auoptions'):
            ('Windows Update : Mode de mise à jour automatique', 'Windows Update', '2=notif,3=auto,4=planifié'),
        ('software\\policies\\microsoft\\windows\\windowsupdate\\au', 'usewuserver'):
            ('Windows Update : Utiliser serveur WSUS interne', 'Windows Update', '1=oui'),
        ('software\\policies\\microsoft\\windows\\windowsupdate', 'wuserver'):
            ('Windows Update : URL du serveur WSUS', 'Windows Update', 'URL'),
        ('software\\policies\\microsoft\\windows\\windowsupdate', 'wustatusserver'):
            ('Windows Update : URL du serveur de stats WSUS', 'Windows Update', 'URL'),

        # ── PowerShell ──
        ('software\\policies\\microsoft\\windows\\powershell\\scriptblocklogging', 'enablescriptblocklogging'):
            ('PowerShell : Journalisation ScriptBlock', 'PowerShell', '1=activé'),
        ('software\\policies\\microsoft\\windows\\powershell\\transcription', 'enabletranscripting'):
            ('PowerShell : Transcription activée', 'PowerShell', '1=activé'),
        ('software\\policies\\microsoft\\windows\\powershell\\transcription', 'outputdirectory'):
            ('PowerShell : Dossier de transcription', 'PowerShell', 'chemin'),
        ('software\\policies\\microsoft\\windows\\powershell\\modulellogging', 'enablemodulelogging'):
            ('PowerShell : Journalisation des modules', 'PowerShell', '1=activé'),
        ('software\\policies\\microsoft\\powershellcore\\scriptblocklogging', 'enablescriptblocklogging'):
            ('PowerShell Core : Journalisation ScriptBlock', 'PowerShell', '1=activé'),

        # ── Credential Guard / Device Guard ──
        ('system\\currentcontrolset\\control\\deviceguard', 'enablevirtualizationbasedsecurity'):
            ('Device Guard : Virtualisation (VBS/Credential Guard)', 'Sécurité avancée', '1=activé'),
        ('system\\currentcontrolset\\control\\deviceguard', 'requireplatformsecurityfeatures'):
            ('Device Guard : Niveau de sécurité requis', 'Sécurité avancée', '1=Secure Boot,3=Secure Boot+DMA'),
        ('system\\currentcontrolset\\control\\lsa', 'lsacfgflags'):
            ('Credential Guard : Activation', 'Sécurité avancée', '1=activé sans verrou,2=activé avec verrou UEFI'),

        # ── AppLocker ──
        ('software\\policies\\microsoft\\windows\\srpv2', 'enforcementmode'):
            ('AppLocker : Mode d\'application', 'AppLocker', '0=audit,1=enforced'),

        # ── BitLocker ──
        ('software\\policies\\microsoft\\fveroot\\fve', 'osmanageddrive'):
            ('BitLocker : Lecteur OS géré', 'BitLocker', '1=requis'),
        ('software\\policies\\microsoft\\fve', 'useadvancedstartup'):
            ('BitLocker : Démarrage avancé (PIN/clé)', 'BitLocker', '1=activé'),
        ('software\\policies\\microsoft\\fve', 'recoverykeymessage'):
            ('BitLocker : Message de récupération', 'BitLocker', 'texte'),
        ('software\\policies\\microsoft\\fve', 'fdvenableddrive'):
            ('BitLocker : Lecteurs de données fixes', 'BitLocker', '1=requis'),
        ('software\\policies\\microsoft\\fve', 'rdvenableddrive'):
            ('BitLocker : Lecteurs amovibles', 'BitLocker', '1=requis'),

        # ── RDP / Terminal Services ──
        ('software\\policies\\microsoft\\windows nt\\terminal services', 'fdisableauditfail'):
            ('RDP : Désactiver audit échec connexion', 'RDP / Terminal Services', '1=désactivé'),
        ('software\\policies\\microsoft\\windows nt\\terminal services', 'userauthenication'):
            ('RDP : NLA (Network Level Auth) requis', 'RDP / Terminal Services', '1=requis'),
        ('software\\policies\\microsoft\\windows nt\\terminal services', 'minencryptionlevel'):
            ('RDP : Niveau de chiffrement minimum', 'RDP / Terminal Services', '1=faible,2=client,3=élevé,4=FIPS'),
        ('software\\policies\\microsoft\\windows nt\\terminal services', 'fencryptionlevelusedforsessiondata'):
            ('RDP : Chiffrement des données de session', 'RDP / Terminal Services', ''),
        ('software\\policies\\microsoft\\windows nt\\terminal services', 'maxinstances'):
            ('RDP : Nombre max de sessions', 'RDP / Terminal Services', 'nombre'),
        ('software\\policies\\microsoft\\windows nt\\terminal services', 'shadow'):
            ('RDP : Shadowing (contrôle à distance)', 'RDP / Terminal Services', '0=désactivé,1=full,2=view'),
        ('software\\policies\\microsoft\\windows nt\\terminal services', 'fpromptupdatedsettings'):
            ('RDP : Redirection imprimantes', 'RDP / Terminal Services', '0=désactivé'),
        ('software\\policies\\microsoft\\windows nt\\terminal services', 'fdisableclip'):
            ('RDP : Redirection presse-papiers désactivée', 'RDP / Terminal Services', '1=désactivé'),
        ('software\\policies\\microsoft\\windows nt\\terminal services', 'fdisabledrives'):
            ('RDP : Redirection lecteurs désactivée', 'RDP / Terminal Services', '1=désactivé'),
        ('software\\policies\\microsoft\\windows nt\\terminal services', 'fdisableprnt'):
            ('RDP : Redirection imprimantes désactivée', 'RDP / Terminal Services', '1=désactivé'),
        ('software\\policies\\microsoft\\windows nt\\terminal services', 'fdisablelpt'):
            ('RDP : Redirection ports LPT désactivée', 'RDP / Terminal Services', '1=désactivé'),
        ('software\\policies\\microsoft\\windows nt\\terminal services', 'fdisablecom'):
            ('RDP : Redirection ports COM désactivée', 'RDP / Terminal Services', '1=désactivé'),
        ('software\\policies\\microsoft\\windows nt\\terminal services', 'tsdisconnecttime'):
            ('RDP : Délai déconnexion session inactive (ms)', 'RDP / Terminal Services', 'millisecondes'),
        ('software\\policies\\microsoft\\windows nt\\terminal services', 'tsreconnecttime'):
            ('RDP : Délai reconnexion session déconnectée (ms)', 'RDP / Terminal Services', 'millisecondes'),
        ('software\\policies\\microsoft\\windows nt\\terminal services', 'maxidletime'):
            ('RDP : Délai session inactive (ms)', 'RDP / Terminal Services', 'millisecondes'),

        # ── Pare-feu Windows ──
        ('software\\policies\\microsoft\\windowsfirewall\\domainprofile', 'enablefirewall'):
            ('Pare-feu : Profil domaine activé', 'Pare-feu Windows', '0=désactivé CRITIQUE'),
        ('software\\policies\\microsoft\\windowsfirewall\\standardprofile', 'enablefirewall'):
            ('Pare-feu : Profil standard activé', 'Pare-feu Windows', '0=désactivé CRITIQUE'),
        ('software\\policies\\microsoft\\windowsfirewall\\domainprofile', 'donotallowexceptions'):
            ('Pare-feu : Pas d\'exceptions autorisées (domaine)', 'Pare-feu Windows', '1=strict'),
        ('software\\policies\\microsoft\\windowsfirewall\\domainprofile', 'disablenotifications'):
            ('Pare-feu : Notifications désactivées (domaine)', 'Pare-feu Windows', '1=pas de notification'),

        # ── Internet Explorer / Edge ──
        ('software\\policies\\microsoft\\internet explorer\\main', 'start page'):
            ('IE/Edge : Page de démarrage', 'Navigateur', 'URL'),
        ('software\\policies\\microsoft\\internet explorer\\control panel', 'homepage'):
            ('IE : Page d\'accueil verrouillée', 'Navigateur', '1=verrouillé'),
        ('software\\policies\\microsoft\\internet explorer\\security', 'lockdownsecuritylevel'):
            ('IE : Niveau de sécurité verrouillé', 'Navigateur', ''),
        ('software\\policies\\microsoft\\internet explorer\\restrictions', 'nohomepage'):
            ('IE : Accès aux options désactivé', 'Navigateur', '1=désactivé'),

        # ── Proxy ──
        ('software\\policies\\microsoft\\windows\\currentversion\\internet settings', 'proxyenable'):
            ('Proxy : Utiliser un proxy', 'Proxy / Internet', '1=oui'),
        ('software\\policies\\microsoft\\windows\\currentversion\\internet settings', 'proxyserver'):
            ('Proxy : Adresse du serveur proxy', 'Proxy / Internet', 'hôte:port'),
        ('software\\policies\\microsoft\\windows\\currentversion\\internet settings', 'proxyoverride'):
            ('Proxy : Exceptions proxy (bypass)', 'Proxy / Internet', 'liste'),
        ('software\\policies\\microsoft\\windows\\currentversion\\internet settings', 'autoconfigurl'):
            ('Proxy : URL de configuration automatique (PAC)', 'Proxy / Internet', 'URL .pac'),

        # ── Antivirus / Defender ──
        ('software\\policies\\microsoft\\windows defender', 'disableantispyware'):
            ('Defender : Antispyware désactivé', 'Windows Defender', '1=désactivé CRITIQUE'),
        ('software\\policies\\microsoft\\windows defender', 'disablerealtimemonitoring'):
            ('Defender : Protection temps réel désactivée', 'Windows Defender', '1=désactivé CRITIQUE'),
        ('software\\policies\\microsoft\\windows defender\\real-time protection', 'disablebehaviormonitoring'):
            ('Defender : Surveillance comportementale désactivée', 'Windows Defender', '1=désactivé'),
        ('software\\policies\\microsoft\\windows defender\\spynet', 'spynetreporting'):
            ('Defender : Rapport cloud (MAPS)', 'Windows Defender', '0=désactivé,1=basique,2=avancé'),
        ('software\\policies\\microsoft\\windows defender\\windows defender exploit guard\\asr', 'exasr_enabled'):
            ('Defender : Attack Surface Reduction (ASR)', 'Windows Defender', '1=activé'),

        # ── Mappage lecteurs / scripts ──
        ('software\\policies\\microsoft\\windows\\system', 'enablelogonscriptdelay'):
            ('Scripts : Délai script logon', 'Scripts & Démarrage', '0=pas de délai'),
        ('software\\policies\\microsoft\\windows\\system', 'groupolicyrefreshtime'):
            ('GPO : Intervalle de rafraîchissement (min)', 'Stratégie de groupe', 'minutes'),
        ('software\\policies\\microsoft\\windows\\system', 'groupolicyrefrashtimeoffset'):
            ('GPO : Décalage rafraîchissement (min)', 'Stratégie de groupe', 'minutes'),

        # ── Restrictions utilisateur ──
        ('software\\microsoft\\windows\\currentversion\\policies\\explorer', 'nodrivetypeautorun'):
            ('AutoRun : Désactivé sur tous les lecteurs', 'Restrictions', '255=tout désactivé'),
        ('software\\microsoft\\windows\\currentversion\\policies\\explorer', 'norun'):
            ('Restrictions : Commande Exécuter désactivée', 'Restrictions', '1=désactivé'),
        ('software\\microsoft\\windows\\currentversion\\policies\\explorer', 'nocontrolpanel'):
            ('Restrictions : Panneau de configuration désactivé', 'Restrictions', '1=désactivé'),
        ('software\\microsoft\\windows\\currentversion\\policies\\explorer', 'notaskmgr'):
            ('Restrictions : Gestionnaire de tâches désactivé', 'Restrictions', '1=désactivé SUSPECT'),
        ('software\\microsoft\\windows\\currentversion\\policies\\explorer', 'norecentdocshistory'):
            ('Restrictions : Historique documents récents désactivé', 'Restrictions', '1=désactivé'),
        ('software\\microsoft\\windows\\currentversion\\policies\\system', 'disableregistrytools'):
            ('Restrictions : Éditeur de registre désactivé', 'Restrictions', '1=désactivé'),
        ('software\\microsoft\\windows\\currentversion\\policies\\system', 'disabletaskmgr'):
            ('Restrictions : Gestionnaire de tâches désactivé', 'Restrictions', '1=désactivé SUSPECT'),
        ('software\\microsoft\\windows\\currentversion\\policies\\system', 'disablecmd'):
            ('Restrictions : Invite de commandes désactivée', 'Restrictions', '1=désactivé'),

        # ── Gestion des comptes / LAPS ──
        ('software\\policies\\microsoft services\\admpwd', 'admpwdenabled'):
            ('LAPS : Gestion mot de passe admin local activée', 'LAPS', '1=activé'),
        ('software\\policies\\microsoft services\\admpwd', 'passwordcomplexity'):
            ('LAPS : Complexité du mot de passe', 'LAPS', '4=max'),
        ('software\\policies\\microsoft services\\admpwd', 'passwordlength'):
            ('LAPS : Longueur du mot de passe admin', 'LAPS', 'caractères'),
        ('software\\policies\\microsoft services\\admpwd', 'passwordagedays'):
            ('LAPS : Durée de vie du mot de passe admin (jours)', 'LAPS', 'jours'),

        # ── Chiffrement / TLS ──
        ('system\\currentcontrolset\\control\\securityproviders\\schannel\\protocols\\tls 1.0\\server', 'enabled'):
            ('TLS 1.0 Serveur : Activé', 'Chiffrement / TLS', '0=désactivé recommandé'),
        ('system\\currentcontrolset\\control\\securityproviders\\schannel\\protocols\\tls 1.1\\server', 'enabled'):
            ('TLS 1.1 Serveur : Activé', 'Chiffrement / TLS', '0=désactivé recommandé'),
        ('system\\currentcontrolset\\control\\securityproviders\\schannel\\protocols\\ssl 2.0\\server', 'enabled'):
            ('SSL 2.0 Serveur : Activé', 'Chiffrement / TLS', '0=désactivé CRITIQUE'),
        ('system\\currentcontrolset\\control\\securityproviders\\schannel\\protocols\\ssl 3.0\\server', 'enabled'):
            ('SSL 3.0 Serveur : Activé', 'Chiffrement / TLS', '0=désactivé CRITIQUE'),

        # ── Audit avancé (via registre) ──
        ('system\\currentcontrolset\\control\\lsa', 'auditbaseobjects'):
            ('Audit : Objets de base du système', 'Audit', '1=activé'),
        ('system\\currentcontrolset\\control\\lsa', 'fullprivilegeauditing'):
            ('Audit : Tous les privilèges', 'Audit', '1=activé'),
        ('software\\policies\\microsoft\\windows\\eventlog\\security', 'maxsize'):
            ('Journal Sécurité : Taille max (Ko)', 'Journaux événements', 'Ko — recommandé ≥ 1048576'),
        ('software\\policies\\microsoft\\windows\\eventlog\\application', 'maxsize'):
            ('Journal Application : Taille max (Ko)', 'Journaux événements', 'Ko'),
        ('software\\policies\\microsoft\\windows\\eventlog\\system', 'maxsize'):
            ('Journal Système : Taille max (Ko)', 'Journaux événements', 'Ko'),
        ('software\\policies\\microsoft\\windows\\eventlog\\security', 'retention'):
            ('Journal Sécurité : Politique de rétention', 'Journaux événements', '0=écraser si nécessaire'),

        # ── Imprimantes / spooler ──
        ('system\\currentcontrolset\\control\\print\\providers\\lanman print services\\servers', 'addprinterdrivers'):
            ('Spooler : Installation drivers restreinte aux admins', 'Impression', '1=admins seulement'),
        ('software\\policies\\microsoft\\windows nt\\printers\\pointandprint', 'nopolicyapplicabletosystem'):
            ('Point and Print : Restrictions désactivées', 'Impression', '1=CRITIQUE PrintNightmare'),
        ('software\\policies\\microsoft\\windows nt\\printers\\pointandprint', 'trustedservers'):
            ('Point and Print : Serveurs de confiance uniquement', 'Impression', '1=activé'),
        ('software\\policies\\microsoft\\windows nt\\printers\\pointandprint', 'serverlist'):
            ('Point and Print : Liste des serveurs autorisés', 'Impression', 'liste'),

        # ── Dossiers de redirection ──
        ('software\\policies\\microsoft\\windows\\system', 'allowx-zone-dereference'):
            ('Redirection dossiers : Déréférencement cross-zone', 'Redirection', ''),
        ('software\\policies\\microsoft\\windows\\system', 'folderredirectionsync'):
            ('Redirection dossiers : Synchronisation', 'Redirection', ''),

        # ── Misc sécurité ──
        ('software\\microsoft\\windows\\currentversion\\policies\\system', 'enablelua'):
            ('UAC : Activé (EnableLUA)', 'UAC', '1=activé'),
        ('software\\microsoft\\windows\\currentversion\\policies\\system', 'consentpromptbehavioradmin'):
            ('UAC : Comportement admins', 'UAC', '0=silencieux CRITIQUE,2=credentials,5=confirmation'),
        ('software\\microsoft\\windows\\currentversion\\policies\\system', 'localaccounttokenfilterpolicy'):
            ('UAC : Token plein comptes locaux réseau', 'UAC', '1=CRITIQUE Pass-the-Hash'),
        ('system\\currentcontrolset\\control\\lsa', 'restrictanonymoussam'):
            ('LSA : Restriction accès SAM anonyme', 'Sécurité LSA', '1=restreint'),
        ('system\\currentcontrolset\\control\\lsa', 'everyoneincludesanonymous'):
            ('LSA : Everyone inclut anonymes', 'Sécurité LSA', '0=recommandé'),
        ('system\\currentcontrolset\\control\\lsa', 'lmcompatibilitylevel'):
            ('NTLM : Niveau de compatibilité LM', 'Authentification', '5=NTLMv2 seulement'),
        ('system\\currentcontrolset\\control\\lsa', 'nolmhash'):
            ('NTLM : Ne pas stocker hash LM', 'Authentification', '1=recommandé'),
        ('system\\currentcontrolset\\services\\lanmanserver\\parameters', 'requiresecuritysignature'):
            ('SMB : Signature requise côté serveur', 'SMB', '1=requis'),
        ('system\\currentcontrolset\\services\\lanmanworkstation\\parameters', 'requiresecuritysignature'):
            ('SMB : Signature requise côté client', 'SMB', '1=requis'),
        ('system\\currentcontrolset\\services\\lanmanserver\\parameters', 'smb1'):
            ('SMB : SMBv1 activé', 'SMB', '0=désactivé recommandé'),
        ('system\\currentcontrolset\\control\\securityproviders\\wdigest', 'uselogoncredential'):
            ('WDigest : Mots de passe en clair dans lsass', 'Authentification', '0=désactivé recommandé'),
    }

    results = []
    for (key, vname, rtype, val) in registry_entries:
        k = key.lower().replace('hkey_local_machine\\', '').replace('hklm\\', '').replace('hkey_current_user\\', '').replace('hkcu\\', '')
        n = vname.lower()
        lookup = ADMX_MAP.get((k, n))

        alert = None
        if lookup:
            label, category, hint = lookup
            # Détecter les valeurs critiques
            try:
                vi = int(val)
                if 'désactivé CRITIQUE' in hint and vi == 1:
                    alert = f'CRITIQUE : {label}'
                elif 'CRITIQUE' in hint and vi == 1:
                    alert = f'Attention : {label}'
                elif label in ('WDigest : Mots de passe en clair dans lsass',) and vi == 1:
                    alert = 'WDigest actif — credentials exposés'
                elif 'désactivé' in hint and vi == 0 and 'CRITIQUE' in hint:
                    alert = f'CRITIQUE : valeur = 0'
            except (ValueError, TypeError):
                pass
            results.append({
                'key':      f"{k}\\{vname}",
                'name':     vname,
                'value':    str(val),
                'label':    label,
                'category': category,
                'hint':     hint,
                'alert':    alert,
                'decoded':  True,
            })
        else:
            # Clé non reconnue — afficher quand même mais sans label
            short = key.split('\\')[-1]
            results.append({
                'key':      f"{k}\\{vname}",
                'name':     vname,
                'value':    str(val),
                'label':    f"{short} → {vname}",
                'category': 'Registre',
                'hint':     '',
                'alert':    None,
                'decoded':  False,
            })
    return results


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
    """Parse Registry.pol → liste de (key_lower, value_name_lower, type, parsed_value)
    Supporte REG_DWORD, REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ, REG_BINARY.
    Robuste aux formats exotiques — erreurs silencieuses.
    """
    entries = []
    if len(data) < 8 or data[:4] != b'PReg':
        return entries

    offset = 8
    while offset < len(data) - 4:
        try:
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
                try:
                    s = data[pos:end].decode('utf-16-le', errors='replace')
                except Exception:
                    s = ''
                return s, end + 2

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

            # Parser la valeur selon le type
            try:
                if reg_type == 4 and len(val_data) >= 4:       # REG_DWORD
                    parsed_val = struct.unpack_from('<I', val_data)[0]
                elif reg_type == 5 and len(val_data) >= 4:      # REG_DWORD_BIG_ENDIAN
                    parsed_val = struct.unpack_from('>I', val_data)[0]
                elif reg_type in (1, 2) and val_data:           # REG_SZ, REG_EXPAND_SZ
                    parsed_val = val_data.decode('utf-16-le', errors='replace').rstrip('\x00')
                elif reg_type == 7 and val_data:                # REG_MULTI_SZ
                    parts = val_data.decode('utf-16-le', errors='replace').rstrip('\x00')
                    parsed_val = ' | '.join(p for p in parts.split('\x00') if p)
                elif reg_type == 11 and len(val_data) >= 8:     # REG_QWORD
                    parsed_val = struct.unpack_from('<Q', val_data)[0]
                else:                                            # REG_BINARY et autres
                    parsed_val = val_data.hex()
            except Exception:
                parsed_val = val_data.hex() if val_data else ''

            entries.append((key.lower(), value_name.lower(), reg_type, parsed_val))

        except Exception:
            # Entrée corrompue — continuer avec la suivante
            offset += 2
            continue

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

    # Table d'évaluation sécurité des contradictions
    # (section, key_short) → {valeur_sure, comparateur, label_recommande}
    SECURITY_EVAL = {
        ('system_access',  'lmcompatibilitylevel'):   {'safe_op': 'gte', 'safe_val': 5, 'label': 'NTLMv2 uniquement (≥ 5)'},
        ('system_access',  'nolmhash'):               {'safe_op': 'eq',  'safe_val': 1, 'label': 'Ne pas stocker hash LM (= 1)'},
        ('system_access',  'restrictanonymous'):      {'safe_op': 'gte', 'safe_val': 1, 'label': 'Restreindre anonymes (≥ 1)'},
        ('system_access',  'enableguestaccount'):     {'safe_op': 'eq',  'safe_val': 0, 'label': 'Compte Invité désactivé (= 0)'},
        ('system_access',  'lockoutbadcount'):        {'safe_op': 'lte_nonzero', 'safe_val': 10, 'label': 'Verrouillage ≤ 10 tentatives'},
        ('password_policy','minimumpasswordlength'):  {'safe_op': 'gte', 'safe_val': 14, 'label': 'Longueur minimale ≥ 14'},
        ('password_policy','passwordcomplexity'):     {'safe_op': 'eq',  'safe_val': 1,  'label': 'Complexité activée (= 1)'},
        ('password_policy','passwordhistorysize'):    {'safe_op': 'gte', 'safe_val': 24, 'label': 'Historique ≥ 24'},
        ('registry_pol',   'uselogoncredential'):     {'safe_op': 'eq',  'safe_val': 0,  'label': 'WDigest désactivé (= 0)'},
        ('registry_pol',   'smb1'):                   {'safe_op': 'eq',  'safe_val': 0,  'label': 'SMBv1 désactivé (= 0)'},
        ('registry_pol',   'enablefirewall'):         {'safe_op': 'eq',  'safe_val': 1,  'label': 'Pare-feu activé (= 1)'},
        ('registry_pol',   'enablelua'):              {'safe_op': 'eq',  'safe_val': 1,  'label': 'UAC activé (= 1)'},
        ('registry_pol',   'enablescriptblocklogging'): {'safe_op': 'eq', 'safe_val': 1, 'label': 'ScriptBlock Logging activé (= 1)'},
        ('registry_pol',   'nolargelogfilewarning'):  {'safe_op': 'eq',  'safe_val': 0,  'label': ''},
        ('event_audit',    'auditlogonevents'):       {'safe_op': 'gte', 'safe_val': 3,  'label': 'Audit connexions Succès+Échec (≥ 3)'},
        ('event_audit',    'auditaccountmanage'):     {'safe_op': 'gte', 'safe_val': 3,  'label': 'Audit gestion comptes Succès+Échec (≥ 3)'},
    }

    def _is_safe_value(section, key_short, val_str) -> bool | None:
        """Retourne True si la valeur est sûre, False si dangereuse, None si inconnu."""
        rule = SECURITY_EVAL.get((section, key_short))
        if not rule:
            return None
        try:
            v = int(val_str.split(',')[-1].strip())
        except (ValueError, TypeError):
            return None
        op = rule['safe_op']
        sv = rule['safe_val']
        if op == 'eq':     return v == sv
        if op == 'gte':    return v >= sv
        if op == 'lte':    return v <= sv
        if op == 'lte_nonzero': return 0 < v <= sv
        return None
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

        # Évaluer si le conflit est une contradiction de sécurité
        # (une valeur sûre vs une valeur dangereuse)
        key_short = key.split('\\')[-1].lower()
        sec_rule = SECURITY_EVAL.get((section, key_short))
        contradiction = None
        safe_gpo = None
        unsafe_gpos = []
        if sec_rule:
            for e in unique_entries:
                is_safe = _is_safe_value(section, key_short, e['value'])
                if is_safe is True:
                    safe_gpo = e
                elif is_safe is False:
                    unsafe_gpos.append(e)
            if safe_gpo and unsafe_gpos:
                contradiction = {
                    'label':       sec_rule['label'],
                    'safe_gpo':    safe_gpo['gpo_name'],
                    'safe_val':    safe_gpo['value'],
                    'unsafe_gpos': [{'name': u['gpo_name'], 'value': u['value']} for u in unsafe_gpos],
                    'danger':      f"La GPO '{safe_gpo['gpo_name']}' sécurise ce paramètre "
                                   f"mais {'une autre GPO la contredit' if len(unsafe_gpos)==1 else str(len(unsafe_gpos))+' autres GPO la contredisent'} — "
                                   f"si ces GPO ont une priorité plus haute, le paramètre dangereux s'applique.",
                }
                # Élever la sévérité si c'est une vraie contradiction de sécurité
                is_security = True
                severity = 'conflict_high'

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
            'contradiction':   contradiction,
            'label':           f"{section_label} → {key_short}",
        })

    # Trier : sécurité d'abord, puis nombre de GPO en conflit
    conflicts.sort(key=lambda c: (0 if c['is_security'] else 1, -c['gpo_count']))
    return conflicts[:100]   # cap à 100 pour ne pas exploser le JSON



def _enrich_gpos_for_search(gpos: list, gpo_reports: list) -> list:
    """Injecte les findings calculés dans chaque GPO pour les indexer dans la recherche."""
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
        # Tronquer les valeurs très longues pour ne pas gonfler le JSON
        key_s   = str(key)[:120]   if key   else ''
        val_s   = str(value)[:80]  if value else ''
        ctx_s   = str(context)[:80] if context else ''
        index.append({
            'gpo_name':  gpo['name'],
            'gpo_guid':  gpo['guid'],
            'type':      type_,
            'type_icon': icon,
            'key':       key_s,
            'value':     val_s,
            'context':   ctx_s,
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

        # ── Registry.pol — indexer via ADMX décodé (plus lisible, pas de doublon) ──
        # On n'indexe PAS les registry_entries brutes pour éviter de gonfler le JSON.
        # Les clés ADMX décodées sont indexées plus bas (registry_admx).
        # On indexe seulement les clés non décodées (sans label ADMX).
        admx_keys = {r['key'].lower() for r in gpo.get('registry_admx', [])}
        for (reg_key, vname, rtype, val) in gpo.get('registry_entries', []):
            full = f"{reg_key.lower()}\\{vname.lower()}"
            if full not in admx_keys:  # seulement si pas déjà couvert par ADMX
                short_key = reg_key.split('\\')[-1]
                _add(gpo, 'Registre (Registry.pol)', '🗝',
                     f"{short_key} → {vname}", str(val), reg_key)

        for (reg_key, vname, rtype, val) in gpo.get('registry_entries_user', []):
            full = f"{reg_key.lower()}\\{vname.lower()}"
            if full not in admx_keys:
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

        # ── Findings de sécurité (indexés pour la recherche) ─────────────────
        for f in gpo.get('_findings_preview', []):
            _add(gpo, 'Constatation sécurité', '🔒',
                 f.get('title', ''), f.get('severity', ''), f.get('category', ''))

        # ── Logiciels / Applications ─────────────────────────────────────────
        for scope, key in [('Machine', 'software_machine'), ('Utilisateur', 'software_user')]:
            for s in gpo.get(key, []):
                _add(gpo, f'Logiciel ({scope})', '📦',
                     s.get('name', ''), s.get('path', ''),
                     f"Action: {s.get('action','')} | {s.get('publisher','')}")

        # ── Partages réseau ──────────────────────────────────────────────────
        for s in gpo.get('network_shares', []):
            _add(gpo, 'Partage réseau', '🗂',
                 s.get('name', ''), s.get('path', ''),
                 f"Action: {s.get('action','')} | {s.get('comment','')}")

        # ── Sources ODBC ─────────────────────────────────────────────────────
        for scope, key in [('Machine', 'datasources_machine'), ('Utilisateur', 'datasources_user')]:
            for d in gpo.get(key, []):
                _add(gpo, f'Source ODBC ({scope})', '🗃',
                     d.get('name', ''), d.get('driver', ''),
                     f"Serveur: {d.get('server','')} | DB: {d.get('db','')}")

        # ── Proxy / Internet ─────────────────────────────────────────────────
        for s in gpo.get('internet_settings', []):
            _add(gpo, 'Proxy / Internet', '🌐',
                 s.get('proxy', ''), s.get('home', ''),
                 f"Bypass: {s.get('bypass','')}")

        # ── Options réseau / VPN ─────────────────────────────────────────────
        for n in gpo.get('network_options', []):
            _add(gpo, f"Réseau {n.get('type','VPN')}", '🔌',
                 n.get('name', ''), n.get('server', ''), n.get('action', ''))

        # ── Dossiers ─────────────────────────────────────────────────────────
        for scope, key in [('Machine', 'folders_machine'), ('Utilisateur', 'folders_user')]:
            for f in gpo.get(key, []):
                _add(gpo, f'Dossier ({scope})', '📁',
                     f.get('path', ''), f.get('action', ''), '')

        # ── Fichiers INI ─────────────────────────────────────────────────────
        for scope, key in [('Machine', 'ini_files_machine'), ('Utilisateur', 'ini_files_user')]:
            for i in gpo.get(key, []):
                _add(gpo, f'Fichier INI ({scope})', '📝',
                     f"{i.get('path','')} [{i.get('section','')}]",
                     f"{i.get('property','')} = {i.get('value','')}", '')

        # ── Paramètres ADMX décodés ───────────────────────────────────────────
        for scope, key in [('Machine', 'registry_admx'), ('Utilisateur', 'registry_admx_user')]:
            for r in gpo.get(key, []):
                _add(gpo, f"Paramètre ADMX ({r.get('category','Registre')})", '⚙',
                     r.get('label', r.get('name', '')),
                     r.get('value', ''),
                     f"{r.get('hint','')} | {r.get('key','')}")

    return index[:30000]  # Cap global — évite un JSON géant sur les très grands AD



def _gpo_flags(gpo: dict) -> int:
    """Retourne les flags d'une GPO comme entier (0=actif, 1=PC off, 2=user off, 3=tout off)."""
    try:
        return int(gpo.get('flags', 0))
    except (ValueError, TypeError):
        return 0

def is_gpo_fully_disabled(gpo: dict) -> bool:
    return _gpo_flags(gpo) == 3

def is_gpo_computer_disabled(gpo: dict) -> bool:
    return _gpo_flags(gpo) in (1, 3)

def is_gpo_user_disabled(gpo: dict) -> bool:
    return _gpo_flags(gpo) in (2, 3)

def _ou_depth(ou_dn: str) -> int:
    """Profondeur d'un DN dans l'arbre AD (nombre de composants OU=)."""
    return len([p for p in ou_dn.split(',') if p.strip().upper().startswith('OU=')])

def _gpo_max_depth(gpo: dict) -> int:
    links = gpo.get('links', [])
    if not links:
        return 0
    return max((_ou_depth(l.get('ou', '')) for l in links), default=0)

def build_rsop(gpos: list) -> tuple[dict, list]:
    """
    Construit le RSOP (Resultant Set of Policy) en agrégeant toutes les GPO.
    GPO priorité = ordre dans la liste (dernier = priorité la plus haute).
    Retourne (rsop_settings dict, rsop_registry list).
    """
    rsop_settings = {}
    rsop_registry = {}       # Registry.pol : (key_lower, vname_lower) -> int/str
    rsop_registry_xml = {}   # Registry.xml : (hive\key_lower, name_lower) -> int/str

    # Trier par priorité Windows réelle :
    # GPO domaine (profondeur 0) → OU parente → OU enfant → Enforced (priorité max)
    enforced_gpos = [g for g in gpos if any(l.get('enforced') for l in g.get('links', []))]
    normal_gpos   = [g for g in gpos if not any(l.get('enforced') for l in g.get('links', []))]
    normal_gpos.sort(key=_gpo_max_depth)
    enforced_gpos.sort(key=_gpo_max_depth)
    ordered_gpos = normal_gpos + enforced_gpos  # dernier = priorité la plus haute

    for gpo in ordered_gpos:
        # Ignorer les GPO entièrement désactivées
        if is_gpo_fully_disabled(gpo):
            continue

        # Ignorer les GPO dont TOUS les liens sont désactivés
        links = gpo.get('links', [])
        if links and all(l.get('disabled') for l in links):
            continue

        # Note sur le Security Filtering : si une GPO a un Security Filtering
        # restrictif (ne s'applique pas à "Authenticated Users"), elle ne
        # s'applique pas à tous les postes. On l'inclut quand même dans le RSOP
        # global MAIS on annotera les findings correspondants avec scope_note.
        # (La vérification est faite dans la partie "enrichissement des findings")

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

    3 cas possibles :
    1. Valeur explicitement mauvaise → finding avec sévérité de la règle
    2. Paramètre absent des GPO :
       - rule['absent_sev'] défini → finding avec cette sévérité + mention "non configuré"
       - rule['absent_sev'] = None → conforme (valeur par défaut Windows acceptable)
    3. Valeur correcte → conforme (retourne None)
    """
    section  = rule['section']
    operator = rule.get('operator', '')
    absent_sev = rule.get('absent_sev')

    def _make_absent_finding():
        """Finding 'non configuré dans les GPO' — à remonter uniquement si important."""
        return {
            'rule_id':       rule['id'],
            'title':         rule['title'],
            'severity':      absent_sev,
            'ref':           rule['ref'],
            'category':      rule['category'],
            'remediation':   rule['remediation'],
            'rec_value':     rule.get('rec_value', ''),
            'detail':        (
                f"Paramètre non configuré explicitement dans les GPO — "
                f"la valeur par défaut Windows s'applique, ce qui peut être insuffisant. "
                f"Valeur recommandée : {rule.get('rec_value', 'voir remédiation')}"
            ),
            'not_configured': True,
        }

    def _make_violation_finding(detail: str):
        return {
            'rule_id':       rule['id'],
            'title':         rule['title'],
            'severity':      rule['severity'],
            'ref':           rule['ref'],
            'category':      rule['category'],
            'remediation':   rule['remediation'],
            'rec_value':     rule.get('rec_value', ''),
            'detail':        detail,
            'not_configured': False,
        }

    # ── Règles registre (Registry.pol) ──────────────────────────────────────
    if section == 'registry':
        key_lower = rule['reg_key'].lower()
        val_lower = rule['reg_value'].lower()
        expected  = rule['reg_expected']
        actual    = rsop_registry.get((key_lower, val_lower), None)

        if actual is None:
            # Pas configuré dans les GPO
            if absent_sev:
                return _make_absent_finding()
            return None  # valeur par défaut Windows acceptable

        if actual != expected:
            return _make_violation_finding(
                f"Valeur appliquée par le RSOP : {actual} — attendu : {expected}"
            )
        return None  # conforme

    # ── Règles GptTmpl.inf ───────────────────────────────────────────────────
    sec       = rsop_settings.get(section, {})
    check_key = rule.get('check_key', '').lower()
    raw       = sec.get(check_key) if sec else None

    # Certains paramètres "Options de sécurité" peuvent être dans [Registry Values]
    # plutôt que dans [System Access] selon la façon dont la GPO est configurée.
    # Ex: LmCompatibilityLevel, NoLMHash → format "type,valeur" dans registry_values
    REGVAL_ALIASES = {
        # (check_key, section) → clé dans registry_values
        ('lmcompatibilitylevel', 'system_access'):
            'machine\\system\\currentcontrolset\\control\\lsa\\lmcompatibilitylevel',
        ('nolmhash', 'system_access'):
            'machine\\system\\currentcontrolset\\control\\lsa\\nolmhash',
        ('restrictanonymous', 'system_access'):
            'machine\\system\\currentcontrolset\\control\\lsa\\restrictanonymous',
        ('enableguestaccount', 'system_access'):
            'machine\\software\\microsoft\\windows nt\\currentversion\\winlogon\\enableguestaccount',
    }

    if raw is None:
        # Chercher dans registry_values du GptTmpl.inf (format "type,valeur")
        alias_key = REGVAL_ALIASES.get((check_key, section))
        if alias_key:
            regval_raw = rsop_settings.get('registry_values', {}).get(alias_key)
            if regval_raw:
                # Extraire la valeur entière depuis "type,valeur"
                try:
                    raw = str(int(regval_raw.split(',')[-1].strip()))
                except (ValueError, IndexError):
                    pass

    if raw is None:
        # Paramètre absent de toutes les GPO
        if absent_sev:
            return _make_absent_finding()
        return None  # valeur par défaut Windows acceptable

    actual    = int_val(raw)
    threshold = rule.get('threshold', 0)
    violated  = False

    if operator == 'lt'         and actual < threshold:             violated = True
    elif operator == 'gt'       and actual > threshold and actual != 0: violated = True
    elif operator == 'gt_or_zero' and (actual == 0 or actual > threshold): violated = True
    elif operator == 'ne'       and actual != threshold:            violated = True
    elif operator == 'eq'       and actual == threshold:            violated = True

    if violated:
        op_str = {
            'lt':         f'< {threshold}',
            'gt':         f'> {threshold}',
            'ne':         f'≠ {threshold}',
            'eq':         str(threshold),
            'gt_or_zero': f'= 0 ou > {threshold}',
        }.get(operator, str(threshold))
        return _make_violation_finding(
            f"Valeur appliquée par le RSOP : {actual} (attendu : {op_str}) — "
            f"recommandé : {rule.get('rec_value', 'voir remédiation')}"
        )
    return None  # conforme


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

    # Même logique que evaluate_rule_on_rsop :
    # certains paramètres Options de sécurité sont dans [Registry Values]
    REGVAL_ALIASES = {
        ('lmcompatibilitylevel', 'system_access'):
            'machine\\system\\currentcontrolset\\control\\lsa\\lmcompatibilitylevel',
        ('nolmhash', 'system_access'):
            'machine\\system\\currentcontrolset\\control\\lsa\\nolmhash',
        ('restrictanonymous', 'system_access'):
            'machine\\system\\currentcontrolset\\control\\lsa\\restrictanonymous',
        ('enableguestaccount', 'system_access'):
            'machine\\software\\microsoft\\windows nt\\currentversion\\winlogon\\enableguestaccount',
    }
    if raw is None:
        alias_key = REGVAL_ALIASES.get((check_key, section))
        if alias_key:
            regval_raw = settings.get('registry_values', {}).get(alias_key)
            if regval_raw:
                try:
                    raw = str(int(regval_raw.split(',')[-1].strip()))
                except (ValueError, IndexError):
                    pass

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

        # Collecter aussi les Fine-Grained Password Policies (PSO)
        # pour annoter les findings PWD et éviter les faux positifs
        self._pso_list = self._get_pso_list()
        if self._pso_list:
            print(f"[+] {len(self._pso_list)} Fine-Grained Password Policies (PSO) détectées")

        # Essai 1 : recherche avec paging (nécessaire si > ~100 GPO)
        # Essai 2 : sans paging si le DC ne le supporte pas
        entries = []
        for paged_size in [500, 0]:
            try:
                self.conn.search(
                    search_base=gpo_dn,
                    search_filter='(objectClass=groupPolicyContainer)',
                    search_scope=SUBTREE,
                    attributes=['displayName', 'cn', 'gPCFileSysPath',
                                'versionNumber', 'flags', 'whenCreated', 'whenChanged',
                                'gPCWQLFilter', 'nTSecurityDescriptor'],
                    paged_size=paged_size if paged_size else None,
                    paged_cookie=None,
                )
                entries = list(self.conn.entries)
                # Récupérer les pages suivantes si paging actif
                if paged_size:
                    while True:
                        cookie = self.conn.result.get('controls', {}).get(
                            '1.2.840.113556.1.4.319', {}).get('value', {}).get('cookie')
                        if not cookie:
                            break
                        self.conn.search(
                            search_base=gpo_dn,
                            search_filter='(objectClass=groupPolicyContainer)',
                            search_scope=SUBTREE,
                            attributes=['displayName', 'cn', 'gPCFileSysPath',
                                        'versionNumber', 'flags', 'whenCreated', 'whenChanged',
                                        'gPCWQLFilter'],
                            paged_size=paged_size,
                            paged_cookie=cookie,
                        )
                        entries += list(self.conn.entries)
                break  # succès
            except Exception as e:
                if paged_size == 0:
                    print(f"[!] Erreur LDAP get_gpos : {e}")
                    return []
                # Réessayer sans paging
                continue
        wmi_filters = self._get_wmi_filters()
        gpos = []
        for entry in entries:
            # entry_attributes_as_dict évite LDAPCursorAttributeError
            # quand un attribut est absent (comportement selon la version de ldap3)
            attrs = entry.entry_attributes_as_dict

            def _get(name, default=''):
                val = attrs.get(name) or attrs.get(name.lower())
                if not val:
                    return default
                v = val[0] if isinstance(val, list) else val
                return str(v) if v is not None else default

            guid   = _get('cn')
            sysvol = _get('gPCFileSysPath')
            if not guid:
                continue

            # Filtre WMI éventuel
            wql_dn = _get('gPCWQLFilter')
            wmi_info = None
            if wql_dn and wql_dn not in ('', 'None', '[]'):
                m = re.search(r'\{([0-9A-Fa-f-]{36})\}', wql_dn)
                if m:
                    wk = '{' + m.group(1).upper() + '}'
                    wmi_info = wmi_filters.get(wk, {
                        'guid': wk, 'name': wk, 'query': wql_dn, 'description': '',
                    })

            # Security Filtering — extraire les groupes/comptes autorisés
            # depuis le nTSecurityDescriptor (ACE avec droit Apply Group Policy)
            security_filter = self._parse_security_filter(attrs)

            gpos.append({
                'name':            _get('displayName') or f'GPO-{guid[:8]}',
                'guid':            guid,
                'sysvol_path':     sysvol,
                'version':         _get('versionNumber', '0'),
                'flags':           _get('flags', '0'),
                'created':         _get('whenCreated'),
                'changed':         _get('whenChanged'),
                'links':           [],
                'settings':        {},
                'registry_entries': [],
                'wmi_filter':      wmi_info,
                'security_filter': security_filter,
            })
        print(f"[+] {len(gpos)} GPO trouvées ({sum(1 for g in gpos if g['wmi_filter'])} avec filtre WMI)")
        return gpos

    def _get_pso_list(self) -> list:
        """Récupère les Fine-Grained Password Policies (msDS-PasswordSettings)."""
        psos = []
        try:
            pso_dn = f"CN=Password Settings Container,CN=System,{self.base_dn}"
            self.conn.search(
                search_base=pso_dn,
                search_filter='(objectClass=msDS-PasswordSettings)',
                search_scope=SUBTREE,
                attributes=['cn', 'msDS-MinimumPasswordLength', 'msDS-PasswordHistoryLength',
                            'msDS-PasswordComplexityEnabled', 'msDS-MaximumPasswordAge',
                            'msDS-LockoutThreshold', 'msDS-PasswordSettingsPrecedence',
                            'msDS-PSOAppliesTo'],
            )
            for entry in self.conn.entries:
                attrs = entry.entry_attributes_as_dict
                def _g(k, d=''):
                    v = attrs.get(k) or attrs.get(k.lower())
                    if not v: return d
                    x = v[0] if isinstance(v, list) else v
                    return str(x) if x else d
                applies_to = attrs.get('msDS-PSOAppliesTo', [])
                if isinstance(applies_to, list):
                    applies_to = [str(x) for x in applies_to]
                psos.append({
                    'name':        _g('cn'),
                    'min_length':  _g('msDS-MinimumPasswordLength'),
                    'history':     _g('msDS-PasswordHistoryLength'),
                    'complexity':  _g('msDS-PasswordComplexityEnabled'),
                    'max_age':     _g('msDS-MaximumPasswordAge'),
                    'lockout':     _g('msDS-LockoutThreshold'),
                    'precedence':  _g('msDS-PasswordSettingsPrecedence'),
                    'applies_to':  applies_to,
                })
        except Exception:
            pass  # CN=Password Settings Container absent si pas de PSO
        return psos

    def _parse_security_filter(self, attrs: dict) -> list:
        """Extrait le Security Filtering d'une GPO depuis nTSecurityDescriptor.
        Retourne la liste des SID avec droit 'Apply Group Policy' (hors Authenticated Users).
        """
        APPLY_GP_GUID = 'edacfd8f-ffb3-11d1-b41d-00a0c968f939'
        AUTHENTICATED_USERS = 'S-1-5-11'
        filters = []
        try:
            raw_sd = attrs.get('nTSecurityDescriptor')
            if not raw_sd:
                return []
            try:
                from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
                sd_bytes = raw_sd[0] if isinstance(raw_sd, list) else raw_sd
                if isinstance(sd_bytes, str):
                    return []
                sd = SR_SECURITY_DESCRIPTOR(data=bytes(sd_bytes))
                if sd['Dacl']:
                    for ace in sd['Dacl']['Data']:
                        if ace['AceType'] == 5:  # ACCESS_ALLOWED_OBJECT_ACE
                            try:
                                obj_guid = str(ace['Ace']['ObjectType']).replace('-','').lower()
                                if APPLY_GP_GUID.replace('-','') in obj_guid:
                                    sid = ace['Ace']['Sid'].formatCanonical()
                                    if AUTHENTICATED_USERS not in sid:
                                        filters.append(sid)
                            except Exception:
                                pass
            except Exception:
                pass
        except Exception:
            pass
        return filters

    def _get_wmi_filters(self) -> dict:
        """Récupère les filtres WMI (msWMI-Som) depuis l'AD."""
        filters = {}
        try:
            wmi_dn = f"CN=SOM,CN=WMIPolicy,CN=System,{self.base_dn}"
            self.conn.search(
                search_base=wmi_dn,
                search_filter='(objectClass=msWMI-Som)',
                search_scope=SUBTREE,
                attributes=['cn', 'msWMI-Name', 'msWMI-Parm1', 'msWMI-Parm2'],
            )
            for entry in self.conn.entries:
                attrs = entry.entry_attributes_as_dict
                def _g(k, d=''):
                    v = attrs.get(k) or attrs.get(k.lower())
                    if not v: return d
                    x = v[0] if isinstance(v, list) else v
                    return str(x) if x else d
                guid = _g('cn')
                if not guid:
                    continue
                query = _g('msWMI-Parm2')
                wql_m = re.search(r'SELECT\s+.+', query, re.IGNORECASE | re.DOTALL)
                filters['{' + guid.strip('{}').upper() + '}'] = {
                    'guid': guid,
                    'name': _g('msWMI-Name') or guid,
                    'query': wql_m.group(0).strip() if wql_m else query[:200],
                    'description': _g('msWMI-Parm1'),
                }
        except Exception:
            pass  # CN=SOM absent si aucun filtre WMI configuré
        return filters

    def get_gpo_links(self):
        # Recherche avec paging pour les grands domaines (beaucoup d'OU)
        entries = []
        # Chercher les liens GPO dans le domaine ET dans les sites AD
        search_bases = [self.base_dn]
        # Ajouter la base de configuration pour les sites réseau
        try:
            config_dn = f"CN=Sites,CN=Configuration,{self.base_dn}"
            search_bases.append(config_dn)
        except Exception:
            pass

        for search_base in search_bases:
            for paged_size in [500, 0]:
                try:
                    self.conn.search(
                        search_base=search_base,
                        search_filter='(gPLink=*)',
                        search_scope=SUBTREE,
                        attributes=['distinguishedName', 'gPLink', 'name'],
                        paged_size=paged_size if paged_size else None,
                    )
                    entries += list(self.conn.entries)
                    if paged_size:
                        while True:
                            cookie = self.conn.result.get('controls', {}).get(
                                '1.2.840.113556.1.4.319', {}).get('value', {}).get('cookie')
                            if not cookie:
                                break
                            self.conn.search(
                                search_base=search_base,
                                search_filter='(gPLink=*)',
                                search_scope=SUBTREE,
                                attributes=['distinguishedName', 'gPLink', 'name'],
                                paged_size=paged_size,
                                paged_cookie=cookie,
                            )
                            entries += list(self.conn.entries)
                    break
                except Exception:
                    if paged_size == 0:
                        break
                    continue

        links = {}
        # Regex robuste : UUID format standard dans un bloc [LDAP://...;flag]
        GPLINK_RE = re.compile(
            r'\[LDAP://[^\]]*\{([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}'
            r'-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\}[^;]*;(\d+)\]',
            re.IGNORECASE
        )
        for entry in entries:
            attrs = entry.entry_attributes_as_dict
            def _g(k, d=''):
                v = attrs.get(k) or attrs.get(k.lower())
                if not v: return d
                x = v[0] if isinstance(v, list) else v
                return str(x) if x else d
            gp_link = _g('gPLink')
            ou_dn   = _g('distinguishedName')
            if not gp_link or not ou_dn:
                continue
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
            self._smb_errors = 0

            # Détecter le nom exact du partage SYSVOL
            all_shares = [s['shi1_netname'].rstrip('\x00') for s in smb.listShares()]
            sysvol_shares = [s for s in all_shares if s.upper() == 'SYSVOL']
            self._sysvol_share = sysvol_shares[0] if sysvol_shares else 'SYSVOL'
            print(f"    [+] SMB connecté — partages : {all_shares}")

            # Détecter le préfixe de chemin SYSVOL sans dépendre d'un GUID spécifique.
            # On cherche le dossier Policies sous différents préfixes possibles.
            # Certains AD exposent \\domaine\SYSVOL\domaine\Policies
            # D'autres \\domaine\SYSVOL\Policies directement
            # D'autres encore avec le nom NetBIOS au lieu du FQDN
            netbios = self.domain.split('.')[0].upper()
            prefixes_to_try = list(dict.fromkeys([
                self.domain,           # FQDN : sdis25.lan
                netbios,               # NetBIOS : SDIS25
                self.domain.upper(),
                self.domain.lower(),
                '',                    # pas de préfixe
            ]))

            self._smb_path_prefix = self.domain  # défaut
            for prefix in prefixes_to_try:
                test_path = (f"\\{prefix}\\Policies\\" if prefix else "\\Policies\\") + '*'
                try:
                    smb.listPath(self._sysvol_share, test_path)
                    self._smb_path_prefix = prefix
                    label = prefix if prefix else '(aucun)'
                    print(f"    [+] Préfixe SYSVOL détecté : '{label}'")
                    break
                except Exception:
                    continue
            else:
                print(f"    [!] Préfixe SYSVOL non détecté — utilisation de '{self.domain}'")

            return True
        except Exception as e:
            self._smb = None
            self._sysvol_share = 'SYSVOL'
            self._smb_path_prefix = self.domain
            self._smb_errors = 0
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
            """Chemin relatif impacket en tenant compte du préfixe détecté."""
            try:
                pol_i = next(i for i,s in enumerate(segs_base) if s.lower() == 'policies')
                after = segs_base[pol_i+1:] + list(parts)
            except StopIteration:
                after = segs_base + list(parts)
            prefix = getattr(self, '_smb_path_prefix', self.domain)
            if prefix:
                return '\\' + prefix + '\\Policies\\' + '\\'.join(after)
            else:
                return '\\Policies\\' + '\\'.join(after)

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

        # ── Nouveaux parseurs ──
        x = rx('Machine', 'Preferences', 'Applications', 'Applications.xml')
        if x: gpo['software_machine'] = parse_software_xml(x)

        x = rx('User', 'Preferences', 'Applications', 'Applications.xml')
        if x: gpo['software_user'] = parse_software_xml(x)

        x = rx('Machine', 'Preferences', 'IniFiles', 'IniFiles.xml')
        if x: gpo['ini_files_machine'] = parse_ini_files_xml(x)

        x = rx('User', 'Preferences', 'IniFiles', 'IniFiles.xml')
        if x: gpo['ini_files_user'] = parse_ini_files_xml(x)

        x = rx('Machine', 'Preferences', 'DataSources', 'DataSources.xml')
        if x: gpo['datasources_machine'] = parse_datasources_xml(x)

        x = rx('User', 'Preferences', 'DataSources', 'DataSources.xml')
        if x: gpo['datasources_user'] = parse_datasources_xml(x)

        x = rx('User', 'Preferences', 'InternetSettings', 'InternetSettings.xml')
        if x: gpo['internet_settings'] = parse_internet_settings_xml(x)

        x = rx('Machine', 'Preferences', 'NetworkShares', 'NetworkShares.xml')
        if x: gpo['network_shares'] = parse_network_shares_xml(x)

        x = rx('Machine', 'Preferences', 'Folders', 'Folders.xml')
        if x: gpo['folders_machine'] = parse_folders_xml(x)

        x = rx('User', 'Preferences', 'Folders', 'Folders.xml')
        if x: gpo['folders_user'] = parse_folders_xml(x)

        x = rx('User', 'Preferences', 'Regional', 'Regional.xml')
        if x: gpo['regional'] = parse_regional_xml(x)

        x = rx('User', 'Preferences', 'NetworkOptions', 'NetworkOptions.xml')
        if x: gpo['network_options'] = parse_network_options_xml(x)

        # Décodage ADMX des clés Registry.pol
        if gpo.get('registry_entries'):
            gpo['registry_admx'] = parse_admx_registry(gpo['registry_entries'])
        if gpo.get('registry_entries_user'):
            gpo['registry_admx_user'] = parse_admx_registry(gpo['registry_entries_user'])

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

        # ── Scripts (scripts.ini + psscripts.ini) ──────────────────────────
        # scripts.ini machine  → sections [Startup] [Shutdown]
        # scripts.ini user     → sections [Logon]   [Logoff]
        # psscripts.ini machine → idem mais pour PowerShell
        # psscripts.ini user   → idem

        sm_ini = rt('Machine', 'Scripts', 'scripts.ini') or ''
        su_ini = rt('User',    'Scripts', 'scripts.ini') or ''
        ps_m   = rt('Machine', 'Scripts', 'psscripts.ini') or ''
        ps_u   = rt('User',    'Scripts', 'psscripts.ini') or ''

        sc = {'startup': [], 'shutdown': [], 'logon': [], 'logoff': []}

        # Parser scripts.ini
        base = parse_scripts(sm_ini, sm_ini, su_ini, su_ini)
        for k in sc: sc[k] += base.get(k, [])

        # Parser psscripts.ini machine (sections Startup/Shutdown)
        if ps_m:
            ps = parse_psscripts_ini(ps_m, is_user=False)
            sc['startup']  += ps.get('startup', [])
            sc['shutdown'] += ps.get('shutdown', [])

        # Parser psscripts.ini user (sections Logon/Logoff)
        if ps_u:
            ps_u_p = parse_psscripts_ini(ps_u, is_user=True)
            sc['logon']  += ps_u_p.get('logon', [])
            sc['logoff'] += ps_u_p.get('logoff', [])

        # Fallback : lister les fichiers dans les dossiers SYSVOL si tout est vide
        if not any(sc.values()):
            def _ls(path):
                return [{'cmd': f.get_longname(), 'params': ''}
                        for f in self._list_scripts(path) if f.get_longname()]
            sc['startup']  = _ls(smb_rel('Machine', 'Scripts', 'Startup'))
            sc['shutdown'] = _ls(smb_rel('Machine', 'Scripts', 'Shutdown'))
            sc['logon']    = _ls(smb_rel('User',    'Scripts', 'Logon'))
            sc['logoff']   = _ls(smb_rel('User',    'Scripts', 'Logoff'))

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
        if gpo.get('software_machine') or gpo.get('software_user'): parts.append('logiciels')
        if gpo.get('network_shares'): parts.append('partages réseau')
        if gpo.get('datasources_machine') or gpo.get('datasources_user'): parts.append('ODBC')
        if gpo.get('internet_settings'): parts.append('proxy/internet')
        if gpo.get('network_options'): parts.append('VPN/réseau')
        if gpo.get('folders_machine') or gpo.get('folders_user'): parts.append('dossiers')
        if gpo.get('ini_files_machine') or gpo.get('ini_files_user'): parts.append('INI')
        if gpo.get('registry_admx'): parts.append(f"{len(gpo['registry_admx'])} clés ADMX")
        if parts:
            print(f"    [+] {gpo['name']} : {', '.join(parts)}")

    def _list_scripts(self, rel_path: str) -> list:
        """Liste les scripts dans un dossier SYSVOL via SMB."""
        if not getattr(self, '_smb', None):
            return []
        try:
            files = self._smb.listPath(self._sysvol_share, rel_path + '\\*')
            return [
                f for f in files
                if f.get_longname() not in ('..', '.', '')
                and not f.is_directory()
            ]
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
        # Attacher les PSO aux données pour analyze_gpos
        for gpo in gpos:
            gpo['_pso_list'] = getattr(self, '_pso_list', [])
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
            'guid': '{E45F7081-2222-3333-4444-555566667777}',
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
            'guid': '{F5608892-3333-4444-5555-666677778888}',
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
            # Pour privilege_rights : résoudre les SIDs en noms lisibles
            display_v = v
            if sec_key == 'privilege_rights' and v:
                resolved = []
                for sid_raw in v.split(','):
                    sid_raw = sid_raw.strip()
                    if not sid_raw:
                        continue
                    clean = sid_raw.lstrip('*').lower()
                    _SID_NAMES = {
                        's-1-5-32-544':'Administrateurs','s-1-5-32-545':'Utilisateurs',
                        's-1-5-32-546':'Invités','s-1-5-32-551':'Opérateurs de sauvegarde',
                        's-1-5-32-555':'Utilisateurs Bureau à distance',
                        's-1-5-11':'Utilisateurs authentifiés','s-1-5-18':'Système local',
                        's-1-5-19':'Service local','s-1-5-20':'Service réseau',
                        's-1-1-0':'Tout le monde','s-1-5-4':'Service interactif',
                        's-1-5-6':'Service','s-1-5-9':'Contrôleurs de domaine',
                        's-1-3-0':'Créateur propriétaire',
                    }
                    name = _SID_NAMES.get(clean, sid_raw)
                    # Comptes de domaine (SID long) — on garde le SID mais sans le *
                    if name == sid_raw and sid_raw.startswith('*'):
                        name = sid_raw[1:]  # retirer le * mais garder le SID
                    resolved.append(name)
                display_v = ', '.join(resolved)
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
            params.append({'key': k, 'value': display_v, 'label': label, 'hint': hint, 'alert': alert})
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

    # ── Registre décodé ADMX (Machine) ──────────────────────────────────────
    admx = gpo.get('registry_admx', [])
    if admx:
        # Grouper par catégorie
        by_cat = {}
        for r in admx:
            cat = r.get('category', 'Registre')
            by_cat.setdefault(cat, []).append(r)
        for cat, items in sorted(by_cat.items()):
            params = []
            for r in items:
                params.append({
                    'key':   r['label'],
                    'value': r['value'],
                    'label': r['label'],
                    'hint':  r.get('hint', ''),
                    'alert': r.get('alert'),
                })
            sections.append({'title': f'Paramètres ADMX — {cat} (Machine)', 'icon': '⚙', 'params': params})

    # ── Registre décodé ADMX (Utilisateur) ──────────────────────────────────
    admx_u = gpo.get('registry_admx_user', [])
    if admx_u:
        by_cat = {}
        for r in admx_u:
            cat = r.get('category', 'Registre')
            by_cat.setdefault(cat, []).append(r)
        for cat, items in sorted(by_cat.items()):
            params = []
            for r in items:
                params.append({
                    'key':   r['label'],
                    'value': r['value'],
                    'label': r['label'],
                    'hint':  r.get('hint', ''),
                    'alert': r.get('alert'),
                })
            sections.append({'title': f'Paramètres ADMX — {cat} (Utilisateur)', 'icon': '⚙', 'params': params})

    # ── Logiciels / Applications ─────────────────────────────────────────────
    for scope, key in [('Machine', 'software_machine'), ('Utilisateur', 'software_user')]:
        items = gpo.get(key, [])
        if items:
            params = []
            for s in items:
                alert = None
                if s['action'] == 'Désinstaller':
                    alert = f"Désinstalle : {s['name']}"
                params.append({
                    'key':   s['name'],
                    'value': s['path'] or '',
                    'label': f"{s['action']}{' v'+s['version'] if s.get('version') else ''}{' · '+s['publisher'] if s.get('publisher') else ''}",
                    'hint':  '',
                    'alert': alert,
                })
            sections.append({'title': f'Logiciels / Applications — {scope}', 'icon': '📦', 'params': params})

    # ── Partages réseau ──────────────────────────────────────────────────────
    shares = gpo.get('network_shares', [])
    if shares:
        params = [{'key': s['name'], 'value': s['path'], 'label': s['action'],
                   'hint': s.get('comment', ''), 'alert': None} for s in shares]
        sections.append({'title': 'Partages réseau', 'icon': '🗂', 'params': params})

    # ── Sources de données ODBC ──────────────────────────────────────────────
    for scope, key in [('Machine', 'datasources_machine'), ('Utilisateur', 'datasources_user')]:
        items = gpo.get(key, [])
        if items:
            params = [{'key': d['name'], 'value': d.get('server', '') + ('/' + d.get('db', '') if d.get('db') else ''),
                       'label': d.get('driver', ''), 'hint': d.get('scope', ''), 'alert': None} for d in items]
            sections.append({'title': f'Sources de données ODBC — {scope}', 'icon': '🗃', 'params': params})

    # ── Paramètres Internet / Proxy ──────────────────────────────────────────
    inet = gpo.get('internet_settings', [])
    if inet:
        params = []
        for s in inet:
            if s.get('proxy'):
                params.append({'key': 'Serveur proxy', 'value': s['proxy'],
                               'label': 'Activé' if s.get('enabled') else 'Désactivé',
                               'hint': f"Bypass : {s.get('bypass', '')}", 'alert': None})
            if s.get('home'):
                params.append({'key': 'Page d\'accueil', 'value': s['home'],
                               'label': '', 'hint': '', 'alert': None})
        if params:
            sections.append({'title': 'Paramètres Internet / Proxy', 'icon': '🌐', 'params': params})

    # ── Options réseau / VPN ─────────────────────────────────────────────────
    netopts = gpo.get('network_options', [])
    if netopts:
        params = [{'key': n['name'], 'value': n.get('server', ''),
                   'label': n['type'], 'hint': n.get('action', ''), 'alert': None} for n in netopts]
        sections.append({'title': 'Options réseau / VPN', 'icon': '🔌', 'params': params})

    # ── Dossiers ─────────────────────────────────────────────────────────────
    for scope, key in [('Machine', 'folders_machine'), ('Utilisateur', 'folders_user')]:
        items = gpo.get(key, [])
        if items:
            params = [{'key': f['path'], 'value': f['action'],
                       'label': f['action'], 'hint': '', 'alert': None} for f in items]
            sections.append({'title': f'Dossiers — {scope}', 'icon': '📁', 'params': params})

    # ── Fichiers INI ─────────────────────────────────────────────────────────
    for scope, key in [('Machine', 'ini_files_machine'), ('Utilisateur', 'ini_files_user')]:
        items = gpo.get(key, [])
        if items:
            params = [{'key': f"{i['path']} [{i['section']}]", 'value': f"{i['property']} = {i['value']}",
                       'label': i['action'] or '', 'hint': '', 'alert': None} for i in items]
            sections.append({'title': f'Fichiers INI — {scope}', 'icon': '📝', 'params': params})

    # ── Paramètres régionaux ─────────────────────────────────────────────────
    regional = gpo.get('regional', [])
    if regional:
        params = []
        for r in regional:
            if r.get('locale'):
                params.append({'key': 'Paramètres régionaux', 'value': r['locale'], 'label': '', 'hint': '', 'alert': None})
            if r.get('timezone'):
                params.append({'key': 'Fuseau horaire', 'value': r['timezone'], 'label': '', 'hint': '', 'alert': None})
        if params:
            sections.append({'title': 'Paramètres régionaux', 'icon': '🌍', 'params': params})

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



# ─── GPO par défaut Windows AD ────────────────────────────────────────────────
# Ces GPO ne doivent JAMAIS être modifiées — créer des GPO dédiées à la place.
# Si elles ont été modifiées, c'est un écart de configuration à signaler.

DEFAULT_GPOS = {
    '{31B2F340-016D-11D2-945F-00C04FB984F9}': {
        'name': 'Default Domain Policy',
        'purpose': 'Politique de mots de passe et de verrouillage du domaine uniquement',
        'should_contain': ['password_policy', 'system_access', 'kerberos_policy'],
        'should_not_contain': [
            # registry_entries (Registry.pol) est normal — contient les paramètres ADMX
            # registry_xml_machine (préférences registre) est différent — c'est suspect
            'registry_xml_machine',
            'printers', 'drives', 'scripts',
            'scheduled_tasks', 'groups',
        ],
    },
    '{6AC1786C-016F-11D2-945F-00C04FB984F9}': {
        'name': 'Default Domain Controllers Policy',
        'purpose': 'Droits utilisateurs sur les contrôleurs de domaine uniquement',
        'should_contain': ['privilege_rights', 'event_audit'],
        'should_not_contain': [
            # registry_entries (Registry.pol/ADMX) acceptable
            'registry_xml_machine',
            'printers', 'drives', 'scripts',
            'scheduled_tasks', 'groups',
            'password_policy',
        ],
    },
}


def check_default_gpo_modifications(gpos: list) -> list:
    """
    Détecte si les GPO par défaut ont été modifiées au-delà de leur usage normal.
    Génère un plan de migration détaillé : quoi déplacer, vers quelle GPO, dans quel ordre.
    """
    findings = []

    # Table de classification : quel type de contenu → quelle GPO dédiée recommandée
    MIGRATION_GROUPS = {
        'registry_entries': {
            'gpo_name': 'O-Securite-Registre',
            'label':    'Clés de registre (Registry.pol)',
            'scope':    'Configuration ordinateur → Préférences → Registre',
            'ou_link':  'Domaine ou OU Computers selon la cible',
        },
        'registry_xml_machine': {
            'gpo_name': 'O-Preferences-Registre',
            'label':    'Préférences registre XML (Registry.xml)',
            'scope':    'Configuration ordinateur → Préférences → Registre',
            'ou_link':  'Domaine ou OU Computers selon la cible',
        },
        'printers': {
            'gpo_name': 'O-Imprimantes-Machine',
            'label':    'Imprimantes machine',
            'scope':    'Configuration ordinateur → Préférences → Imprimantes',
            'ou_link':  'OU contenant les postes concernés',
        },
        'printers_user': {
            'gpo_name': 'U-Imprimantes',
            'label':    'Imprimantes utilisateur',
            'scope':    'Configuration utilisateur → Préférences → Imprimantes',
            'ou_link':  'OU contenant les utilisateurs concernés',
        },
        'drives': {
            'gpo_name': 'U-Lecteurs-Reseau',
            'label':    'Lecteurs réseau',
            'scope':    'Configuration utilisateur → Préférences → Lecteurs mappés',
            'ou_link':  'OU contenant les utilisateurs concernés',
        },
        'scripts': {
            'gpo_name': 'O-Scripts-Demarrage',
            'label':    'Scripts de démarrage/arrêt',
            'scope':    'Configuration ordinateur → Paramètres Windows → Scripts',
            'ou_link':  'Domaine ou OU selon la portée des scripts',
        },
        'scheduled_tasks': {
            'gpo_name': 'O-Taches-Planifiees',
            'label':    'Tâches planifiées',
            'scope':    'Configuration ordinateur → Préférences → Tâches planifiées',
            'ou_link':  'OU contenant les machines cibles',
        },
        'groups': {
            'gpo_name': 'O-Groupes-Locaux',
            'label':    'Groupes locaux',
            'scope':    'Configuration ordinateur → Préférences → Utilisateurs et groupes locaux',
            'ou_link':  'OU contenant les machines cibles',
        },
        'services': {
            'gpo_name': 'O-Services-Windows',
            'label':    'Services Windows',
            'scope':    'Configuration ordinateur → Préférences → Services',
            'ou_link':  'OU contenant les machines cibles',
        },
        'software_machine': {
            'gpo_name': 'O-Logiciels',
            'label':    'Installation de logiciels',
            'scope':    'Configuration ordinateur → Préférences → Applications',
            'ou_link':  'OU contenant les machines cibles',
        },
        'network_shares': {
            'gpo_name': 'O-Partages-Reseau',
            'label':    'Partages réseau',
            'scope':    'Configuration ordinateur → Préférences → Partages réseau',
            'ou_link':  'OU Servers ou Computers selon la cible',
        },
        'audit_csv': {
            'gpo_name': 'O-Audit-Avance',
            'label':    'Audit avancé (audit.csv)',
            'scope':    'Configuration ordinateur → Paramètres Windows → Paramètres de sécurité → Configuration avancée stratégie d\'audit',
            'ou_link':  'Domaine (tous les postes) ou OU Servers pour les serveurs',
        },
    }

    # Sections GptTmpl.inf inattendues dans la DDCP
    SETTINGS_MIGRATION = {
        'password_policy': {
            'gpo_name': 'Default Domain Policy',
            'label':    'Politique de mots de passe',
            'scope':    'Configuration ordinateur → Stratégies → Paramètres de sécurité → Stratégies de compte',
            'ou_link':  'Doit rester dans Default Domain Policy uniquement',
            'warning':  'La politique de mots de passe DOIT être dans Default Domain Policy, pas dans DDCP',
        },
        'event_audit': {
            'gpo_name': 'O-Audit-Evenements',
            'label':    'Audit des événements',
            'scope':    'Configuration ordinateur → Stratégies → Paramètres de sécurité → Stratégies locales → Stratégie d\'audit',
            'ou_link':  'Domaine pour tous, ou OU Servers/Workstations si différenciation',
        },
        'registry_values': {
            'gpo_name': 'O-Securite-Options',
            'label':    'Options de sécurité (Registry Values)',
            'scope':    'Configuration ordinateur → Stratégies → Paramètres de sécurité → Stratégies locales → Options de sécurité',
            'ou_link':  'Domaine ou OU selon la portée',
        },
        'system_access': {
            'gpo_name': 'O-Securite-Options',
            'label':    'Paramètres d\'accès système',
            'scope':    'Configuration ordinateur → Stratégies → Paramètres de sécurité → Stratégies locales → Options de sécurité',
            'ou_link':  'Domaine ou OU selon la portée',
        },
    }

    for gpo in gpos:
        guid = gpo.get('guid', '').upper()
        default_info = DEFAULT_GPOS.get(guid)
        if not default_info:
            continue

        name     = default_info['name']
        purpose  = default_info['purpose']
        should_not = default_info['should_not_contain']

        # ── Détecter le contenu problématique et construire le plan de migration ──
        migration_plan = []   # liste de {gpo_cible, label, items, scope, ou_link}
        problematic_labels = []

        for key in should_not:
            content = gpo.get(key)
            if not content:
                continue
            info = MIGRATION_GROUPS.get(key)
            if not info:
                continue
            problematic_labels.append(info['label'])

            # Extraire les détails du contenu pour le plan
            items_detail = []
            if key == 'registry_entries':
                for (reg_key, vname, rtype, val) in (content or [])[:10]:
                    items_detail.append(f"{reg_key.split(chr(92))[-1]} → {vname} = {val}")
            elif key == 'scripts':
                for scope_k, scope_label in [('startup','Démarrage'),('shutdown','Arrêt'),('logon','Ouverture session'),('logoff','Fermeture session')]:
                    for sc in (content.get(scope_k) or []):
                        cmd = sc.get('cmd','') if isinstance(sc, dict) else str(sc)
                        if cmd:
                            items_detail.append(f"[{scope_label}] {cmd}")
            elif key == 'printers':
                for p in (content or [])[:5]:
                    items_detail.append(f"{p.get('name','')} → {p.get('path','')}")
            elif key == 'drives':
                for d in (content or [])[:5]:
                    items_detail.append(f"{d.get('letter','')}:\\ → {d.get('path','')}")
            elif key == 'scheduled_tasks':
                for t in (content or [])[:5]:
                    items_detail.append(f"{t.get('name','')} : {t.get('cmd','')}")
            elif key == 'groups':
                for g in (content or [])[:5]:
                    members = ', '.join(m.get('name','') for m in g.get('members',[])[:3])
                    items_detail.append(f"{g.get('name','')} ← {members}")
            elif key == 'services':
                for s in (content or [])[:5]:
                    items_detail.append(f"{s.get('name','')} : {s.get('startup','')}")
            elif key == 'registry_xml_machine':
                for r in (content or [])[:5]:
                    items_detail.append(f"{r.get('key','').split(chr(92))[-1]} → {r.get('name','')} = {r.get('value','')}")
            elif key == 'audit_csv':
                for a in (content or [])[:5]:
                    items_detail.append(f"{a.get('subcategory','')} : {a.get('inclusion','')}")

            extra = max(0, len(items_detail) - 8)
            migration_plan.append({
                'gpo_name':    info['gpo_name'],
                'label':       info['label'],
                'scope':       info['scope'],
                'ou_link':     info['ou_link'],
                'items':       items_detail[:8],
                'extra_count': extra,
                'count':      len(content) if isinstance(content, list) else
                              sum(len(v) for v in content.values() if isinstance(v, list))
                              if isinstance(content, dict) else 1,
            })

        # Sections settings inattendues (pour DDCP principalement)
        settings = gpo.get('settings', {})
        if guid == '{6AC1786C-016F-11D2-945F-00C04FB984F9}':
            allowed_sections = {'privilege_rights', 'event_audit', 'system_access', 'registry_values'}
            for section, params in settings.items():
                if section not in allowed_sections and params and any(v for v in params.values() if v):
                    info = SETTINGS_MIGRATION.get(section, {
                        'gpo_name': 'O-Securite-Custom',
                        'label': section,
                        'scope': 'Configuration ordinateur → Paramètres de sécurité',
                        'ou_link': 'Selon la portée du paramètre',
                    })
                    if info.get('warning'):
                        problematic_labels.append(f"{info['label']} ⚠ {info['warning']}")
                    else:
                        problematic_labels.append(info['label'])
                        migration_plan.append({
                            'gpo_name': info['gpo_name'],
                            'label':    info['label'],
                            'scope':    info['scope'],
                            'ou_link':  info['ou_link'],
                            'params_list': [f"{k} = {v}" for k, v in list(params.items())[:5]],
                            'count':    len(params),
                        })

        if problematic_labels:
            # Dédupliquer le plan de migration par GPO cible
            merged_plan = {}
            for step in migration_plan:
                key = step['gpo_name']
                if key not in merged_plan:
                    merged_plan[key] = dict(step)
                else:
                    merged_plan[key]['params_list'] += step['params_list']
                    merged_plan[key]['count'] += step['count']
                    if step['label'] not in merged_plan[key]['label']:
                        merged_plan[key]['label'] += ' + ' + step['label']

            findings.append({
                'rule_id':        f'DEFAULT-GPO-{guid[:8]}',
                'title':          f'GPO par défaut modifiée : {name}',
                'severity':       'warning',
                'ref':            'Bonne pratique AD · ANSSI R-AD · MS Best Practices',
                'category':       'Gouvernance GPO',
                'rec_value':      'Ne jamais modifier ces GPO — créer des GPO dédiées',
                'migration_plan': list(merged_plan.values()),
                'detail': (
                    f'Contenu détecté hors usage normal : {", ".join(problematic_labels)}. '
                    f'Usage attendu : {purpose}.'
                ),
                'remediation': (
                    f'La GPO "{name}" contient des paramètres non standards.\n'
                    f'Usage attendu : {purpose} uniquement.\n\n'
                    'Voir le plan de migration ci-dessous pour savoir quoi créer et où déplacer.'
                ),
                'not_configured': False,
                'source_gpos':    [{'name': gpo['name'], 'guid': gpo['guid']}],
            })
        else:
            findings.append({
                'rule_id':        f'DEFAULT-GPO-OK-{guid[:8]}',
                'title':          f'{name} — non modifiée ✓',
                'severity':       'good',
                'ref':            'Bonne pratique AD · ANSSI R-AD',
                'category':       'Gouvernance GPO',
                'rec_value':      'Correct',
                'migration_plan': [],
                'remediation':    '',
                'detail':         f'La GPO par défaut "{name}" n\'a pas été modifiée — conforme aux bonnes pratiques.',
                'not_configured': False,
            })

    return findings

def detect_catchall_gpos(gpos: list) -> list:
    """Détecte les GPO fourre-tout.
    Critères (OR) :
    1. ≥ 3 catégories fonctionnelles distinctes avec du contenu réel
    2. Volume total de paramètres ≥ 30 (GPO trop générique)
    3. Config ordinateur + utilisateur mélangées avec ≥ 2 catégories
    """
    CATCHALL_THRESHOLD_CATS   = 3
    CATCHALL_THRESHOLD_PARAMS = 30
    DEFAULT_GUIDS = {'{31B2F340-016D-11D2-945F-00C04FB984F9}',
                     '{6AC1786C-016F-11D2-945F-00C04FB984F9}'}

    FUNC_CATEGORIES = {
        'Politique de mots de passe': [('settings','password_policy')],
        'Audit des événements':       [('settings','event_audit')],
        'Droits utilisateurs':        [('settings','privilege_rights')],
        'Options de sécurité':        [('settings','system_access'),('settings','registry_values')],
        'Kerberos':                   [('settings','kerberos_policy')],
        'Paramètres ADMX':            [('gpo','registry_entries'), ('gpo','registry_admx'), ('gpo','registry_admx_user')],
        'Préférences registre':       [('gpo','registry_xml_machine'),('gpo','registry_xml_user')],
        'Copie de fichiers':          [('gpo','files_machine'),('gpo','files_user')],
        'Scripts':                    [('gpo','scripts')],
        'Imprimantes':                [('gpo','printers'),('gpo','printers_user')],
        'Lecteurs réseau':            [('gpo','drives'),('gpo','drives_user')],
        'Tâches planifiées':          [('gpo','scheduled_tasks')],
        'Groupes locaux':             [('gpo','groups')],
        'Services':                   [('gpo','services')],
        'Logiciels':                  [('gpo','software_machine'),('gpo','software_user')],
        'Partages réseau':            [('gpo','network_shares')],
        'Dossiers':                   [('gpo','folders_machine'),('gpo','folders_user')],
        'Options réseau / VPN':       [('gpo','network_options')],
        'Internet / Proxy':           [('gpo','internet_settings')],
    }

    SUGGESTIONS_MAP = {
        'Politique de mots de passe': 'O-Securite-MotsDePasse → politique de mots de passe',
        'Audit des événements':       'O-Audit-Evenements → configuration de l\'audit',
        'Scripts':                    'O-Scripts-Logon → scripts logon/logoff | O-Scripts-Machine → startup/shutdown',
        'Imprimantes':                'O-Imprimantes → déploiement d\'imprimantes',
        'Préférences registre':       'O-Securite-Registre → paramètres de registre',
        'Logiciels':                  'O-Logiciels → installation de logiciels',
        'Tâches planifiées':          'O-Taches-Planifiees → tâches planifiées',
        'Droits utilisateurs':        'O-Droits-Utilisateurs → attribution des droits',
        'Lecteurs réseau':            'U-Lecteurs-Reseau → lecteurs réseau mappés',
        'Groupes locaux':             'O-Groupes-Locaux → groupes locaux',
        'Services':                   'O-Services-Windows → services Windows',
        'Partages réseau':            'O-Partages-Reseau → partages réseau',
        'Options réseau / VPN':       'U-VPN-Connexions → options réseau/VPN',
        'Kerberos':                   'Default Domain Policy → stratégie Kerberos',
        'Options de sécurité':        'O-Securite-Options → options de sécurité',
        'Paramètres ADMX':            'O-Securite-ADMX → paramètres de stratégie (ADMX)',
    }

    findings = []
    for gpo in gpos:
        if gpo.get('guid', '').upper() in DEFAULT_GUIDS:
            continue
        if not gpo.get('links'):
            continue
        settings = gpo.get('settings', {})

        # ── Catégories présentes ────────────────────────────────────────────
        present = []
        for cat_name, sources in FUNC_CATEGORIES.items():
            for (src_type, key) in sources:
                content = gpo.get(key) if src_type == 'gpo' else settings.get(key)
                if not content:
                    continue
                if key == 'scripts':
                    # Vérifier que les scripts ont vraiment un cmd non vide
                    has = any(
                        isinstance(v, dict) and v.get('cmd')
                        for lst in content.values() if isinstance(lst, list)
                        for v in lst
                    )
                    if has:
                        present.append(cat_name); break
                elif isinstance(content, list) and len(content) > 0:
                    present.append(cat_name); break
                elif isinstance(content, dict) and any(v for v in content.values() if v):
                    present.append(cat_name); break

        # ── Volume total de paramètres ──────────────────────────────────────
        total_params = 0
        total_params += len(gpo.get('registry_entries', []))
        total_params += len(gpo.get('registry_entries_user', []))
        total_params += len(gpo.get('registry_admx', []))        # clés ADMX décodées machine
        total_params += len(gpo.get('registry_admx_user', []))   # clés ADMX décodées user
        total_params += len(gpo.get('registry_xml_machine', []))
        total_params += len(gpo.get('registry_xml_user', []))
        total_params += len(gpo.get('printers', []))
        total_params += len(gpo.get('printers_user', []))
        total_params += len(gpo.get('drives', []))
        total_params += len(gpo.get('drives_user', []))
        total_params += len(gpo.get('scheduled_tasks', []))
        total_params += len(gpo.get('groups', []))
        total_params += len(gpo.get('services', []))
        total_params += len(gpo.get('files_machine', []))
        total_params += len(gpo.get('files_user', []))
        total_params += len(gpo.get('software_machine', []))
        total_params += len(gpo.get('software_user', []))
        total_params += len(gpo.get('network_shares', []))
        total_params += sum(
            len(lst) for lst in (gpo.get('scripts') or {}).values()
            if isinstance(lst, list)
        )
        for section_data in settings.values():
            if isinstance(section_data, dict):
                total_params += sum(1 for v in section_data.values() if v)

        # ── Ordinateur + Utilisateur mélangés ──────────────────────────────
        scripts = gpo.get('scripts') or {}
        has_computer = any([
            bool(gpo.get('registry_entries')),
            bool(gpo.get('registry_admx')),      # ADMX décodés machine
            bool(gpo.get('printers')),
            bool(gpo.get('registry_xml_machine')),
            bool(gpo.get('files_machine')),
            bool(settings.get('password_policy')),
            bool(settings.get('event_audit')),
            bool(settings.get('privilege_rights')),
            any(isinstance(v,dict) and v.get('cmd') for v in scripts.get('startup',[]) + scripts.get('shutdown',[])),
        ])
        has_user = any([
            bool(gpo.get('drives')),
            bool(gpo.get('printers_user')),
            bool(gpo.get('registry_xml_user')),
            bool(gpo.get('registry_admx_user')),  # ADMX décodés user
            bool(gpo.get('files_user')),
            bool(gpo.get('internet_settings')),
            any(isinstance(v,dict) and v.get('cmd') for v in scripts.get('logon',[]) + scripts.get('logoff',[])),
        ])
        mixed_scopes = has_computer and has_user
        if mixed_scopes and 'Config. ordinateur + utilisateur' not in present:
            present.append('Config. ordinateur + utilisateur')

        # ── Décision ────────────────────────────────────────────────────────
        is_catchall = (
            len(present) >= CATCHALL_THRESHOLD_CATS
            or total_params >= CATCHALL_THRESHOLD_PARAMS
            or (mixed_scopes and len(present) >= 2)
        )

        if is_catchall:
            suggestions = [SUGGESTIONS_MAP[c] for c in present if c in SUGGESTIONS_MAP]
            reason = []
            if len(present) >= CATCHALL_THRESHOLD_CATS:
                reason.append(f"{len(present)} catégories fonctionnelles")
            if total_params >= CATCHALL_THRESHOLD_PARAMS:
                reason.append(f"{total_params} paramètres au total")
            if mixed_scopes and len(present) >= 2:
                reason.append("Ordinateur + Utilisateur mélangés")
            findings.append({
                'gpo_name':    gpo['name'],
                'gpo_guid':    gpo['guid'],
                'categories':  present,
                'cat_count':   len(present),
                'total_params':total_params,
                'reason':      ' · '.join(reason),
                'suggestions': suggestions,
                'links':       gpo.get('links', []),
            })
    return findings



    # Poids par règle (points de risque ajoutés au score de la catégorie)
# Plafond par catégorie : 100 pts max
RULE_WEIGHTS = {
    # ── Authentification — vulnérabilités critiques d'auth réseau ──────────
    'AUTH-001': 100,  # Hash LM stocké — cassé en secondes (rainbow tables)
    'AUTH-002': 100,  # NTLMv1 autorisé — capturé et craqué facilement
    'AUTH-003':  30,  # Pas de verrouillage — brute-force illimité
    'AUTH-004':  15,  # Verrouillage trop court
    # ── Mots de passe ──────────────────────────────────────────────────────
    'PWD-001':   40,  # Longueur < 14 — craquable
    'PWD-002':   25,  # Historique court — réutilisation cyclique
    'PWD-003':   50,  # Pas de complexité — dictionnaire trivial
    'PWD-004':   20,  # Durée illimitée ou excessive
    'PWD-005':    5,  # Avertissement trop court
    'PWD-006':   15,  # Durée minimale = 0 — contourne l'historique
    # ── Système — exposition mémoire et protocoles ─────────────────────────
    'SYS-001': 100,  # WDigest — mots de passe en clair dans lsass
    'SYS-002':  70,  # SMBv1 — EternalBlue/WannaCry
    'SYS-003':  40,  # Pare-feu désactivé
    'SYS-004':  20,  # AutoRun actif — USB malveillante
    'SYS-005':  10,  # Credential Guard absent
    # ── UAC & Élévation ────────────────────────────────────────────────────
    'UAC-001': 100,  # UAC désactivé — escalade silencieuse
    'UAC-002':  80,  # Admins sans demande UAC
    'UAC-003':  25,  # Compte admin intégré non filtré
    'UAC-004':  80,  # Token plein comptes locaux — Pass-the-Hash
    # ── Protocoles réseau ──────────────────────────────────────────────────
    'SMB-001':  35,  # Signature SMB non requise — relay MITM
    'LDAP-001': 80,  # Intégrité LDAP désactivée — LDAP relay
    'LDAP-002': 20,  # LDAP pas au niveau max
    'NTLM-001': 30,  # Trafic NTLM sortant non restreint
    'RDP-001':  40,  # NLA non requis — BlueKeep
    # ── Impression ────────────────────────────────────────────────────────
    'PRINT-001': 90, # PrintNightmare — installation drivers non restreinte
    # ── LSA & Protection mémoire ───────────────────────────────────────────
    'LSA-001':  30,  # RunAsPPL non activé — Mimikatz
    # ── Accès anonyme ──────────────────────────────────────────────────────
    'PRIV-001': 50,  # Accès réseau anonyme autorisé
    'PRIV-002': 15,  # Compte Invité activé
    'ANON-001': 25,  # Everyone inclut anonymes
    'ANON-002': 25,  # Partages accessibles anonymement
    # ── Audit ─────────────────────────────────────────────────────────────
    'AUDIT-001': 25,  # Audit connexions absent
    'AUDIT-002': 20,  # Audit gestion comptes absent
    'AUDIT-003': 20,  # Audit changements stratégie absent
    'AUDIT-005': 10,  # Audit avancé non prioritaire
    'AUDIT-006': 10,  # Audit privilèges absent
    'AUDIT-007': 10,  # Audit événements système absent
    'LOG-001':   15,  # Journal sécurité trop petit
    # ── PowerShell ────────────────────────────────────────────────────────
    'PS-001':   30,   # ScriptBlock Logging désactivé
    # ── Kerberos ──────────────────────────────────────────────────────────
    'KERB-002': 20,   # DES/RC4 non désactivé
    # ── Droits utilisateurs dangereux ──────────────────────────────────────
    'PRIV-R001': 100, # SeDebugPrivilege — Mimikatz direct
    'PRIV-R002': 100, # SeTcbPrivilege — Act as OS
    'PRIV-R003':  40, # SeTakeOwnership étendu
    'PRIV-R004':  35, # SeBackupPrivilege étendu — exfiltration SAM
    'PRIV-R005': 100, # SeLoadDriverPrivilege — driver malveillant Ring 0
    # ── Préférences registre (Registry.xml) ────────────────────────────────
    'REGXML-001': 100, # Partages admin activés — Pass-the-Hash trivial
    'REGXML-002':  80, # Token plein comptes locaux
    'REGXML-003': 100, # UAC désactivé via préférences
    'REGXML-004': 100, # WDigest activé via préférences
    'REGXML-005':  70, # SMBv1 activé via préférences
    'REGXML-006':  40, # Pare-feu désactivé via préférences
    'REGXML-007':  30, # ScriptBlock Logging désactivé via préférences
    'REGXML-008': 100, # Pare-feu profil standard désactivé
    'REGXML-009': 100, # Defender désactivé
    'REGXML-010': 100, # Protection temps réel Defender désactivée
    'REGXML-011':  60, # Surveillance comportementale Defender désactivée
    'REGXML-012':  80, # NLA RDP désactivé via préférences
    'REGXML-013':  30, # Chiffrement RDP insuffisant
}
def analyze_gpos(gpos: list) -> dict:
    if not gpos:
        print("[!] Aucune GPO collectée — vérifiez la connexion LDAP et les droits du compte.")
        gpos = []
    # 1. RSOP global → findings globaux (ce qui s'applique réellement)
    rsop_settings, rsop_reg_list, rsop_registry_xml = build_rsop(gpos)
    rsop_registry = {(e[0], e[1]): e[3] for e in rsop_reg_list}

    # Récupérer les PSO depuis les GPO (injectées par collect_all)
    pso_list = []
    for gpo in gpos:
        if gpo.get('_pso_list'):
            pso_list = gpo['_pso_list']
            break

    global_findings = []
    for rule in AUDIT_RULES:
        finding = evaluate_rule_on_rsop(rule, rsop_settings, rsop_registry)
        if finding:
            # Annoter les findings de mots de passe si des PSO existent
            if pso_list and rule.get('category') == 'Mots de passe':
                finding['pso_note'] = (
                    f"⚠ {len(pso_list)} Fine-Grained Password Policy (PSO) détectée(s) — "
                    f"ce finding peut ne pas s'appliquer aux comptes couverts par une PSO : "
                    + ', '.join(p['name'] for p in pso_list[:3])
                )
            global_findings.append(finding)

    # Évaluer les règles sur les [Registry Values] du GptTmpl.inf
    rsop_regval = rsop_settings.get('registry_values', {})
    global_findings += evaluate_regval_rules(rsop_regval)

    # Évaluer les règles sur les Registry.xml (préférences registre)
    global_findings += evaluate_registry_xml_rules(rsop_registry_xml)

    # Évaluer les droits utilisateurs (Privilege Rights — [Privilege Rights] de GptTmpl.inf)
    rsop_privrights = rsop_settings.get('privilege_rights', {})
    global_findings += evaluate_privright_rules(rsop_privrights)

    # ── Enrichissement des findings "absent" — portée limitée ────────────────
    # Si un paramètre est absent du RSOP global mais existe dans une GPO
    # à portée limitée (WMI, Security Filtering, OU spécifique), le signaler.

    for finding in global_findings:
        if not finding.get('not_configured'):
            continue  # seulement les "absent"

        rule_id   = finding['rule_id']
        rule      = next((r for r in AUDIT_RULES if r['id'] == rule_id), None)
        if not rule:
            continue

        check_key = (rule.get('check_key') or '').lower()
        section   = rule.get('section', '')
        reg_key   = (rule.get('reg_key') or '').lower()
        reg_val   = (rule.get('reg_value') or '').lower()

        # Chercher dans toutes les GPO individuelles si ce paramètre est configuré
        partial_gpos = []
        for gpo in gpos:
            if is_gpo_fully_disabled(gpo):
                continue

            found_in_gpo = False
            gpo_settings = gpo.get('settings', {})
            gpo_registry = gpo.get('registry_entries', [])

            if section == 'registry':
                for (k, v, t, val) in gpo_registry:
                    if k.lower() == reg_key and v.lower() == reg_val:
                        found_in_gpo = True
                        break
            elif section and check_key:
                sec = gpo_settings.get(section, {})
                if sec and check_key in sec:
                    found_in_gpo = True
                else:
                    # Vérifier registry_values alias
                    REGVAL_ALIASES = {
                        ('lmcompatibilitylevel', 'system_access'):
                            'machine\\system\\currentcontrolset\\control\\lsa\\lmcompatibilitylevel',
                        ('nolmhash', 'system_access'):
                            'machine\\system\\currentcontrolset\\control\\lsa\\nolmhash',
                        ('restrictanonymous', 'system_access'):
                            'machine\\system\\currentcontrolset\\control\\lsa\\restrictanonymous',
                        ('enableguestaccount', 'system_access'):
                            'machine\\software\\microsoft\\windows nt\\currentversion\\winlogon\\enableguestaccount',
                    }
                    alias = REGVAL_ALIASES.get((check_key, section))
                    if alias and gpo_settings.get('registry_values', {}).get(alias):
                        found_in_gpo = True

            if found_in_gpo:
                links = gpo.get('links', [])
                wmi   = gpo.get('wmi_filter')
                sf    = gpo.get('security_filter', [])
                # Déterminer si la portée est limitée
                is_limited = bool(wmi or sf)
                if not is_limited:
                    # Vérifier si lié uniquement à des OU enfants (pas au domaine racine)
                    domain_link = any(
                        not l.get('ou', '').upper().startswith('OU=')
                        for l in links
                    )
                    is_limited = not domain_link and len(links) > 0

                partial_gpos.append({
                    'name':       gpo['name'],
                    'guid':       gpo['guid'],
                    'limited':    is_limited,
                    'wmi':        wmi.get('name', '') if wmi else '',
                    'sf':         sf[:3] if sf else [],
                    'ous':        [l.get('ou', '') for l in links[:3]],
                })

        if partial_gpos:
            limited = [g for g in partial_gpos if g['limited']]
            full    = [g for g in partial_gpos if not g['limited']]
            if full:
                # Paramètre configuré dans une GPO à portée complète
                # → le finding "absent" est probablement un faux positif
                finding['scope_note'] = (
                    f"ℹ Ce paramètre est configuré dans "
                    f"{', '.join(g['name'] for g in full[:2])} "
                    f"mais n'a pas été détecté dans le RSOP global — "
                    f"vérifier que cette GPO s'applique bien à toutes les machines."
                )
            elif limited:
                # Paramètre configuré mais seulement dans des GPO à portée limitée
                details = []
                for g in limited[:3]:
                    info_parts = []
                    if g['wmi']:
                        info_parts.append(f"filtre WMI : {g['wmi']}")
                    if g['sf']:
                        info_parts.append(f"filtrage sécurité : {', '.join(str(s) for s in g['sf'][:2])}")
                    if g['ous']:
                        info_parts.append(f"OU : {g['ous'][0].split(',')[0]}")
                    details.append(f"{g['name']} ({' | '.join(info_parts)})")
                finding['scope_note'] = (
                    f"⚠ Paramètre configuré mais portée limitée — "
                    f"ne s'applique pas à toutes les machines : "
                    + ' ; '.join(details)
                )
    default_gpo_findings = check_default_gpo_modifications(gpos)
    catchall_gpos        = detect_catchall_gpos(gpos)
    for f in default_gpo_findings:
        if f['severity'] == 'warning':
            global_findings.append(f)
        # Les 'good' sont ajoutés aux conformes plus bas

    # ── Exclure les GPO par défaut des source_gpos dans les remediations ──────
    # On ne doit pas conseiller de modifier Default Domain Policy / DDCP
    DEFAULT_GUIDS = set(DEFAULT_GPOS.keys())
    for finding in global_findings:
        if 'source_gpos' in finding:
            # Filtrer les GPO par défaut des sources
            non_default = [g for g in finding['source_gpos']
                          if g['guid'].upper() not in DEFAULT_GUIDS]
            default_sources = [g for g in finding['source_gpos']
                               if g['guid'].upper() in DEFAULT_GUIDS]

            finding['source_gpos'] = non_default

            # Si le paramètre problématique vient d'une GPO par défaut,
            # ajouter une note dans la remédiation
            if default_sources:
                default_names = ', '.join(g['name'] for g in default_sources)
                finding['default_gpo_note'] = (
                    f"⚠ Ce paramètre est configuré dans : {default_names}. "
                    f"Ne pas modifier cette GPO — créer une GPO dédiée avec la valeur correcte "
                    f"et la lier aux OU appropriées. La nouvelle GPO écrasera la valeur de la GPO par défaut."
                )
                if not finding['source_gpos']:
                    # Tous les findings viennent de GPO par défaut → suggérer de créer une GPO
                    finding['action_label'] = "Créer une nouvelle GPO dédiée (ne pas modifier la GPO par défaut)"
    for finding in global_findings:
        rid = finding['rule_id']
        all_rules_by_id = {r['id']: r for r in AUDIT_RULES + AUDIT_RULES_REGVAL + AUDIT_RULES_REGISTRY_XML}
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
    compliant_rules = []
    for r in AUDIT_RULES:
        if r['id'] not in violated_ids:
            # Vérifier que le paramètre est bien configuré (pas juste absent avec absent_sev=None)
            sec = rsop_settings.get(r['section'], {})
            check_key = r.get('check_key', '')
            is_configured = (
                (check_key and sec and check_key.lower() in sec) or
                (r['section'] == 'registry' and
                 (r.get('reg_key', '').lower(), r.get('reg_value', '').lower()) in rsop_registry)
            )
            compliant_rules.append({
                'id':         r['id'],
                'title':      r.get('detail_ok', r['title']),
                'category':   r['category'],
                'ref':        r['ref'],
                'rec_value':  r.get('rec_value', ''),
                'remediation':r['remediation'],
                'configured': is_configured,
            })
    # Règles REGVAL conformes
    for r in AUDIT_RULES_REGVAL:
        if r['id'] not in violated_ids and rsop_regval.get(r['regval_key'].lower()):
            compliant_rules.append({
                'id':         r['id'],
                'title':      r.get('detail_ok', r['title']),
                'category':   r.get('category', ''),
                'ref':        r['ref'],
                'rec_value':  '',
                'remediation':r['remediation'],
                'configured': True,
            })

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

        # Pénaliser aussi les clés ADMX dangereuses détectées dans cette GPO
        for r in gpo.get('registry_admx', []):
            if r.get('alert') and 'CRITIQUE' in r.get('alert', ''):
                per_gpo_findings.append({
                    'rule_id':    f"ADMX-{r.get('name','').upper()[:12]}",
                    'title':      r.get('label', r.get('name', '')),
                    'severity':   'critical',
                    'ref':        'Paramètre ADMX',
                    'category':   r.get('category', 'Registre'),
                    'remediation':f"Valeur détectée : {r.get('value','')} — {r.get('hint','')}",
                    'detail':     r.get('alert', ''),
                })
            elif r.get('alert'):
                per_gpo_findings.append({
                    'rule_id':    f"ADMX-{r.get('name','').upper()[:12]}",
                    'title':      r.get('label', r.get('name', '')),
                    'severity':   'warning',
                    'ref':        'Paramètre ADMX',
                    'category':   r.get('category', 'Registre'),
                    'remediation':f"Valeur : {r.get('value','')} — {r.get('hint','')}",
                    'detail':     r.get('alert', ''),
                })

        # Score de risque par GPO — cohérent avec le score global PingCastle
        # On utilise les mêmes poids que le score global.
        # Score = 0 (sûr) → 100 (risque max), plafonné à 100.
        # Seuls les findings confirmés (not_configured=False) comptent.
        confirmed_per_gpo = [f for f in per_gpo_findings if not f.get('not_configured')]
        gpo_risk = 0
        for f in confirmed_per_gpo:
            rid = f.get('rule_id', '')
            weight = RULE_WEIGHTS.get(rid, {'critical': 30, 'warning': 15, 'info': 5}.get(f['severity'], 10))
            gpo_risk += weight
        score = min(100, gpo_risk)

        # Préparer le contenu lisible de la GPO
        content_sections = _format_gpo_content(gpo)

        # has_content : la GPO a-t-elle du contenu réel ?
        # On vérifie à la fois les sections formatées ET les champs bruts
        # car certains contenus (scripts avec cmd vide, settings vides) peuvent
        # produire des sections sans params
        has_content = (
            any(s['params'] for s in content_sections)
            or bool(gpo.get('registry_entries'))
            or bool(gpo.get('registry_entries_user'))
            or bool(gpo.get('registry_admx'))
            or bool(gpo.get('registry_admx_user'))
            or bool(gpo.get('shortcuts_machine'))
            or bool(gpo.get('shortcuts_user'))
            or bool(gpo.get('regional'))
            or bool(gpo.get('datasources_machine'))
            or bool(gpo.get('datasources_user'))
            or bool(gpo.get('network_options'))
            or bool(gpo.get('ini_files_machine'))
            or bool(gpo.get('ini_files_user'))
            or bool(gpo.get('internet_settings'))
            or bool(gpo.get('files_machine'))
            or bool(gpo.get('files_user'))
            or any(
                isinstance(v, list) and v
                for v in (gpo.get('scripts') or {}).values()
            )
            or bool(gpo.get('settings') and any(
                v for section in gpo['settings'].values()
                if isinstance(section, dict)
                for v in section.values() if v
            ))
        )

        gpo_reports.append({
            'name':            gpo['name'],
            'guid':            gpo['guid'],
            'links':           gpo['links'],
            'link_count':      len(gpo['links']),
            'flags':           gpo.get('flags', '0'),
            'created':         gpo.get('created', ''),
            'changed':         gpo.get('changed', ''),
            'findings':        per_gpo_findings,
            'score':           score,
            'is_orphan':       not gpo['links'],
            'has_content':     has_content,
            'wmi_filter':      gpo.get('wmi_filter'),
            'security_filter': gpo.get('security_filter', []),
        })
        # Index de contenu — exclure les sections de registre brutes (trop volumineuses)
        # On garde uniquement les sections décodées/lisibles
        EXCLUDE_TITLES = {'Registre Windows — Machine (Registry.pol)',
                          'Registre Windows — Utilisateur (Registry.pol)'}
        content_sections_slim = [s for s in content_sections
                                  if s['title'] not in EXCLUDE_TITLES or len(s.get('params', [])) <= 20]
        gpo_content_index[gpo['guid']] = content_sections_slim

    # Ajouter les GPO par défaut non modifiées dans les conformes
    for f in default_gpo_findings:
        if f['severity'] == 'good':
            compliant_rules.append({
                'id':         f['rule_id'],
                'title':      f['title'],
                'category':   f['category'],
                'ref':        f['ref'],
                'rec_value':  '',
                'remediation':'',
                'configured': True,
            })
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

    # ══════════════════════════════════════════════════════════════════════════
    # SCORING STYLE PINGCASTLE
    # Score de RISQUE : 0 = aucun risque, 100 = risque maximal
    # Chaque règle a un poids fixe par catégorie.
    # Le score final = MAX des scores par catégorie (le pire domaine tire le score)
    # Inspiré de PingCastle : une seule faille critique suffit à avoir un mauvais score.
    # ══════════════════════════════════════════════════════════════════════════



    # Catégories de score (style PingCastle — score par domaine)
    CATEGORY_RULES = {
        'Authentification':  ['AUTH-001','AUTH-002','AUTH-003','AUTH-004',
                              'PWD-001','PWD-002','PWD-003','PWD-004','PWD-005','PWD-006',
                              'REGXML-004','KERB-002'],
        'Privilèges':        ['UAC-001','UAC-002','UAC-003','UAC-004',
                              'PRIV-001','PRIV-002','ANON-001','ANON-002',
                              'PRIV-R001','PRIV-R002','PRIV-R003','PRIV-R004','PRIV-R005',
                              'REGXML-001','REGXML-002','REGXML-003'],
        'Sécurité réseau':   ['SMB-001','LDAP-001','LDAP-002','NTLM-001','RDP-001',
                              'SYS-001','SYS-002','REGXML-005','REGXML-006','REGXML-008',
                              'REGXML-012','REGXML-013'],
        'Protection système':['SYS-003','SYS-004','SYS-005','PRINT-001','LSA-001',
                              'REGXML-007','REGXML-009','REGXML-010','REGXML-011','PS-001'],
        'Audit & Traçabilité':['AUDIT-001','AUDIT-002','AUDIT-003','AUDIT-005',
                               'AUDIT-006','AUDIT-007','LOG-001'],
    }

    def _compute_category_score(findings_ids: set, category_rules: list) -> int:
        """Score de risque pour une catégorie = somme des poids, plafonné à 100."""
        total = 0
        for rule_id in category_rules:
            if rule_id in findings_ids:
                total += RULE_WEIGHTS.get(rule_id, 10)
        return min(total, 100)

    # Calculer les scores par catégorie
    # On exclut les findings "non configuré" (not_configured=True) du score
    # car ils indiquent un manque de visibilité, pas une vraie vulnérabilité confirmée
    confirmed_findings = [f for f in global_findings if not f.get('not_configured')]
    confirmed_ids = {f['rule_id'] for f in confirmed_findings}

    category_scores = {
        cat: _compute_category_score(confirmed_ids, rules)
        for cat, rules in CATEGORY_RULES.items()
    }

    # Score global = MAX des catégories (comme PingCastle)
    # La pire catégorie détermine le niveau de risque global
    global_score = max(category_scores.values()) if category_scores else 0

    # Niveau de risque en texte (style PingCastle)
    if global_score >= 75:
        risk_level = 'Critique'
        risk_color = 'red'
    elif global_score >= 50:
        risk_level = 'Élevé'
        risk_color = 'amber'
    elif global_score >= 25:
        risk_level = 'Modéré'
        risk_color = 'amber'
    else:
        risk_level = 'Faible'
        risk_color = 'green'

    # Séparer findings confirmés (vraie mauvaise valeur) vs non couverts (absent des GPO)
    confirmed_findings  = [f for f in global_findings if not f.get('not_configured')]
    uncovered_findings  = [f for f in global_findings if f.get('not_configured')]

    criticals = sum(1 for f in confirmed_findings if f['severity'] == 'critical')
    warnings  = sum(1 for f in confirmed_findings if f['severity'] == 'warning')
    infos     = sum(1 for f in confirmed_findings if f['severity'] == 'info')
    # Recommandations = paramètres importants absents des GPO (non couverts)
    reco_critical = sum(1 for f in uncovered_findings if f['severity'] == 'critical')
    reco_warning  = sum(1 for f in uncovered_findings if f['severity'] == 'warning')
    reco_info     = sum(1 for f in uncovered_findings if f['severity'] == 'info')
    # Pénalités additionnelles (orphelines, conflits) — max +10 pts
    orphan_penalty   = min(len(orphan_gpos) * 1, 5)
    conflict_penalty = min(conflicts_high * 2 + conflicts_low, 5)
    global_score = min(100, global_score + orphan_penalty + conflict_penalty)

    return {
        'global_score':    global_score,
        'risk_level':      risk_level,
        'risk_color':      risk_color,
        'category_scores': category_scores,
        'total_findings':  len(global_findings),
        'criticals':       criticals,
        'warnings':        warnings,
        'infos':           infos,
        'reco_critical':   reco_critical,
        'reco_warning':    reco_warning,
        'reco_info':       reco_info,
        'confirmed_findings': confirmed_findings,
        'uncovered_findings': uncovered_findings,
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
        'gpo_count':          len(gpos),
        'wmi_count':          sum(1 for g in gpos if g.get('wmi_filter')),
        'default_gpo_status': [f for f in default_gpo_findings],
        'catchall_gpos':      catchall_gpos,
        'empty_gpo_guids':    [r['guid'] for r in gpo_reports if not r.get('has_content', True)],
        'search_index':       build_search_index(_enrich_gpos_for_search(gpos, gpo_reports)),
    }


# ─── Template HTML ────────────────────────────────────────────────────────────

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="fr" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GPOctopus — {{ data.generated_at }}</title>
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
html{font-size:16px}
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
.fc-detail{font-size:12px;color:var(--txt2);padding:10px 0 6px;line-height:1.6;white-space:pre-wrap}
.fc-ref{font-size:11px;color:var(--txt3);margin-bottom:6px}
.fc-reco{
  font-size:12px;color:var(--green);
  padding:8px 12px;background:var(--green-bg);border-radius:4px;
  line-height:1.6;white-space:pre-wrap;font-family:'JetBrains Mono',monospace;font-size:11px;
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
  color:var(--txt);font-size:16px;font-family:'Inter',sans-serif;
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

.sort-btn{padding:3px 10px;border-radius:4px;border:1px solid var(--border);background:var(--surface2);color:var(--txt2);cursor:pointer;font-size:11px}
.sort-btn.active{background:var(--blue)!important;color:#fff!important;border-color:var(--blue)!important}
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
.migration-body.open{display:block !important}

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
    <button id="global-back-btn" onclick="goBack()" title="Retour" style="display:none;margin-top:8px;width:100%;align-items:center;justify-content:center;gap:6px;padding:6px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--txt2);font-size:12px;cursor:pointer">
      <span>←</span> <span class="back-label">Retour</span>
    </button>
  </div>

  <div class="sb-score">
    <div class="score-ring">
      <svg width="52" height="52" viewBox="0 0 52 52">
        <circle cx="26" cy="26" r="22" fill="none" stroke="var(--border2)" stroke-width="4"/>
        <circle cx="26" cy="26" r="22" fill="none"
          stroke="{% if data.global_score>=75%}var(--red){% elif data.global_score>=50%}var(--amber){% elif data.global_score>=25%}var(--amber){% else %}var(--green){% endif %}"
          stroke-width="4" stroke-linecap="round"
          stroke-dasharray="{{ (data.global_score/100*138.2)|round(1) }} 138.2"/>
      </svg>
      <div class="score-val">
        <span class="n" style="color:{% if data.global_score>=75%}var(--red){% elif data.global_score>=25%}var(--amber){% else %}var(--green){% endif %}">{{ data.global_score }}</span>
        <span class="l">/100</span>
      </div>
    </div>
    <div class="score-info">
      <div class="label" style="color:{% if data.global_score>=75%}var(--red){% elif data.global_score>=25%}var(--amber){% else %}var(--green){% endif %}">
        {{ data.risk_level }}
      </div>
      <div class="sub">{{ data.criticals }} critique · {{ data.warnings }} alerte<br>{{ data.compliant_count }} conforme · {{ data.orphan_count }} orpheline</div>
      <div style="font-size:9px;color:var(--txt3);margin-top:3px">Score de risque — 0=sûr, 100=critique</div>
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
    <div class="sub-item" onclick="showSub('security','reco')"><span class="si-icon">💡</span>Recommandations<span class="si-count" style="color:var(--txt3)">{{ data.reco_critical + data.reco_warning + data.reco_info }}</span></div>
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
          <div class="ml">🔴 Critiques (confirmés)</div>
        </div>
        <div class="metric-card amber" onclick="showSub('security','warnings')">
          <div class="mv">{{ data.warnings }}</div>
          <div class="ml">🟡 Alertes (confirmées)</div>
        </div>
        <div class="metric-card green" onclick="showSub('security','compliant')">
          <div class="mv">{{ data.compliant_count }}</div>
          <div class="ml">✅ Conformes</div>
        </div>
        <div class="metric-card blue" onclick="showSub('security','conflicts')">
          <div class="mv">{{ data.conflicts_high + data.conflicts_low }}</div>
          <div class="ml">⚡ Conflits GPO</div>
        </div>
        <div class="metric-card" style="cursor:pointer;background:var(--surface2);border:1px solid var(--border)" onclick="showSub('security','reco')">
          <div class="mv" style="color:var(--txt2)">{{ data.reco_critical + data.reco_warning + data.reco_info }}</div>
          <div class="ml" style="color:var(--txt3)">💡 Recommandations</div>
        </div>
      </div>

      <!-- Bandeau GPO par défaut -->
      {% if data.default_gpo_status | selectattr('severity', 'eq', 'warning') | list %}
      <div style="margin-bottom:20px">
        <div class="section-title">🛡 GPO par défaut Windows</div>
        <div style="display:flex;flex-direction:column;gap:10px">
          {% for f in data.default_gpo_status %}

          {% if f.severity == 'warning' %}
          <!-- GPO modifiée — afficher le plan de migration -->
          <div style="background:var(--surface);border:1px solid rgba(212,137,42,.4);border-left:4px solid var(--amber);border-radius:8px;overflow:hidden">
            <!-- En-tête -->
            <div style="padding:14px 18px;background:var(--amber-bg);display:flex;align-items:center;gap:12px;cursor:pointer" onclick="this.nextElementSibling.classList.toggle('open')">
              <span style="font-size:20px">⚠️</span>
              <div style="flex:1">
                <div style="font-size:15px;font-weight:700;color:var(--amber)">{{ f.title }}</div>
                <div style="font-size:12px;color:var(--txt2);margin-top:2px">{{ f.detail }}</div>
              </div>
              <span style="font-size:12px;color:var(--amber);font-weight:600;flex-shrink:0">Voir le plan de migration ▼</span>
            </div>

            <!-- Plan de migration — masqué par défaut, ouvert au clic -->
            <div style="display:none;padding:0" class="migration-body">

              <!-- Intro -->
              <div style="padding:16px 18px;border-bottom:1px solid var(--border);font-size:13px;color:var(--txt2);line-height:1.6;background:var(--surface2)">
                <strong style="color:var(--txt)">Pourquoi c'est un problème ?</strong><br>
                Les GPO par défaut sont difficiles à auditer, à documenter et à protéger.
                Une modification involontaire ou malveillante y passe inaperçue.
                La bonne pratique est de les laisser dans leur état d'origine et de créer des GPO dédiées pour chaque usage.
              </div>

              {% if f.migration_plan %}
              <!-- Étapes de migration -->
              <div style="padding:16px 18px;border-bottom:1px solid var(--border)">
                <div style="font-size:13px;font-weight:700;color:var(--txt);margin-bottom:14px">
                  📋 Plan de migration — {{ f.migration_plan|length }} GPO à créer
                </div>

                {% for step in f.migration_plan %}
                <div style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;margin-bottom:10px;overflow:hidden">
                  <!-- En-tête de l'étape -->
                  <div style="padding:12px 16px;background:var(--blue-bg);border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px">
                    <div style="width:24px;height:24px;border-radius:50%;background:var(--blue);color:#fff;font-size:11px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0">{{ loop.index }}</div>
                    <div style="flex:1">
                      <div style="font-size:13px;font-weight:700;color:var(--blue);font-family:'JetBrains Mono',monospace">{{ step.gpo_name }}</div>
                      <div style="font-size:11px;color:var(--txt2);margin-top:1px">{{ step.label }} — {{ step.count }} paramètre(s) à déplacer</div>
                    </div>
                  </div>
                  <!-- Détails de l'étape -->
                  <div style="padding:12px 16px">
                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:10px">
                      <div>
                        <div style="font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--txt3);font-weight:600;margin-bottom:4px">📍 Emplacement dans la GPO</div>
                        <div style="font-size:11px;color:var(--txt2);line-height:1.6;font-family:'JetBrains Mono',monospace;background:var(--surface);padding:6px 10px;border-radius:4px;border:1px solid var(--border)">{{ step.scope }}</div>
                      </div>
                      <div>
                        <div style="font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--txt3);font-weight:600;margin-bottom:4px">🔗 Lier cette GPO à</div>
                        <div style="font-size:11px;color:var(--txt2);line-height:1.6;font-family:'JetBrains Mono',monospace;background:var(--surface);padding:6px 10px;border-radius:4px;border:1px solid var(--border)">{{ step.ou_link }}</div>
                      </div>
                    </div>

                    {% if step.items %}
                    <div style="font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--txt3);font-weight:600;margin-bottom:6px">Paramètres détectés à déplacer</div>
                    <div style="display:flex;flex-direction:column;gap:3px">
                      {% for item in step.params_list %}
                      <div style="font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--txt2);padding:4px 10px;background:var(--surface);border-radius:3px;border:1px solid var(--border)">→ {{ item }}</div>
                      {% endfor %}
                      {% if step.extra_count is defined and step.extra_count > 0 %}
                      <div style="font-size:11px;color:var(--txt3);padding:4px 10px;font-style:italic">… et {{ step.extra_count }} autre(s)</div>
                      {% endif %}
                    </div>
                    {% endif %}
                  </div>
                </div>
                {% endfor %}
              </div>

              <!-- Procédure de migration -->
              <div style="padding:16px 18px;border-bottom:1px solid var(--border)">
                <div style="font-size:13px;font-weight:700;color:var(--txt);margin-bottom:12px">🔧 Procédure étape par étape</div>
                <div style="display:flex;flex-direction:column;gap:8px">
                  <div style="display:flex;gap:12px;align-items:flex-start">
                    <div style="width:22px;height:22px;border-radius:50%;background:var(--green);color:#fff;font-size:10px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:1px">1</div>
                    <div style="font-size:12px;color:var(--txt2);line-height:1.6">Ouvrir la <strong>console GPMC</strong> (Group Policy Management Console) sur le DC ou une machine admin</div>
                  </div>
                  <div style="display:flex;gap:12px;align-items:flex-start">
                    <div style="width:22px;height:22px;border-radius:50%;background:var(--green);color:#fff;font-size:10px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:1px">2</div>
                    <div style="font-size:12px;color:var(--txt2);line-height:1.6">Pour chaque GPO du plan ci-dessus : <strong>créer une nouvelle GPO</strong> (clic droit sur le domaine ou l'OU → "Créer un objet de stratégie de groupe")</div>
                  </div>
                  <div style="display:flex;gap:12px;align-items:flex-start">
                    <div style="width:22px;height:22px;border-radius:50%;background:var(--green);color:#fff;font-size:10px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:1px">3</div>
                    <div style="font-size:12px;color:var(--txt2);line-height:1.6"><strong>Reconfigurer les paramètres</strong> dans la nouvelle GPO (mêmes valeurs que dans la GPO par défaut)</div>
                  </div>
                  <div style="display:flex;gap:12px;align-items:flex-start">
                    <div style="width:22px;height:22px;border-radius:50%;background:var(--green);color:#fff;font-size:10px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:1px">4</div>
                    <div style="font-size:12px;color:var(--txt2);line-height:1.6"><strong>Lier la nouvelle GPO</strong> à l'OU ou au domaine indiqué, vérifier qu'elle s'applique correctement (<code>gpresult /r</code> sur un poste test)</div>
                  </div>
                  <div style="display:flex;gap:12px;align-items:flex-start">
                    <div style="width:22px;height:22px;border-radius:50%;background:var(--amber);color:#fff;font-size:10px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:1px">5</div>
                    <div style="font-size:12px;color:var(--txt2);line-height:1.6"><strong>Supprimer les paramètres de la GPO par défaut</strong> uniquement après validation que la nouvelle GPO fonctionne</div>
                  </div>
                  <div style="display:flex;gap:12px;align-items:flex-start">
                    <div style="width:22px;height:22px;border-radius:50%;background:var(--red);color:#fff;font-size:10px;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:1px">⚠</div>
                    <div style="font-size:12px;color:var(--amber);line-height:1.6"><strong>Ne jamais supprimer</strong> la GPO par défaut elle-même — seulement vider les paramètres ajoutés par erreur</div>
                  </div>
                </div>
              </div>

              {% endif %}

              <!-- Rappel usage normal -->
              <div style="padding:14px 18px;background:var(--surface2)">
                <div style="font-size:12px;color:var(--txt2)">
                  <strong style="color:var(--txt)">Usage normal de cette GPO :</strong> {{ f.get('remediation_short', '') }}
                </div>
              </div>
            </div>
          </div>

          {% endif %}

          {% endfor %}
        </div>
      </div>
      {% endif %}

      <!-- Score par catégorie style PingCastle -->
      <div style="margin-bottom:24px">

        <div class="section-title">📊 Score de risque par domaine
          <span class="st-count" style="font-size:11px;color:var(--txt3);font-weight:400">0 = sûr · 100 = risque maximal · le pire détermine le score global</span>
        </div>
        <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;overflow:hidden">
          {% for cat, score in data.category_scores.items() %}
          {% if score >= 75 %}{% set cat_color = 'var(--red)' %}{% set cat_bg = 'var(--red-bg)' %}{% set cat_label = 'Critique' %}
          {% elif score >= 50 %}{% set cat_color = 'var(--amber)' %}{% set cat_bg = 'var(--amber-bg)' %}{% set cat_label = 'Élevé' %}
          {% elif score >= 25 %}{% set cat_color = 'var(--amber)' %}{% set cat_bg = 'var(--amber-bg)' %}{% set cat_label = 'Modéré' %}
          {% else %}{% set cat_color = 'var(--green)' %}{% set cat_bg = 'var(--green-bg)' %}{% set cat_label = 'Faible' %}
          {% endif %}
          <div style="padding:12px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px">
            <div style="min-width:160px;font-size:12px;font-weight:500;color:var(--txt)">{{ cat }}</div>
            <div style="flex:1;background:var(--surface2);border-radius:4px;height:8px;overflow:hidden">
              <div style="height:100%;width:{{ score }}%;background:{{ cat_color }};border-radius:4px;transition:width .5s ease"></div>
            </div>
            <div style="min-width:38px;text-align:right;font-size:14px;font-weight:700;font-family:'JetBrains Mono',monospace;color:{{ cat_color }}">{{ score }}</div>
            <div style="min-width:55px;font-size:10px;padding:2px 7px;border-radius:10px;background:{{ cat_bg }};color:{{ cat_color }};font-weight:600;text-align:center">{{ cat_label }}</div>
          </div>
          {% endfor %}
          <!-- Score global -->
          {% if data.global_score >= 75 %}{% set g_color = 'var(--red)' %}{% set g_bg = 'var(--red-bg)' %}
          {% elif data.global_score >= 25 %}{% set g_color = 'var(--amber)' %}{% set g_bg = 'var(--amber-bg)' %}
          {% else %}{% set g_color = 'var(--green)' %}{% set g_bg = 'var(--green-bg)' %}{% endif %}
          <div style="padding:12px 16px;background:var(--surface2);display:flex;align-items:center;gap:12px">
            <div style="min-width:160px;font-size:13px;font-weight:700;color:var(--txt)">Score global</div>
            <div style="flex:1;background:var(--surface3);border-radius:4px;height:10px;overflow:hidden">
              <div style="height:100%;width:{{ data.global_score }}%;background:{{ g_color }};border-radius:4px"></div>
            </div>
            <div style="min-width:38px;text-align:right;font-size:18px;font-weight:700;font-family:'JetBrains Mono',monospace;color:{{ g_color }}">{{ data.global_score }}</div>
            <div style="min-width:55px;font-size:11px;padding:3px 8px;border-radius:10px;background:{{ g_bg }};color:{{ g_color }};font-weight:700;text-align:center">{{ data.risk_level }}</div>
          </div>
        </div>

        <!-- Explication du score -->
        <div style="margin-top:10px;padding:10px 14px;background:var(--surface);border:1px solid var(--border);border-radius:6px;font-size:11px;color:var(--txt2);line-height:1.6">
          <strong style="color:var(--txt)">Comment lire ce score ?</strong><br>
          Chaque catégorie est notée de 0 à 100 selon les failles confirmées détectées.
          Le score global est le <strong>maximum</strong> des catégories — une seule faille critique suffit à avoir un score élevé.
          Les findings "<em>non configuré</em>" n'impactent pas le score (manque de visibilité ≠ vulnérabilité confirmée).
        </div>
      </div>

      <!-- Priorités : top 5 critiques -->
      {% set crit_findings = data.confirmed_findings | selectattr('severity','eq','critical') | list %}
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
      {% set warn_findings = data.confirmed_findings | selectattr('severity','eq','warning') | list %}
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

      {% if data.uncovered_findings %}
      <div class="section-title" style="margin-top:8px">💡 Recommandations <span class="st-count">{{ data.uncovered_findings|length }} paramètres non couverts par GPO</span></div>
      <div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:12px 16px;margin-bottom:16px">
        <div style="font-size:12px;color:var(--txt2);margin-bottom:10px">Ces paramètres importants ne sont pas configurés explicitement via GPO — la valeur par défaut Windows s'applique et peut être insuffisante.</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">
          {% if data.reco_critical %}<span style="font-size:12px;padding:3px 10px;border-radius:12px;background:rgba(220,60,60,.1);color:var(--red);border:1px solid rgba(220,60,60,.2)">🔴 {{ data.reco_critical }} haute priorité</span>{% endif %}
          {% if data.reco_warning %}<span style="font-size:12px;padding:3px 10px;border-radius:12px;background:rgba(212,137,42,.1);color:var(--amber);border:1px solid rgba(212,137,42,.2)">🟡 {{ data.reco_warning }} normale</span>{% endif %}
          {% if data.reco_info %}<span style="font-size:12px;padding:3px 10px;border-radius:12px;background:var(--surface2);color:var(--txt3);border:1px solid var(--border)">ℹ {{ data.reco_info }} optionnel</span>{% endif %}
        </div>
        <button class="filter-btn" style="width:100%" onclick="showSub('security','reco')">Voir toutes les recommandations →</button>
      </div>
      {% endif %}

      {% if not data.confirmed_findings %}
      <div class="empty-state"><div class="es-icon">🎉</div><div class="es-title">Aucun problème confirmé</div><div class="es-sub">Aucun paramètre explicitement mal configuré dans vos GPO.{% if data.uncovered_findings %} Consultez les recommandations pour renforcer votre configuration.{% endif %}</div></div>
      {% endif %}
    </div>
  </div>

  <!-- SUB : Critiques -->
  <div id="sub-security-critical" style="display:none">
    <div class="page-header">
      <h2>🔴 Constatations critiques</h2>
      <p>{{ data.criticals }} problème(s) à corriger en priorité</p>
    </div>
    <div class="content-area"><button onclick="goBack()" style="margin-bottom:16px;display:inline-flex;align-items:center;gap:6px;padding:6px 14px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--txt2);font-size:12px;cursor:pointer">← Retour</button>
      <div class="toolbar">
        <div class="search-mini"><span class="si">⌕</span><input type="text" placeholder="Filtrer…" oninput="filterFindingsSub(this.value,'critical')"></div>
        <select class="gpo-source-select" id="gpo-sel-critical" onchange="filtFByGPO(this.value,'critical')">
          <option value="">Toutes les GPO</option>
          {% for gpo in data.gpo_reports %}{% if gpo.findings | selectattr('severity','eq','critical') | list %}<option value="{{ gpo.guid }}">{{ gpo.name }}</option>{% endif %}{% endfor %}
        </select>
        <button class="export-btn" onclick="exportFindings('csv')">⬇ CSV</button>
      </div>
      <div class="finding-list" id="fl-critical">
        {% for f in data.confirmed_findings | selectattr('severity','eq','critical') | list %}
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
            <div class="fc-ref">{{ f.ref }}</div>
            {% if f.get('rec_value') %}<div style="font-size:11px;color:var(--blue);padding:4px 10px;background:var(--blue-bg);border-radius:4px;margin-bottom:6px">🎯 Valeur recommandée : <strong>{{ f.rec_value }}</strong></div>{% endif %}
            <div class="fc-reco">✅ {{ f.remediation }}</div>
            {% if f.get('default_gpo_note') %}<div style="margin-top:6px;font-size:11px;padding:8px 12px;background:rgba(212,137,42,.08);border:1px solid rgba(212,137,42,.3);border-radius:4px;color:var(--amber);line-height:1.5">{{ f.default_gpo_note }}</div>{% endif %}
            {% if f.get('scope_note') %}<div style="margin-top:6px;font-size:11px;padding:8px 12px;background:var(--blue-bg);border:1px solid rgba(74,127,212,.2);border-radius:4px;color:var(--blue);line-height:1.5">{{ f.scope_note }}</div>{% endif %}
            {% if f.get('pso_note') %}<div style="margin-top:6px;font-size:11px;padding:6px 10px;background:var(--amber-bg);border-radius:4px;color:var(--amber)">⚠ {{ f.pso_note }}</div>{% endif %}
            {% if f.source_gpos %}<div class="fc-sources">GPO source : {% for sg in f.source_gpos %}<span class="fc-gpo-link" onclick="openGPODetail('{{ sg.guid }}')">{{ sg.name }}</span>{% endfor %}</div>{% endif %}
            {% if f.action_label %}<div style="margin-top:6px;font-size:11px;padding:4px 8px;background:var(--surface2);border-radius:3px;color:var(--txt2)">🔧 {{ f.action_label }}</div>{% endif %}
            <div class="explain-zone" id="ez-c-{{ f.rule_id }}"></div>
          </div>
        </div>
        {% endfor %}
        {% if not (data.confirmed_findings | selectattr('severity','eq','critical') | list) %}
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
    <div class="content-area"><button onclick="goBack()" style="margin-bottom:16px;display:inline-flex;align-items:center;gap:6px;padding:6px 14px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--txt2);font-size:12px;cursor:pointer">← Retour</button>
      <div class="toolbar">
        <div class="search-mini"><span class="si">⌕</span><input type="text" placeholder="Filtrer…" oninput="filterFindingsSub(this.value,'warning')"></div>
        <select class="gpo-source-select" onchange="filtFByGPO(this.value,'warning')">
          <option value="">Toutes les GPO</option>
          {% for gpo in data.gpo_reports %}{% if gpo.findings | selectattr('severity','eq','warning') | list %}<option value="{{ gpo.guid }}">{{ gpo.name }}</option>{% endif %}{% endfor %}
        </select>
      </div>
      <div class="finding-list" id="fl-warning">
        {% for f in data.confirmed_findings | selectattr('severity','eq','warning') | list %}
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
      <p>Ces paramètres sont correctement configurés dans vos GPO</p>
    </div>
    <div class="content-area"><button onclick="goBack()" style="margin-bottom:16px;display:inline-flex;align-items:center;gap:6px;padding:6px 14px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--txt2);font-size:12px;cursor:pointer">← Retour</button>
      <div class="finding-list">
        {% for r in data.compliant_rules %}
        <div class="finding-card good">
          <div class="fc-head" onclick="togFC(this)">
            <div class="fc-sev good"></div>
            <div class="fc-main">
              <div class="fc-title">{{ r.title }}</div>
              <div class="fc-meta">
                <span>{{ r.category }}</span><span>· {{ r.ref }}</span>
                {% if not r.configured %}<span style="color:var(--txt3);font-style:italic">· valeur par défaut acceptable</span>{% endif %}
              </div>
            </div>
            <span class="fc-pill good">conforme</span>
            <span class="fc-arrow">▶</span>
          </div>
          <div class="fc-body">
            {% if r.rec_value %}<div style="font-size:12px;color:var(--txt2);margin-bottom:6px">✅ Valeur recommandée : <strong>{{ r.rec_value }}</strong></div>{% endif %}
            <div class="fc-ref">{{ r.ref }}</div>
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
    <div class="content-area"><button onclick="goBack()" style="margin-bottom:16px;display:inline-flex;align-items:center;gap:6px;padding:6px 14px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--txt2);font-size:12px;cursor:pointer">← Retour</button>
      <div class="info-box">Un conflit = deux GPO définissent la même clé avec des valeurs différentes. La <strong>GPO gagnante</strong> est celle liée à l'OU la plus profonde ou marquée Enforced.</div>
      <div class="toolbar">
        <button class="filter-btn on" onclick="filtConflicts('all',this)">Tous ({{ data.conflicts_high + data.conflicts_low }})</button>
        <button class="filter-btn" onclick="filtConflicts('high',this)">🔴 Sécurité ({{ data.conflicts_high }})</button>
        <button class="filter-btn" onclick="filtConflicts('low',this)">🟡 Autres ({{ data.conflicts_low }})</button>
        <div class="search-mini" style="margin-left:auto"><span class="si">⌕</span><input type="text" placeholder="Filtrer…" oninput="searchConflicts(this.value)"></div>
      </div>
      {% if data.gpo_conflicts %}
      {% for c in data.gpo_conflicts %}
      <div class="conflict-card {% if c.is_security %}high{% else %}low{% endif %}" data-sec="{{ c.is_security|lower }}" data-txt="{{ c.key_short|lower }}">
        <div class="cc-head" onclick="togCC(this)">
          <span style="font-size:11px">{% if c.contradiction %}⚠️{% elif c.is_security %}🔴{% else %}🟡{% endif %}</span>
          <div style="flex:1;min-width:0">
            <span class="cc-key">{{ c.section_label }} → {{ c.key_short }}</span>
            {% if c.contradiction %}<span style="font-size:10px;color:var(--red);margin-left:8px;font-weight:600">CONTRADICTION SÉCURITÉ</span>{% endif %}
          </div>
          <span style="font-size:10px;color:var(--txt3)">{{ c.gpo_count }} GPO</span>
          <span style="font-size:11px;color:var(--txt3);transition:transform .15s" class="cc-arr">▶</span>
        </div>
        <div class="cc-body">
          {% if c.contradiction %}
          <div style="margin-bottom:12px;padding:10px 14px;background:rgba(220,60,60,.08);border:1px solid rgba(220,60,60,.3);border-radius:6px">
            <div style="font-size:12px;font-weight:600;color:var(--red);margin-bottom:6px">⚠ {{ c.contradiction.label }}</div>
            <div style="font-size:11px;color:var(--txt2);line-height:1.6">{{ c.contradiction.danger }}</div>
            <div style="margin-top:8px;display:flex;flex-direction:column;gap:4px">
              <div style="font-size:11px;padding:4px 10px;background:var(--green-bg);border-radius:4px;color:var(--green)">
                ✅ Valeur sûre : <strong>{{ c.contradiction.safe_gpo }}</strong> → <code>{{ c.contradiction.safe_val }}</code>
              </div>
              {% for u in c.contradiction.unsafe_gpos %}
              <div style="font-size:11px;padding:4px 10px;background:var(--red-bg);border-radius:4px;color:var(--red)">
                ❌ Valeur dangereuse : <strong>{{ u.name }}</strong> → <code>{{ u.value }}</code>
              </div>
              {% endfor %}
            </div>
          </div>
          {% endif %}
          <div class="cc-winner">✅ Gagnant (priorité haute) : <strong style="cursor:pointer;color:var(--green)" onclick="openGPODetail('{{ c.winner.gpo_guid }}')">{{ c.winner.gpo_name }}</strong> → <code>{{ c.winner.value }}</code>{% if c.winner.enforced %} <span style="color:var(--red);font-size:10px">ENFORCED</span>{% endif %}</div>
          {% for l in c.losers %}<div class="cc-loser">❌ Écrasé : <strong style="cursor:pointer" onclick="openGPODetail('{{ l.gpo_guid }}')">{{ l.gpo_name }}</strong> → <code>{{ l.value }}</code></div>{% endfor %}
          {% if not c.enforced_wins %}<div style="margin-top:8px;font-size:11px;color:var(--txt3);font-style:italic">⚠ Aucune GPO Enforced — l'ordre dépend de la profondeur des OU et de l'ordre des liens dans gPLink</div>{% endif %}
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
    <div class="content-area"><button onclick="goBack()" style="margin-bottom:16px;display:inline-flex;align-items:center;gap:6px;padding:6px 14px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--txt2);font-size:12px;cursor:pointer">← Retour</button>
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

  <!-- SUB : Recommandations -->
  <div id="sub-security-reco" style="display:none">
    <div class="page-header">
      <h2>💡 Recommandations — Paramètres non couverts par GPO</h2>
      <p>Ces paramètres importants ne sont pas configurés explicitement dans vos GPO — la valeur par défaut Windows s'applique, ce qui peut être insuffisant</p>
    </div>
    <div class="content-area"><button onclick="goBack()" style="margin-bottom:16px;display:inline-flex;align-items:center;gap:6px;padding:6px 14px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--txt2);font-size:12px;cursor:pointer">← Retour</button>
      <div class="info-box" style="background:rgba(74,127,212,.08);border-color:rgba(74,127,212,.25);color:var(--txt2)">
        💡 Ces éléments ne sont <strong>pas des vulnérabilités confirmées</strong> — ce sont des paramètres que vous devriez envisager de configurer explicitement dans vos GPO pour renforcer votre sécurité.
        <br>Contrairement aux critiques et alertes, ils n'impactent <strong>pas le score de risque</strong>.
      </div>

      {% set reco_crits = data.uncovered_findings | selectattr('severity','eq','critical') | list %}
      {% set reco_warns = data.uncovered_findings | selectattr('severity','eq','warning') | list %}
      {% set reco_infos = data.uncovered_findings | selectattr('severity','eq','info') | list %}

      {% if reco_crits %}
      <div class="section-title" style="margin-top:16px">🔴 Priorité haute — valeur par défaut Windows insuffisante ({{ reco_crits|length }})</div>
      <div class="finding-list">
        {% for f in reco_crits %}
        <div class="finding-card warning">
          <div class="fc-head" onclick="togFC(this)">
            <div class="fc-sev" style="background:var(--red);opacity:.6"></div>
            <div class="fc-main">
              <div class="fc-title">{{ f.title }}</div>
              <div class="fc-meta"><span>{{ f.category }}</span><span>· {{ f.ref }}</span></div>
            </div>
            <span class="fc-pill" style="background:rgba(220,60,60,.1);color:var(--red);border:1px solid rgba(220,60,60,.25)">à configurer</span>
            <span class="fc-arrow">▶</span>
          </div>
          <div class="fc-body">
            <div style="font-size:12px;color:var(--txt3);padding:6px 10px;background:var(--surface2);border-radius:4px;margin-bottom:8px">{{ f.detail }}</div>
            {% if f.get('rec_value') %}<div style="font-size:11px;color:var(--blue);padding:4px 10px;background:var(--blue-bg);border-radius:4px;margin-bottom:6px">🎯 Valeur recommandée : <strong>{{ f.rec_value }}</strong></div>{% endif %}
            <div class="fc-reco">✅ {{ f.remediation }}</div>
            {% if f.get('scope_note') %}<div style="margin-top:6px;font-size:11px;padding:8px 12px;background:var(--blue-bg);border:1px solid rgba(74,127,212,.2);border-radius:4px;color:var(--blue)">{{ f.scope_note }}</div>{% endif %}
            <div class="explain-zone" id="ez-r-{{ f.rule_id }}"></div>
          </div>
        </div>
        {% endfor %}
      </div>
      {% endif %}

      {% if reco_warns %}
      <div class="section-title" style="margin-top:16px">🟡 Priorité normale ({{ reco_warns|length }})</div>
      <div class="finding-list">
        {% for f in reco_warns %}
        <div class="finding-card info">
          <div class="fc-head" onclick="togFC(this)">
            <div class="fc-sev" style="background:var(--amber);opacity:.6"></div>
            <div class="fc-main">
              <div class="fc-title">{{ f.title }}</div>
              <div class="fc-meta"><span>{{ f.category }}</span><span>· {{ f.ref }}</span></div>
            </div>
            <span class="fc-pill" style="background:rgba(212,137,42,.1);color:var(--amber);border:1px solid rgba(212,137,42,.25)">à configurer</span>
            <span class="fc-arrow">▶</span>
          </div>
          <div class="fc-body">
            <div style="font-size:12px;color:var(--txt3);padding:6px 10px;background:var(--surface2);border-radius:4px;margin-bottom:8px">{{ f.detail }}</div>
            {% if f.get('rec_value') %}<div style="font-size:11px;color:var(--blue);padding:4px 10px;background:var(--blue-bg);border-radius:4px;margin-bottom:6px">🎯 Valeur recommandée : <strong>{{ f.rec_value }}</strong></div>{% endif %}
            <div class="fc-reco">✅ {{ f.remediation }}</div>
            <div class="explain-zone" id="ez-r-{{ f.rule_id }}"></div>
          </div>
        </div>
        {% endfor %}
      </div>
      {% endif %}

      {% if reco_infos %}
      <div class="section-title" style="margin-top:16px">ℹ Optionnel ({{ reco_infos|length }})</div>
      <div class="finding-list">
        {% for f in reco_infos %}
        <div class="finding-card info">
          <div class="fc-head" onclick="togFC(this)">
            <div class="fc-sev info"></div>
            <div class="fc-main">
              <div class="fc-title">{{ f.title }}</div>
              <div class="fc-meta"><span>{{ f.category }}</span><span>· {{ f.ref }}</span></div>
            </div>
            <span class="fc-pill info">info</span>
            <span class="fc-arrow">▶</span>
          </div>
          <div class="fc-body">
            <div style="font-size:12px;color:var(--txt3);padding:6px 10px;background:var(--surface2);border-radius:4px;margin-bottom:8px">{{ f.detail }}</div>
            {% if f.get('rec_value') %}<div style="font-size:11px;color:var(--blue);padding:4px 10px;background:var(--blue-bg);border-radius:4px;margin-bottom:6px">🎯 Valeur recommandée : <strong>{{ f.rec_value }}</strong></div>{% endif %}
            <div class="fc-reco">✅ {{ f.remediation }}</div>
          </div>
        </div>
        {% endfor %}
      </div>
      {% endif %}

      {% if not data.uncovered_findings %}
      <div class="empty-state"><div class="es-icon">✅</div><div class="es-title">Tous les paramètres importants sont couverts par vos GPO</div></div>
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
    <div class="content-area"><button onclick="goBack()" style="margin-bottom:16px;display:inline-flex;align-items:center;gap:6px;padding:6px 14px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--txt2);font-size:12px;cursor:pointer">← Retour</button>
      <div class="toolbar">
        <div class="search-mini"><span class="si">⌕</span><input type="text" placeholder="Rechercher une GPO…" oninput="searchGPOList(this.value)"></div>
        <button class="filter-btn on" onclick="filtGPO('all',this)">Toutes</button>
        <button class="filter-btn" onclick="filtGPO('issues',this)">Avec problèmes</button>
        <button class="filter-btn" onclick="filtGPO('wmi',this)">Filtre WMI</button>
        <button class="filter-btn" onclick="filtGPO('orphan',this)">Orphelines</button>
        <div style="margin-left:auto;display:flex;align-items:center;gap:4px;font-size:11px;color:var(--txt3)">
          Trier :
          <button class="sort-btn" data-sort="score"    onclick="setGPOSort('score')"      style="padding:3px 10px;border-radius:4px;border:1px solid var(--border);background:var(--surface2);color:var(--txt2);cursor:pointer;font-size:11px">Score ▼</button>
          <button class="sort-btn active" data-sort="alpha" onclick="setGPOSort('alpha')"  style="padding:3px 10px;border-radius:4px;border:1px solid var(--border);background:var(--surface2);color:var(--txt2);cursor:pointer;font-size:11px">A → Z</button>
          <button class="sort-btn" data-sort="alpha-desc" onclick="setGPOSort('alpha-desc')" style="padding:3px 10px;border-radius:4px;border:1px solid var(--border);background:var(--surface2);color:var(--txt2);cursor:pointer;font-size:11px">Z → A</button>
          <button class="sort-btn" data-sort="date"    onclick="setGPOSort('date')"        style="padding:3px 10px;border-radius:4px;border:1px solid var(--border);background:var(--surface2);color:var(--txt2);cursor:pointer;font-size:11px">Date ▼</button>
        </div>
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
    <div class="content-area"><button onclick="goBack()" style="margin-bottom:16px;display:inline-flex;align-items:center;gap:6px;padding:6px 14px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--txt2);font-size:12px;cursor:pointer">← Retour</button>
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
</div><!-- /tab-diag -->


<!-- ════════════════════ ONGLET INVENTAIRE ════════════════════ -->
<div class="tab-content" id="tab-inventory">

  <!-- SUB : Par OU -->
  <div id="sub-inventory-byou">
    <div class="page-header">
      <h2>⊢ Inventaire par OU</h2>
      <p>Quelles GPO s'appliquent sur quelle OU — dans l'ordre de priorité Windows réel</p>
    </div>
    <div class="content-area"><button onclick="goBack()" style="margin-bottom:16px;display:inline-flex;align-items:center;gap:6px;padding:6px 14px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--txt2);font-size:12px;cursor:pointer">← Retour</button>
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
    <div class="content-area"><button onclick="goBack()" style="margin-bottom:16px;display:inline-flex;align-items:center;gap:6px;padding:6px 14px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--txt2);font-size:12px;cursor:pointer">← Retour</button>
      <div id="type-grid-area"></div>
      <div id="type-detail-area"></div>
    </div>
  </div>

</div><!-- /tab-inventory -->

</main>
</div><!-- /app -->

<!-- ══ DONNÉES ══════════════════════════════════════════════════════════════ -->
<script id="gpo-json" type="application/json">{{ data.gpo_reports | tojson }}</script>
<script id="content-index-json" type="application/json">{{ data.gpo_content_index | tojson }}</script>
<script id="search-index-json" type="application/json">{{ data.search_index | tojson }}</script>
<script id="catchall-json" type="application/json">{{ data.catchall_gpos | tojson }}</script>
<script id="empty-json" type="application/json">{{ data.empty_gpo_guids | tojson }}</script>
<script>
// ══════════════════════════════════════════════════════════════════════
// INIT
// ══════════════════════════════════════════════════════════════════════
let _gpos = [];
// _gpoContentIndex chargé depuis le tag JSON dédié (différé pour accélérer le démarrage)
let _gpoContentIndex = {};
(function(){
  try {
    const el = document.getElementById('content-index-json');
    if (el) _gpoContentIndex = JSON.parse(el.textContent);
  } catch(e) { console.warn('content-index-json parse error', e); }
})();
// _searchIndex chargé depuis le tag JSON dédié
let _searchIndex = [];
(function(){
  try {
    const el = document.getElementById('search-index-json');
    if (el) _searchIndex = JSON.parse(el.textContent);
  } catch(e) { console.warn('search-index-json parse error', e); }
})();
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

  // Index des GPO fourre-tout et vides pour les badges
  try {
    const catchall = JSON.parse(document.getElementById('catchall-json').textContent || '[]');
    const empty    = JSON.parse(document.getElementById('empty-json').textContent || '[]');
    window._catchallGuids = new Set(catchall.map(g=>g.gpo_guid));
    window._emptyGuids    = new Set(empty);
  } catch(e) {
    window._catchallGuids = new Set();
    window._emptyGuids    = new Set();
  }

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
let _navStack = [];  // pile de navigation complète

function _pushNav() {
  _navStack.push({tab: _currentTab, sub: _currentSub[_currentTab]});
  if(_navStack.length > 30) _navStack.shift();
  _updateBackBtn();
}

function _updateBackBtn() {
  const btn = document.getElementById('global-back-btn');
  if(!btn) return;
  if(_navStack.length > 0) {
    btn.style.display = 'flex';
    const prev = _navStack[_navStack.length - 1];
    const labels = {
      'security-overview': 'Vue d\'ensemble',
      'security-critical': 'Critiques',
      'security-warnings': 'Alertes',
      'security-compliant': 'Conformes',
      'security-conflicts': 'Conflits',
      'security-orphans': 'Orphelines',
      'diag-search': 'Recherche',
      'diag-gpolist': 'Toutes les GPO',
      'diag-timeline': 'Timeline',
      'inventory-byou': 'Par OU',
      'inventory-bytype': 'Par type',
    };
    const key = prev.tab + '-' + prev.sub;
    btn.querySelector('.back-label').textContent = labels[key] || prev.sub;
  } else {
    btn.style.display = 'none';
  }
}

function goBack() {
  if(_navStack.length === 0) return;
  const prev = _navStack.pop();
  _updateBackBtn();
  _switchTabInternal(prev.tab);
  _showSubInternal(prev.tab, prev.sub);
}

// ── Navigation interne (sans push sur la pile) ──────────────────────────────
function _switchTabInternal(tab) {
  document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.main-tab').forEach(b=>b.classList.remove('active'));
  document.querySelectorAll('.sub-nav').forEach(n=>n.style.display='none');
  document.getElementById('tab-'+tab).classList.add('active');
  document.getElementById('tab-btn-'+tab).classList.add('active');
  document.getElementById('subnav-'+tab).style.display='';
  _currentTab = tab;
}

function _showSubInternal(tab, sub) {
  const tabEl = document.getElementById('tab-'+tab);
  if(!tabEl) return;
  tabEl.querySelectorAll('[id^="sub-'+tab+'-"]').forEach(el=>el.style.display='none');
  const el = document.getElementById('sub-'+tab+'-'+sub);
  if(el) el.style.display='';
  _currentSub[tab] = sub;
  document.querySelectorAll('#subnav-'+tab+' .sub-item').forEach(si=>{
    si.classList.toggle('active', si.getAttribute('onclick') && si.getAttribute('onclick').includes("'"+sub+"'"));
  });
  if(tab==='inventory' && sub==='byou') renderByOU('');
  if(tab==='inventory' && sub==='bytype') renderByType();
  if(tab==='diag' && sub==='timeline') renderTimeline();
  if(tab==='diag' && sub==='gpolist') renderGPOList(_gpos);
}

// ── Navigation publique (avec push sur la pile) ─────────────────────────────
function switchTab(tab) {
  _pushNav();
  _switchTabInternal(tab);
  _showSubInternal(tab, _currentSub[tab]);
}

function showSub(tab, sub) {
  _pushNav();
  if(_currentTab !== tab) _switchTabInternal(tab);
  _showSubInternal(tab, sub);
}

// ── Overlay GPO Détail ───────────────────────────────────────────────────────
function openGPODetail(guid) {
  // Ouvre la fiche GPO dans un panneau overlay — ne change PAS l'onglet courant
  const overlay = document.getElementById('gpo-overlay');
  const body    = document.getElementById('gpo-overlay-body');
  const title   = document.getElementById('gpo-overlay-title');
  const meta    = document.getElementById('gpo-overlay-meta');
  if(!overlay) return;

  const g = _gpos.find(x=>x.guid===guid);
  if(!g) return;

  // Remplir le header
  title.textContent = g.name;
  const flags = parseInt(g.flags||0);
  const flagStr = flags===3?'⊘ Entièrement désactivée':flags===1?'⊘ Config. ordinateur désactivée':flags===2?'⊘ Config. utilisateur désactivée':'';
  meta.innerHTML = [
    g.guid,
    g.changed ? '📅 ' + g.changed.slice(0,10) : '',
    flagStr ? '<span style="color:var(--amber)">'+flagStr+'</span>' : '',
    g.wmi_filter ? '<span style="color:var(--blue)">⚙ WMI : '+_escHtml(g.wmi_filter.name||'')+'</span>' : '',
  ].filter(Boolean).join(' · ');

  // Remplir le corps avec renderGPODetail
  body.innerHTML = '';
  renderGPODetail(guid, body);

  // Afficher l'overlay
  overlay.style.display = 'block';
  document.body.style.overflow = 'hidden';
  // Animer l'entrée
  const panel = document.getElementById('gpo-overlay-panel');
  panel.style.transform = 'translateX(100%)';
  panel.style.transition = 'transform .25s ease';
  requestAnimationFrame(()=>{ panel.style.transform = 'translateX(0)'; });
}

function closeGPOOverlay() {
  const overlay = document.getElementById('gpo-overlay');
  const panel   = document.getElementById('gpo-overlay-panel');
  if(!overlay) return;
  panel.style.transform = 'translateX(100%)';
  setTimeout(()=>{
    overlay.style.display = 'none';
    document.body.style.overflow = '';
  }, 250);
}

// Fermer avec Échap
document.addEventListener('keydown', e=>{ if(e.key==='Escape') closeGPOOverlay(); });

function goBackFromDetail() {
  closeGPOOverlay();
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
let _gpoFilter='all', _gpoSearch='', _gpoSort='alpha';

function filtGPO(f,btn){
  _gpoFilter=f;
  document.querySelectorAll('#sub-diag-gpolist .filter-btn').forEach(b=>b.classList.remove('on'));
  btn.classList.add('on');
  renderGPOList(_gpos);
}
function searchGPOList(q){ _gpoSearch=q.toLowerCase(); renderGPOList(_gpos); }

function setGPOSort(s){
  _gpoSort=s;
  document.querySelectorAll('.sort-btn').forEach(b=>b.classList.toggle('active',b.dataset.sort===s));
  renderGPOList(_gpos);
}

function renderGPOList(gpos){
  let g=[...gpos];
  if(_gpoSearch) g=g.filter(x=>x.name.toLowerCase().includes(_gpoSearch));
  if(_gpoFilter==='issues') g=g.filter(x=>x.findings?.length>0);
  if(_gpoFilter==='wmi') g=g.filter(x=>x.wmi_filter);
  if(_gpoFilter==='orphan') g=g.filter(x=>x.is_orphan);
  if(_gpoSort==='alpha')
    g.sort((a,b)=>a.name.localeCompare(b.name,'fr',{sensitivity:'base'}));
  else if(_gpoSort==='alpha-desc')
    g.sort((a,b)=>b.name.localeCompare(a.name,'fr',{sensitivity:'base'}));
  else if(_gpoSort==='date')
    g.sort((a,b)=>(b.changed||'').localeCompare(a.changed||''));
  else
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
    const isCatchall = window._catchallGuids && window._catchallGuids.has(gpo.guid);
    const isEmpty    = window._emptyGuids    && window._emptyGuids.has(gpo.guid);

    return`<div class="gpo-card" data-guid="${gpo.guid}" data-issues="${(gpo.findings||[]).length}" data-orphan="${gpo.is_orphan}" data-wmi="${!!gpo.wmi_filter}">
      <div class="gpo-card-head" onclick="openGPODetail('${gpo.guid}')">
        <div class="gpo-name" title="${_escHtml(gpo.name)}">${_escHtml(gpo.name)}</div>
        <div class="gpo-badges">
          ${!gpo.is_orphan?`<span class="badge ${scClass}">Score ${sc}</span>`:''}
          ${critCount>0?`<span class="badge score-bad">🔴 ${critCount}</span>`:''}
          ${warnCount>0?`<span class="badge score-mid">🟡 ${warnCount}</span>`:''}
          ${flg===3?'<span class="badge disabled">désactivée</span>':flg===1?'<span class="badge disabled">PC off</span>':flg===2?'<span class="badge disabled">User off</span>':''}
          ${gpo.is_orphan?'<span class="badge orphan">orpheline</span>':''}
          ${isEmpty?'<span class="badge disabled" title="Aucun paramètre configuré">◌ vide</span>':''}
          ${isCatchall?'<span class="badge" style="background:rgba(212,137,42,.15);color:var(--amber);border:1px solid rgba(212,137,42,.3)" title="Mélange trop de catégories — à découper">📦 fourre-tout</span>':''}
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

function renderGPODetail(guid, container){
  const target = container || document.getElementById('gpo-overlay-body');
  if(!target) return;
  const g=_gpos.find(x=>x.guid===guid);
  if(!g) return;

  const flg=parseInt(g.flags||0);
  const flagLabel={'1':'Config. ordinateur désactivée','2':'Config. utilisateur désactivée','3':'Entièrement désactivée'}[String(flg)]||'';
  const sc=g.score??100;
  const scColor=sc>=70?'var(--green)':sc>=40?'var(--amber)':'var(--red)';

  // Header injecté dans le titre de l'overlay (si disponible)
  const hdrEl = document.getElementById('gpo-overlay-title');
  if(hdrEl) hdrEl.textContent = g.name;
  const metaEl = document.getElementById('gpo-overlay-meta');
  if(metaEl) metaEl.innerHTML = [
    g.guid,
    g.changed ? '📅 ' + g.changed.slice(0,10) : '',
    flagLabel ? '<span style="color:var(--amber)">⊘ '+flagLabel+'</span>' : '',
    g.wmi_filter ? '<span style="color:var(--blue)">⚙ WMI : '+_escHtml(g.wmi_filter.name||'')+'</span>' : '',
  ].filter(Boolean).join(' · ');

  let body='';

  // WMI + Security Filtering affichés dans le corps
  if(g.wmi_filter){
    body+=`<div class="wmi-alert" style="margin-bottom:16px">
      <div class="wmi-alert-title">⚙ Filtre WMI actif — ne s'applique pas sur toutes les machines</div>
      <div style="font-size:11px;color:var(--txt2)"><strong>Nom :</strong> ${_escHtml(g.wmi_filter.name||'')}${g.wmi_filter.description?' — '+_escHtml(g.wmi_filter.description):''}</div>
      <div class="wmi-query">${_escHtml(g.wmi_filter.query||'')}</div>
      <div style="font-size:10px;color:var(--amber);margin-top:4px">Si la GPO ne s'applique pas sur un poste : <code>Get-WmiObject -Query "..."</code></div>
    </div>`;
  }
  if(g.security_filter&&g.security_filter.length>0){
    body+=`<div style="margin-bottom:16px;padding:10px 14px;background:var(--blue-bg);border:1px solid rgba(74,127,212,.25);border-radius:6px">
      <div style="font-size:12px;font-weight:600;color:var(--blue);margin-bottom:5px">🔒 Security Filtering — s'applique uniquement à :</div>
      <div style="font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--txt2)">${g.security_filter.map(s=>_escHtml(s)).join('<br>')}</div>
    </div>`;
  }

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

  target.innerHTML=body;
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
  // Extraire les segments OU d'un DN : ancêtre → feuille
  // "OU=Laptops,OU=Computers,DC=corp,DC=local" → ['Computers','Laptops']
  function ouSegs(dn){
    return dn.split(',')
      .filter(p=>p.trim().toUpperCase().startsWith('OU='))
      .map(p=>p.trim().slice(3))
      .reverse();
  }
  // Construire l'arbre
  const tree={label:'',fullDn:'',children:{},gpos:[]};
  Object.values(ouMap).forEach(({dn,gpos})=>{
    const segs=ouSegs(dn);
    if(!segs.length){ tree.gpos.push(...gpos); return; }
    let node=tree;
    segs.forEach((seg,i)=>{
      const k=seg.toLowerCase();
      if(!node.children[k]){
        const dcP=dn.split(',').filter(p=>p.trim().toUpperCase().startsWith('DC=')).join(',');
        const ouP=segs.slice(0,i+1).reverse().map(s=>`OU=${s}`).join(',');
        node.children[k]={label:seg,fullDn:ouP+(dcP?','+dcP:''),children:{},gpos:[]};
      }
      node=node.children[k];
      if(i===segs.length-1) node.gpos.push(...gpos);
    });
  });
  // Trier les GPO : normales par priorité croissante, enforced en dernier
  function sortG(gpos){
    const e=gpos.filter(g=>g.enforced).sort((a,b)=>b.gpoIdx-a.gpoIdx);
    const n=gpos.filter(g=>!g.enforced).sort((a,b)=>b.gpoIdx-a.gpoIdx);
    return[...n,...e];
  }
  const _sc=s=>s==null?'var(--txt3)':s>=70?'var(--green)':s>=40?'var(--amber)':'var(--red)';
  const LC='var(--border2)';
  // Rendu récursif d'un nœud
  function renderNode(node,depth){
    const kids=Object.values(node.children).sort((a,b)=>a.label.localeCompare(b.label));
    const gpos=sortG(node.gpos);
    if(!gpos.length&&!kids.length)return'';
    const ind=depth*22;
    const enf=gpos.filter(g=>g.enforced).length;
    const uid='ou-'+Math.random().toString(36).slice(2,8);
    let h='';
    if(node.label){
      h+=`<div style="margin-left:${ind}px;margin-bottom:5px;position:relative">
        ${depth>0?`<div style="position:absolute;left:-11px;top:0;bottom:50%;width:11px;border-left:1px solid ${LC};border-bottom:1px solid ${LC};border-bottom-left-radius:3px;pointer-events:none"></div>`:''}
        <div class="ou-card" style="margin-bottom:0">
          <div class="ou-card-head" onclick="document.getElementById('${uid}').classList.toggle('open')">
            <span style="color:var(--teal);font-size:12px">${kids.length?'▶':'⊢'}</span>
            <div style="flex:1;min-width:0">
              <span style="font-size:13px;font-weight:600">${_escHtml(node.label)}</span>
              <span style="font-size:10px;color:var(--txt3);margin-left:8px;font-family:'JetBrains Mono',monospace">${_escHtml(node.fullDn)}</span>
            </div>
            <span style="font-size:11px;color:var(--txt3);flex-shrink:0;display:flex;gap:6px">
              ${gpos.length?`<span style="color:var(--blue)">${gpos.length} GPO</span>`:''}
              ${kids.length?`<span>${kids.length} sous-OU</span>`:''}
              ${enf?`<span style="color:var(--red)">${enf} ENFORCED</span>`:''}
            </span>
          </div>
          <div class="ou-card-body" id="${uid}">`;
      if(gpos.length){
        h+=`<div style="font-size:10px;color:var(--txt3);padding:5px 14px;background:var(--surface2);border-bottom:1px solid var(--border)">
          Priorité : <strong>P1 = basse</strong> → <strong>P${gpos.length} = haute (gagne les conflits)</strong>
        </div>`;
        gpos.forEach((g,i)=>{
          h+=`<div class="ou-gpo-row" style="cursor:pointer" onclick="openGPODetail('${g.guid}')">
            <span class="ou-priority">P${i+1}${g.enforced?' ⬆':''}</span>
            <span class="ou-gpo-name">${_escHtml(g.name)}</span>
            ${g.score!=null?`<span class="ou-score" style="color:${_sc(g.score)}">${g.score}/100</span>`:''}
            ${g.changed?`<span class="ou-changed">${g.changed}</span>`:''}
            ${g.enforced?'<span class="badge enforced">ENFORCED</span>':''}
            ${g.disabled?'<span class="badge disabled">lien off</span>':''}
            ${parseInt(g.flags||0)===3?'<span class="badge disabled">GPO off</span>':''}
            ${g.wmi?'<span class="badge wmi">WMI</span>':''}
            ${window._emptyGuids&&window._emptyGuids.has(g.guid)?'<span class="badge disabled">◌ vide</span>':''}
            ${window._catchallGuids&&window._catchallGuids.has(g.guid)?'<span class="badge" style="background:rgba(212,137,42,.15);color:var(--amber);border:1px solid rgba(212,137,42,.3)">📦 fourre-tout</span>':''}
          </div>`;
        });
      }
      h+=`</div></div></div>`;
    }
    // Sous-OUs avec ligne verticale de connexion
    if(kids.length){
      h+=`<div style="margin-left:${node.label?ind+22:ind}px;position:relative">`;
      if(node.label)h+=`<div style="position:absolute;left:0;top:0;bottom:10px;border-left:1px dashed ${LC};pointer-events:none"></div>`;
      kids.forEach(c=>{h+=renderNode(c,0);});
      h+=`</div>`;
    }
    return h;
  }
  let html='';
  // GPO liées directement au domaine (pas dans une OU)
  if(tree.gpos.length){
    const gpos=sortG(tree.gpos);
    html+=`<div class="ou-card" style="margin-bottom:10px;border-left:2px solid var(--blue)">
      <div class="ou-card-head" onclick="this.nextElementSibling.classList.toggle('open')">
        <span>🌐</span>
        <div style="flex:1"><span style="font-size:13px;font-weight:600">Domaine (racine)</span>
          <span style="font-size:11px;color:var(--txt3);margin-left:8px">GPO applicables sur tout le domaine — priorité la plus basse</span></div>
        <span style="font-size:11px;color:var(--txt3)">${gpos.length} GPO ▶</span>
      </div>
      <div class="ou-card-body">
        <div style="font-size:10px;color:var(--txt3);padding:5px 14px;background:var(--surface2);border-bottom:1px solid var(--border)">P1 (basse) → P${gpos.length} (haute)</div>
        ${gpos.map((g,i)=>`<div class="ou-gpo-row" style="cursor:pointer" onclick="openGPODetail('${g.guid}')">
          <span class="ou-priority">P${i+1}</span>
          <span class="ou-gpo-name">${_escHtml(g.name)}</span>
          ${g.score!=null?`<span class="ou-score" style="color:${_sc(g.score)}">${g.score}/100</span>`:''}
          ${g.changed?`<span class="ou-changed">${g.changed}</span>`:''}
          ${g.enforced?'<span class="badge enforced">ENFORCED</span>':''}
        </div>`).join('')}
      </div>
    </div>`;
  }
  Object.values(tree.children).sort((a,b)=>a.label.localeCompare(b.label)).forEach(c=>{html+=renderNode(c,0);});
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

<!-- ════════ OVERLAY GPO DÉTAIL ════════════════════════════════════════════ -->
<div id="gpo-overlay" style="display:none;position:fixed;inset:0;z-index:1000;background:rgba(0,0,0,.55);backdrop-filter:blur(2px)" onclick="if(event.target===this)closeGPOOverlay()">
  <div id="gpo-overlay-panel" style="position:absolute;top:0;right:0;width:min(780px,100vw);height:100vh;background:var(--bg);overflow-y:auto;box-shadow:-8px 0 40px rgba(0,0,0,.3);display:flex;flex-direction:column">
    <!-- Header panneau -->
    <div id="gpo-overlay-header" style="padding:16px 20px;border-bottom:1px solid var(--border);background:var(--surface);position:sticky;top:0;z-index:10;display:flex;align-items:center;gap:12px">
      <div style="flex:1;min-width:0">
        <div id="gpo-overlay-title" style="font-size:15px;font-weight:700;color:var(--txt);overflow:hidden;text-overflow:ellipsis;white-space:nowrap"></div>
        <div id="gpo-overlay-meta" style="font-size:11px;color:var(--txt3);margin-top:2px"></div>
      </div>
      <button onclick="closeGPOOverlay()" style="flex-shrink:0;width:32px;height:32px;border-radius:50%;background:var(--surface2);border:1px solid var(--border);color:var(--txt2);font-size:16px;cursor:pointer;display:flex;align-items:center;justify-content:center" title="Fermer">✕</button>
    </div>
    <!-- Corps du panneau -->
    <div id="gpo-overlay-body" style="padding:20px;flex:1"></div>
  </div>
</div>
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
    parser.add_argument('-o', '--output', default='rapport_gpo.html', help='Fichier de sortie')
    parser.add_argument('--json',     action='store_true', help='Export JSON')
    args = parser.parse_args()

    print("=" * 60)
    print("  GPOctopus Audit — CIS · ANSSI · MS Baseline")
    print("=" * 60)

    if args.dc and args.domain and args.user and args.password:
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
    print(f"[+] Score de risque : {report['global_score']}/100 — {report['risk_level']}")
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
        output
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

# ─── Helpers ─────────────────────────────────────────────────────────────────

def _run_auditor(extra_args, output):
    """Lance l'audit en appelant main() directement dans le même processus."""
    argv_backup = sys.argv[:]
    sys.argv = [sys.argv[0]]
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
