# 🐙 GPOctopus

> Audit de sécurité des GPO Active Directory — collecte LDAP + analyse SYSVOL, rapport HTML interactif.
> Référentiels CIS Benchmarks · ANSSI · Microsoft Security Baseline 2022.

---

## ✨ Fonctionnalités

- **Wizard interactif** : lance-le sans argument, il te guide pas à pas
- **Auto-installation** des dépendances Python manquantes au démarrage
- **Collecte LDAP complète** : toutes les GPO, leurs liaisons OU, leurs flags
- **Lecture SYSVOL via SMB direct** (impacket) — pas besoin de `mount.cifs`
- **Montage SYSVOL automatique** si `cifs-utils` est disponible
- **Construction du RSOP** : fusion de toutes les GPO comme le ferait Windows
- **70+ règles d'audit** couvrant :
  - Politique de mots de passe (longueur, complexité, historique, expiration)
  - Authentification réseau (NTLMv1, LM hash, WDigest, LDAP signing)
  - UAC & élévation de privilèges (LocalAccountTokenFilterPolicy, EnableLUA)
  - Audit des événements (connexions, comptes, politiques, PowerShell)
  - Registre (SMBv1, pare-feu, AutoRun, Credential Guard, PrintNightmare)
  - Kerberos, RDP/NLA, LSASS RunAsPPL
- **17 règles d'amélioration** (enhancement) : durcissement avancé sourcé CIS/ANSSI
- **Détection des conflits GPO** : même paramètre, valeurs différentes — gagnant/perdant identifiés
- **Détection des redondances** : mêmes paramètres dans plusieurs GPO
- **Recherche globale cross-catégories** : cherche dans tous les types de contenu GPO
- **Rapport HTML interactif** autonome — aucun serveur requis, chargement optimisé
- **Mode démo** sans AD pour tester le rapport
- **Sauvegarde de la config** pour relancer rapidement

---

## ⚡ Démarrage rapide

```bash
# Installation des dépendances (faite automatiquement au premier lancement)
pip3 install ldap3 jinja2 impacket pycryptodome --break-system-packages

# Wizard interactif (recommandé)
python3 GPOctopus.py

# Mode démo (sans AD)
python3 GPOctopus.py --demo

# Mode CLI direct
python3 GPOctopus.py --dc 192.168.1.10 --domain corp.local --user admin --password 'P@ss!' -o rapport.html
```

---

## 📋 Prérequis

| Prérequis | Détail |
|-----------|--------|
| OS | Linux, macOS, Windows |
| Python | ≥ 3.10 |
| Compte AD | Lecture seule suffit (`Domain Users`) |
| Réseau | Accès au DC sur le port 389 (LDAP) et 445 (SMB/SYSVOL) |
| SYSVOL | Optionnel mais recommandé pour les contrôles registre |

Les dépendances Python sont **installées automatiquement** au premier lancement si elles sont absentes.

---

## 🚀 Modes d'utilisation

### Wizard interactif

```
python3 GPOctopus.py
```

Le wizard guide à travers :
1. Saisie des paramètres AD (DC, domaine, utilisateur, mot de passe)
2. Test de connectivité LDAP automatique
3. Tentative de montage du SYSVOL
4. Génération du rapport
5. Ouverture dans le navigateur

La configuration est sauvegardée dans `gpoctopus.conf` pour les prochaines fois.

### CLI

```bash
# Audit complet avec SYSVOL monté
python3 GPOctopus.py \
  --dc 192.168.1.10 \
  --domain corp.local \
  --user auditeur \
  --password 'MotDePasse!' \
  --sysvol /mnt/sysvol \
  -o rapport.html

# SYSVOL monté manuellement avant l'audit
sudo mount -t cifs //DC01/SYSVOL /mnt/sysvol \
  -o user=admin,domain=CORP,vers=3.0
python3 GPOctopus.py --dc DC01 --domain corp.local \
  --user admin --password 'P@ss!' \
  --sysvol /mnt/sysvol -o rapport.html

# Mode démo (données fictives, aucun AD requis)
python3 GPOctopus.py --demo -o demo.html

# Export JSON
python3 GPOctopus.py --dc ... --json -o rapport.json
```

---

## 📊 Rapport HTML

Le rapport généré est un fichier HTML **autonome** (aucun serveur requis) avec un chargement optimisé (lazy rendering, données chargées à la demande).

| Section | Contenu |
|---------|---------|
| **Tableau de bord** | Score global, graphiques, actions prioritaires, accès rapide par sévérité |
| **Priorités** | Findings triés par criticité, GPO à modifier identifiées |
| **Recherche GPO** | Moteur de recherche cross-catégories dans toutes les GPO |
| **Constatations RSOP** | Ce qui s'applique réellement après fusion des GPO (critical / warning / info) |
| **GPO par GPO** | Contenu détaillé de chaque GPO (sécurité, registre, imprimantes, scripts…) |
| **Par type** | Toutes les GPO regroupées par type de contenu |
| **Par OU** | Quelles GPO s'appliquent sur quelle unité organisationnelle |
| **Conformes** | Contrôles correctement configurés dans le RSOP |
| **Améliorations** | Pistes de durcissement avancées — CIS/ANSSI niveau supérieur |
| **Conflits GPO** | Même paramètre, valeurs différentes dans plusieurs GPO — gagnant/perdant identifiés |
| **Orphelines** | GPO non liées à une OU + paramètres redondants |

---

## 🔎 Moteur de recherche GPO

La vue **Recherche GPO** permet de chercher dans l'ensemble du contenu SYSVOL collecté :

- **Recherche multi-mots avec ET inter-catégories** : `RDS imprimante` trouve les GPO qui parlent à la fois de RDS et d'imprimantes, même dans des paramètres différents
- **Raccourcis rapides** : Imprimantes, Lecteurs, Scripts, Tâches, Services, Registre, Groupes, Liens OU
- **Résultats groupés par GPO** avec surbrillance des termes et clic pour ouvrir la GPO directement
- **Filtres dynamiques** par type de contenu selon les résultats
- **Suggestion intelligente** : si aucune GPO ne contient tous les termes ensemble, indique lequel donne des résultats seul

Types de contenu indexés : paramètres de sécurité, imprimantes, lecteurs réseau, raccourcis, scripts (startup/shutdown/logon/logoff), tâches planifiées, registre (Registry.pol + XML + GptTmpl), services, groupes locaux, variables d'environnement, copie de fichiers, audit avancé, liens OU.

---

## ⚡ Détection des conflits GPO

GPOctopus détecte les cas où le **même paramètre est configuré avec des valeurs différentes** dans plusieurs GPO actives — ce qui est distinct d'une simple redondance (même valeur).

Pour chaque conflit, le rapport indique :
- La **GPO gagnante** (valeur appliquée réellement, enforced prioritaire)
- Les **GPO perdantes** (valeurs écrasées silencieusement)
- Le niveau de criticité (sécurité critique / configuration)
- La recommandation pour résoudre l'ambiguïté

---

## 🔍 Règles d'audit

### GptTmpl.inf (politique de sécurité)

| ID | Catégorie | Référence |
|----|-----------|-----------|
| PWD-001 | Longueur minimale < 14 caractères | CIS 1.1.1 · ANSSI R-03 |
| PWD-002 | Historique < 24 entrées | CIS 1.1.2 · ANSSI R-03 |
| PWD-003 | Complexité désactivée | CIS 1.1.5 |
| PWD-004 | Expiration illimitée ou > 365j | CIS 1.1.3 |
| AUTH-001 | Hash LM stocké | CIS 2.3.11.2 · ANSSI R-05 |
| AUTH-002 | NTLMv1 autorisé (LmCompatibilityLevel < 5) | CIS 2.3.11.7 · ANSSI R-06 |
| AUTH-003 | Verrouillage désactivé ou > 10 tentatives | CIS 1.2.1 |
| AUDIT-001/002/003 | Audit connexions / comptes / politiques non configuré | CIS 17.x |

### Registry Values & Registry.pol

| ID | Risque | CVE / Référence |
|----|--------|-----------------|
| SYS-001 | WDigest activé — mots de passe en clair dans lsass | KB2871997 |
| SYS-002 | SMBv1 non désactivé | MS ADV170012 |
| UAC-001 | UAC désactivé (EnableLUA = 0) | CIS 2.3.17.1 |
| UAC-004 | LocalAccountTokenFilterPolicy = 1 (Pass-the-Hash) | MS KB951016 |
| PRINT-001 | Drivers imprimantes non restreints (PrintNightmare) | CVE-2021-34527 |
| LDAP-001 | Intégrité LDAP client désactivée | MS ADV190023 |
| LSA-001 | RunAsPPL non activé (Mimikatz) | MS KB3033929 |
| RDP-001 | NLA non requis pour RDP | CVE-2019-0708 |
| PS-001 | Script Block Logging PowerShell désactivé | CIS 18.9.100.1 |

### Améliorations (enhancement) — durcissement avancé

Ces règles ne signalent pas une faille mais proposent un niveau de sécurité supérieur, vérifiable via GPO/registre. Chaque suggestion inclut le chemin GPO exact et la clé de registre.

| ID | Catégorie | Référence |
|----|-----------|-----------|
| ENH-NTLM-001 | Audit NTLM sortant non activé sur les DC | ANSSI CERTFR-2021-DUR-001 · CIS 2.3.11.9 |
| ENH-NTLM-002 | Restriction NTLM entrant dans le domaine | ANSSI CERTFR-2021-DUR-001 · CIS 2.3.11.10 |
| ENH-KERB-001 | RC4 Kerberos non désactivé (Kerberoasting) | CIS 2.3.11.4 · ANSSI R-07 |
| ENH-KERB-002 | Kerberos Armoring (FAST) non activé | MS Security Baseline 2022 |
| ENH-AUDIT-001 | Audit avancé non prioritaire sur l'audit legacy | CIS 17.1.1 · ANSSI R-09 |
| ENH-AUDIT-002 | Transcription PowerShell non activée | CIS 18.9.100.2 · ANSSI R-09 |
| ENH-AUDIT-003 | Module Logging PowerShell non activé | CIS 18.9.100.3 · ANSSI R-09 |
| ENH-SMB-001 | Signature SMB non requise côté serveur | CIS 2.3.8.2 · MS Baseline 2022 |
| ENH-SMB-002 | Chiffrement SMB non activé | MS Baseline 2022 · KB5040266 |
| ENH-LSA-001 | Mode audit PPL LSASS non configuré | MS KB3033929 · ANSSI R-08 |
| ENH-AUTH-001 | Fine-Grained Password Policy non détectée | ANSSI R-03 |
| ENH-AUTH-002 | LAPS non détecté via GPO | ANSSI R-30 · CIS 18.3.2 |
| ENH-RDP-001 | Restricted Admin Mode RDP non activé | ANSSI R-12 · MS KB2871997 |
| ENH-RDP-002 | Chiffrement RDP non forcé au niveau maximum | CIS 18.10.56.3 |
| ENH-SYS-001 | Credential Guard non configuré | MS Baseline 2022 · ANSSI R-08 |
| ENH-SYS-002 | Protected Users group non utilisé | ANSSI R-08 · MS KB2871997 |
| ENH-SYS-003 | Timeout sessions RDP déconnectées non configuré | CIS 18.10.56.2 |

---

## 🗂️ Contenu GPO analysé

En plus des politiques de sécurité, GPOctopus lit et affiche dans le rapport :

- **Imprimantes** (Machine & Utilisateur) — `Printers.xml`
- **Lecteurs réseau** — `Drives.xml`
- **Raccourcis** — `Shortcuts.xml`
- **Tâches planifiées** — `ScheduledTasks.xml`
- **Scripts** démarrage/arrêt/ouverture/fermeture de session — `scripts.ini` + `psscripts.ini`
- **Groupes locaux** — `Groups.xml`
- **Variables d'environnement** — `EnvironmentVariables.xml`
- **Copie de fichiers** — `Files.xml`
- **Services Windows** — `Services.xml`
- **Audit avancé** — `audit.csv`
- **Préférences Registre XML** — `Registry.xml`

---

## ⚠️ Avertissement légal

Ce script est destiné à des **audits de sécurité autorisés**. Toute utilisation sur des systèmes sans autorisation explicite est illégale. L'auteur décline toute responsabilité en cas d'utilisation malveillante.

---

## 📄 Licence

MIT — voir [LICENSE](LICENSE)
