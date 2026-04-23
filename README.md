# 🐙 GPOctopus

> Audit de sécurité des GPO Active Directory — collecte LDAP + analyse SYSVOL, rapport HTML interactif.
> Référentiels CIS Benchmarks · ANSSI · Microsoft Security Baseline.

---

## ✨ Fonctionnalités

- **Wizard interactif** : lance-le sans argument, il te guide pas à pas
- **Auto-installation** des dépendances Python manquantes au démarrage
- **Collecte LDAP complète** : toutes les GPO, leurs liaisons OU, leurs flags
- **Lecture SYSVOL via SMB direct** (impacket) — pas besoin de `mount.cifs`
- **Montage SYSVOL automatique** si `cifs-utils` est disponible
- **Construction du RSOP** : fusion de toutes les GPO comme le ferait Windows
- **50+ règles d'audit** couvrant :
  - Politique de mots de passe (longueur, complexité, historique, expiration)
  - Authentification réseau (NTLMv1, LM hash, WDigest, LDAP signing)
  - UAC & élévation de privilèges (LocalAccountTokenFilterPolicy, EnableLUA)
  - Audit des événements (connexions, comptes, politiques, PowerShell)
  - Registre (SMBv1, pare-feu, AutoRun, Credential Guard, PrintNightmare)
  - Kerberos, RDP/NLA, LSASS RunAsPPL
- **Rapport HTML interactif** : score global, graphiques, détail par GPO, par OU, par type de contenu
- **Détection des redondances** : mêmes paramètres dans plusieurs GPO
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

Le wizard te guide à travers :
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

Le rapport généré est un fichier HTML **autonome** (aucun serveur requis) avec :

| Section | Contenu |
|---------|---------|
| **Tableau de bord** | Score global, graphiques, actions prioritaires |
| **Priorités** | Findings triés par criticité, GPO à modifier |
| **Constatations RSOP** | Ce qui s'applique réellement après fusion des GPO |
| **GPO par GPO** | Contenu détaillé de chaque GPO (sécurité, registre, imprimantes, scripts...) |
| **Par type** | Toutes les GPO regroupées par type de contenu |
| **Par OU** | Quelles GPO s'appliquent sur quelle unité organisationnelle |
| **Conformes** | Contrôles correctement configurés |
| **Orphelines** | GPO non liées à une OU + paramètres redondants |

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
