# 🐙 GPOctopus

> **Audit de sécurité des GPO Active Directory**
> Collecte LDAP + analyse SYSVOL complète, rapport HTML interactif autonome.
> Référentiels **CIS Benchmarks · ANSSI · Microsoft Security Baseline 2022**.

---

## ✨ Ce que fait GPOctopus

GPOctopus se connecte à votre Active Directory, lit toutes vos GPO (LDAP + SYSVOL), construit le RSOP réel et génère un rapport HTML interactif qui distingue clairement ce qui est **mal configuré**, ce qui **n'est pas couvert**, et ce qui est **conforme**.

### Collecte

- Toutes les GPO du domaine via **paging LDAP** (pas de limite de résultats)
- GPO liées aux **OU, au domaine et aux sites réseau AD**
- Lecture **SYSVOL via SMB direct** (impacket) — pas besoin de `mount.cifs`
- Détection automatique du préfixe SYSVOL (FQDN, NetBIOS, chemin court)
- **Filtres WMI** et **Security Filtering** collectés pour chaque GPO
- **Fine-Grained Password Policies** (PSO) pour éviter les faux positifs

### Analyse

- **Construction du RSOP** : fusion de toutes les GPO dans l'ordre de priorité Windows (profondeur OU, ENFORCED, liens désactivés exclus)
- **62 règles d'audit** : GptTmpl.inf, Registry.pol, Registry.xml, Privilege Rights
- **Décodage ADMX** : 80+ clés de registre traduites en paramètres lisibles (WSUS, PowerShell, RDP, Defender, BitLocker, LAPS, TLS, UAC, PrintNightmare, SMB, NTLM, WDigest…)
- **Score de risque style PingCastle** : 0 = sûr, 100 = critique, par catégorie, score global = maximum des catégories
- **Findings séparés** : problèmes confirmés (valeur dangereuse) vs recommandations (paramètre absent)
- **Détection des contradictions GPO** : une GPO sécurise un paramètre, une autre le contredit — avec identification claire du danger
- **Détection des GPO fourre-tout** : trop de catégories mélangées, suggestions de découpage
- **Détection des GPO par défaut modifiées** avec plan de migration concret

### Contenu GPO analysé

| Fichier SYSVOL | Contenu |
|----------------|---------|
| `GptTmpl.inf` | Mots de passe, audit, droits utilisateurs, Kerberos, options de sécurité |
| `Registry.pol` | Paramètres ADMX machine et utilisateur |
| `Registry.xml` | Préférences registre |
| `Printers.xml` | Imprimantes machine et utilisateur |
| `Drives.xml` | Lecteurs réseau |
| `Shortcuts.xml` | Raccourcis |
| `ScheduledTasks.xml` | Tâches planifiées |
| `scripts.ini` + `psscripts.ini` | Scripts startup/shutdown/logon/logoff |
| `Groups.xml` | Groupes locaux |
| `Files.xml` | Copie de fichiers |
| `Services.xml` | Services Windows |
| `audit.csv` | Audit avancé |
| `Applications.xml` | Installation de logiciels |
| `DataSources.xml` | Sources ODBC |
| `InternetSettings.xml` | Proxy / Internet Explorer |
| `NetworkShares.xml` | Partages réseau |
| `Folders.xml` | Création/suppression de dossiers |
| `NetworkOptions.xml` | VPN / connexions réseau |
| `IniFiles.xml` | Modification de fichiers .ini |
| `Regional.xml` | Paramètres régionaux |

---

## ⚡ Démarrage rapide

```bash
# Dépendances (installées automatiquement au premier lancement)
pip3 install ldap3 jinja2 impacket pycryptodome --break-system-packages

# Wizard interactif (recommandé)
python3 gpoctopus.py

# CLI direct
python3 gpoctopus.py \
  --dc 192.168.1.10 \
  --domain corp.local \
  --user auditeur \
  --password 'P@ss!' \
  -o rapport.html
```

---

## 📋 Prérequis

| Prérequis | Détail |
|-----------|--------|
| OS | Linux, macOS, Windows (WSL) |
| Python | ≥ 3.10 |
| Compte AD | Lecture seule suffit (`Domain Users`) |
| Réseau | Accès DC sur port 389 (LDAP) et 445 (SMB/SYSVOL) |
| SYSVOL | Recommandé — indispensable pour les contrôles registre et scripts |

Les dépendances Python sont **installées automatiquement** au premier lancement si elles sont absentes.

---

## 🚀 Modes d'utilisation

### Wizard interactif

```
python3 gpoctopus.py
```

Le wizard guide à travers :
1. Saisie des paramètres AD (DC, domaine, utilisateur, mot de passe)
2. Test de connectivité LDAP automatique
3. Montage SYSVOL via SMB direct (impacket) avec détection du préfixe
4. Génération du rapport HTML

La configuration DC/domaine/utilisateur est sauvegardée dans `gpoctopus.conf` pour les prochaines fois.

### CLI

```bash
# Audit complet
python3 gpoctopus.py \
  --dc 192.168.1.10 \
  --domain corp.local \
  --user auditeur \
  --password 'MotDePasse!' \
  -o rapport.html

# SYSVOL monté manuellement
sudo mount -t cifs //DC01/SYSVOL /mnt/sysvol \
  -o user=admin,domain=CORP,vers=3.0
python3 gpoctopus.py \
  --dc DC01 --domain corp.local \
  --user admin --password 'P@ss!' \
  --sysvol /mnt/sysvol \
  -o rapport.html
```

---

## 📊 Rapport HTML

Le rapport est un fichier HTML **autonome** (aucun serveur requis). Les données volumineuses sont chargées en JSON différé pour éviter le blocage du navigateur sur les grands domaines.

### Onglet Sécurité

| Section | Contenu |
|---------|---------|
| **Vue d'ensemble** | Score de risque par catégorie (style PingCastle), GPO par défaut modifiées, aperçu des problèmes |
| **Critiques confirmés** | Paramètres explicitement mal configurés dans les GPO — à corriger en priorité absolue |
| **Alertes confirmées** | Paramètres mal configurés de sévérité warning |
| **Recommandations** | Paramètres importants absents des GPO (valeur par défaut insuffisante) — n'impacte pas le score |
| **Conformes** | Contrôles correctement configurés, avec la valeur recommandée |
| **Conflits GPO** | Même paramètre, valeurs différentes — gagnant/perdant identifiés, contradictions sécurité détectées |
| **Orphelines** | GPO non liées à une OU |

### Onglet Diagnostic

| Section | Contenu |
|---------|---------|
| **Recherche** | Moteur cross-catégories avec synonymes, combos rapides, scope_note si portée limitée |
| **Toutes les GPO** | Liste triable (score, A→Z, Z→A, date), filtrable, avec badges fourre-tout / vide / WMI / ENFORCED |
| **Timeline** | GPO modifiées par période (7j / 30j / 90j / 1an) |

### Onglet Inventaire

| Section | Contenu |
|---------|---------|
| **Par OU** | Arbre AD hiérarchique avec lignes de connexion, ordre de priorité Windows (P1=bas → Pn=haut), badges |
| **Par type** | GPO regroupées par type de contenu |

### Fiche GPO (panneau overlay)

Accessible depuis n'importe quel onglet sans changer de page — glisse depuis la droite.
Affiche : filtres WMI, Security Filtering, findings de sécurité, tous les paramètres configurés groupés par catégorie, liaisons OU.

---

## 🔒 Score de risque

Le score s'inspire de **PingCastle** :

- **0 = aucun risque · 100 = risque maximal**
- Chaque règle a un **poids fixe** basé sur sa dangerosité réelle
- 5 catégories indépendantes, chacune notée de 0 à 100
- **Score global = maximum des catégories** — une seule faille critique suffit

| Exemple | Poids |
|---------|-------|
| WDigest activé (mots de passe en clair) | 100 |
| UAC désactivé | 100 |
| SeDebugPrivilege étendu | 100 |
| NTLMv1 autorisé | 100 |
| Defender désactivé | 100 |
| SMBv1 activé | 70 |
| NLA RDP absent | 80 |
| Pare-feu désactivé | 40 |
| AutoRun actif | 20 |

Seuls les **findings confirmés** (valeur dangereuse explicite) impactent le score. Les recommandations (paramètre absent) n'entrent pas dans le calcul.

---

## 🔎 Règles d'audit

### Mots de passe & Authentification

| ID | Contrôle | Référence |
|----|----------|-----------|
| PWD-001 | Longueur minimale < 14 | CIS 1.1.1 · ANSSI R-03 · MS Baseline |
| PWD-002 | Historique < 24 | CIS 1.1.2 · ANSSI R-03 |
| PWD-003 | Complexité désactivée | CIS 1.1.5 · ANSSI R-03 |
| PWD-004 | Expiration illimitée ou > 365 j | CIS 1.1.3 |
| PWD-006 | Durée minimale = 0 (contourne l'historique) | CIS 1.1.4 |
| AUTH-001 | Hash LM stocké | CIS 2.3.11.2 · ANSSI R-05 |
| AUTH-002 | NTLMv1 autorisé (LmCompatibilityLevel < 5) | CIS 2.3.11.7 · ANSSI R-06 |
| AUTH-003 | Verrouillage désactivé ou > 10 tentatives | CIS 1.2.1 · ANSSI R-04 |
| AUTH-004 | Durée verrouillage < 15 min | CIS 1.2.2 |

### Système & Registre

| ID | Contrôle | Référence |
|----|----------|-----------|
| SYS-001 | WDigest activé | KB2871997 · ANSSI R-08 |
| SYS-002 | SMBv1 non désactivé | MS ADV170012 · ANSSI R-07 |
| SYS-003 | Pare-feu désactivé | CIS 9.1.1 · ANSSI R-11 |
| SYS-004 | AutoRun non désactivé | CIS 18.9.8.1 · ANSSI R-14 |
| UAC-001 | UAC désactivé | CIS 2.3.17.1 · ANSSI R-38 |
| UAC-002 | Admins sans demande UAC | CIS 2.3.17.2 |
| UAC-004 | LocalAccountTokenFilterPolicy = 1 (Pass-the-Hash) | MS KB951016 · CIS 18.3.1 |
| PRINT-001 | Drivers imprimantes non restreints (PrintNightmare) | CVE-2021-34527 |
| LSA-001 | RunAsPPL non activé (Mimikatz) | MS KB3033929 |
| RDP-001 | NLA non requis | CVE-2019-0708 · CIS 18.9.65.3 |
| PS-001 | Script Block Logging désactivé | CIS 18.9.100.1 |

### Préférences Registre (Registry.xml)

| ID | Contrôle | Poids |
|----|----------|-------|
| REGXML-001 | Partages admin activés (Pass-the-Hash) | 100 |
| REGXML-002 | Token plein comptes locaux réseau | 80 |
| REGXML-003 | UAC désactivé via préférences | 100 |
| REGXML-004 | WDigest activé via préférences | 100 |
| REGXML-005 | SMBv1 activé via préférences | 70 |
| REGXML-006 | Pare-feu profil domaine désactivé | 40 |
| REGXML-007 | ScriptBlock Logging désactivé | 30 |
| REGXML-008 | Pare-feu profil standard/privé désactivé | 100 |
| REGXML-009 | Windows Defender désactivé | 100 |
| REGXML-010 | Protection temps réel Defender désactivée | 100 |
| REGXML-011 | Surveillance comportementale Defender désactivée | 60 |
| REGXML-012 | NLA RDP désactivé via préférences | 80 |
| REGXML-013 | Chiffrement RDP insuffisant | 30 |

### Droits utilisateurs (Privilege Rights)

| ID | Contrôle | Poids |
|----|----------|-------|
| PRIV-R001 | SeDebugPrivilege étendu (Mimikatz) | 100 |
| PRIV-R002 | SeTcbPrivilege accordé (Act as OS) | 100 |
| PRIV-R003 | SeTakeOwnershipPrivilege étendu | 40 |
| PRIV-R004 | SeBackupPrivilege étendu | 35 |
| PRIV-R005 | SeLoadDriverPrivilege étendu (driver Ring 0) | 100 |

Les SIDs sont automatiquement résolus en noms lisibles (`*S-1-5-32-544` → `Administrateurs`).

---

## 🗂️ Gouvernance GPO

### Détection des GPO fourre-tout

Une GPO est signalée fourre-tout si elle cumule l'un de ces critères :
- ≥ 3 catégories fonctionnelles différentes (audit + mots de passe + scripts + imprimantes…)
- ≥ 30 paramètres au total
- Configuration ordinateur **et** utilisateur mélangées avec ≥ 2 catégories

Un badge `📦 fourre-tout` apparaît sur chaque GPO concernée dans la liste et l'arbre OU.

### Détection des GPO par défaut modifiées

`Default Domain Policy` et `Default Domain Controllers Policy` ne doivent contenir que leurs paramètres d'origine. Si des scripts, imprimantes, clés de registre ou tâches planifiées y ont été ajoutés, GPOctopus affiche une alerte avec un **plan de migration concret** :

- Quel contenu déplacer
- Dans quelle nouvelle GPO (nom suggéré)
- Où lier cette GPO (OU cible)
- Liste des paramètres détectés
- Procédure pas à pas en 6 étapes

### Détection des conflits et contradictions

Pour chaque conflit (même paramètre, valeurs différentes dans plusieurs GPO) :
- **GPO gagnante** identifiée (priorité OU la plus profonde ou ENFORCED)
- **GPO perdantes** listées avec leurs valeurs écrasées
- **Contradiction sécurité** détectée : si une GPO sécurise et une autre contredit (ex : NTLMv2=5 vs NTLMv1=3), alerte rouge avec explication du danger

---

## ⚙️ Fonctionnement technique

### RSOP — ordre de priorité Windows

GPOctopus reconstruit le RSOP dans l'ordre de priorité Windows réel :

1. GPO domaine (profondeur 0) — priorité la plus basse
2. GPO OU parente → OU enfant (profondeur croissante)
3. GPO ENFORCED — priorité maximale, toujours gagnante
4. Les **liens désactivés** sont exclus du RSOP
5. Les **GPO entièrement désactivées** (flags = 3) sont ignorées

### Paging LDAP

La collecte LDAP utilise le paging (500 entrées/page) pour récupérer tous les objets sans limite, même sur les domaines avec des centaines de GPO. Fallback automatique sans paging si le DC ne le supporte pas.

### Décodage ADMX

Les clés `Registry.pol` brutes sont traduites en paramètres lisibles grâce à une table de 80+ correspondances couvrant : Windows Update/WSUS, PowerShell, RDP/Terminal Services, Pare-feu, Internet Explorer/Edge, Proxy, Defender, AppLocker, BitLocker, LAPS, TLS/SSL, Audit, Impression/PrintNightmare, SMB, NTLM, WDigest, UAC, Restrictions utilisateur.

---

## ⚠️ Avertissement légal

Ce script est destiné à des **audits de sécurité autorisés**. Toute utilisation sur des systèmes sans autorisation explicite est illégale. L'auteur décline toute responsabilité en cas d'utilisation malveillante.

---

## 📄 Licence

MIT — voir [LICENSE](LICENSE)
