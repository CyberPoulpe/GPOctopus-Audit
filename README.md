# 🐙 GPOctopus

> **Audit de sécurité automatisé et analyse poussée des GPO Active Directory.**  
> Collecte LDAP, analyse SYSVOL complète via SMB et génération d'un rapport HTML interactif et autonome.

![License](https://img.shields.io/github/license/CyberPoulpe/GPOctopus-Audit?style=flat-square)
![Language](https://img.shields.io/github/languages/top/CyberPoulpe/GPOctopus-Audit?style=flat-square)
![Stars](https://img.shields.io/github/stars/CyberPoulpe/GPOctopus-Audit?style=flat-square)

---

## 🎯 Aperçu & Objectif

**GPOctopus** se connecte à votre infrastructure Active Directory pour extraire, analyser et croiser la totalité de vos stratégies de groupe (LDAP + SYSVOL). Il reconstruit le **RSOP (Resultant Set of Policy)** réel appliqué aux machines et utilisateurs, puis évalue votre niveau de sécurité par rapport aux référentiels de marché (**CIS Benchmarks**, **ANSSI**, **Microsoft Security Baseline**).

L'outil permet de lever immédiatement le voile sur :
- Les configurations dangereuses (WDigest, NTLMv1, UAC désactivé, etc.).
- Les conflits de GPO (paramètres appliqués puis écrasés).
- Les GPO « fourre-tout » et les altérations des politiques par défaut (`Default Domain Policy`).

---

## ✨ Fonctionnalités clés

### 🔍 Collecte & Décodage
- **Paging LDAP** : Analyse sans restriction, peu importe le nombre de GPO.
- **Accès SYSVOL via SMB direct** : Basé sur `impacket` (aucun montage OS / `mount.cifs` requis).
- **Décodage ADMX étendu** : +80 clés de registre traduites en paramètres lisibles (WSUS, LAPS, BitLocker, PrintNightmare, RDP...).
- **Résolution automatique** : Prise en compte des filtres WMI, du *Security Filtering*, des politiques de mots de passe fines (PSO) et résolution des SIDs.

### 🛡️ Analyse & Scoring Cyber
- **Calcul du RSOP récursif** : Respect strict de la hiérarchie Windows (Profondeur d'OU, liens désactivés, option *ENFORCED*).
- **Score de risque (Style PingCastle)** : Note globale de 0 à 100 basée sur la catégorie la plus critique.
- **Différenciation stricte** : Séparation nette entre les **problèmes confirmés** (impactant le score) et les simples **recommandations**.
- **62 règles d'audit intégrées** : Mots de passe, privilèges (`Privilege Rights`), fichiers `.xml` (drives, tâches planifiées, services...), `GptTmpl.inf`, `Registry.pol`, etc.

### 📊 Gouvernance & Hygiène AD
- **Détection des conflits & contradictions** : Identification explicite des GPO gagnantes/perdantes et des incohérences de sécurité.
- **Alerte GPO fourre-tout** : Identification des stratégies accumulant trop de catégories ou de paramètres.
- **Alerte Default Policies** : Plan de migration pas à pas généré si la *Default Domain Policy* a été altérée.

---

## 📂 Contenu SYSVOL Analysé

GPOctopus inspecte l'ensemble des conteneurs et fichiers de configuration SYSVOL :

| Fichier SYSVOL | Périmètre d'analyse |
| :--- | :--- |
| `GptTmpl.inf` | Mots de passe, droits utilisateurs, options de sécurité, Kerberos |
| `Registry.pol` / `Registry.xml` | Paramètres ADMX et préférences registre (Machine & Utilisateur) |
| `ScheduledTasks.xml` / `Services.xml` | Tâches planifiées et état des services Windows |
| `scripts.ini` / `psscripts.ini` | Scripts au démarrage, extinction, ouverture et fermeture de session |
| `Printers.xml` / `Drives.xml` / `Shares.xml` | Imprimantes, lecteurs réseau et partages réseau |
| `Groups.xml` / `Files.xml` / `Folders.xml` | Groupes locaux, manipulation de fichiers et dossiers |
| `audit.csv` | Stratégies d'audit avancé |

---

## 🚀 Installation & Prérequis

### Prérequis
- **OS** : Linux, macOS ou Windows (WSL)
- **Python** : $\ge$ 3.10
- **Réseau** : Accès aux ports `389` (LDAP) et `445` (SMB/SYSVOL) du DC
- **Compte AD** : Un simple compte utilisateur de domaine (`Domain Users`) en lecture seule suffit.

### Installation

```bash
# Cloner le dépôt
git clone [https://github.com/CyberPoulpe/GPOctopus-Audit.git](https://github.com/CyberPoulpe/GPOctopus-Audit.git)
cd GPOctopus-Audit

# Installer les dépendances Python
pip3 install ldap3 jinja2 impacket pycryptodome --break-system-packages
```
*(Remarque : Les dépendances manquantes sont également vérifiées et installées automatiquement au premier lancement).*

---

## 💡 Utilisation

### Mode 1 : Wizard Interactif (Recommandé)

Guidage pas à pas avec test de connectivité et sauvegarde de la configuration dans `gpoctopus.conf` :

```bash
python3 gpoctopus.py
```

### Mode 2 : Ligne de commande (CLI)

```bash
# Exécution directe avec connexion SMB interne
python3 gpoctopus.py \
  --dc 192.168.1.10 \
  --domain corp.local \
  --user auditeur \
  --password 'P@ssword123!' \
  -o rapport_gpo.html
```

```bash
# Alternative : Utilisation avec un point de montage SYSVOL existant
python3 gpoctopus.py \
  --dc DC01 \
  --domain corp.local \
  --user auditeur \
  --password 'P@ssword123!' \
  --sysvol /mnt/sysvol \
  -o rapport_gpo.html
```

---

## 📊 Structure du Rapport HTML

Le rapport généré est **100% autonome** (aucun serveur web externe requis). Il intègre un chargement différé des données JSON pour garantir la fluidité sur les grands domaines.

* ** Onglet Sécurité** : Vue d'ensemble du score, paramètres critiques/alertes, recommandations, contrôles conformes et conflits de GPO.
* ** Onglet Diagnostic** : Moteur de recherche global avec synonymes, annuaire filtrable de toutes les GPO et timeline des modifications (7j, 30j, 90j, 1 an).
* ** Onglet Inventaire** : Arbre AD hiérarchique par OU respectant la priorité des GPO, et regroupement par types de contenu.
* ** Panneau Overlay** : Fiche détaillée glissante au clic sur n'importe quelle GPO (filtres, règles appliquées, liaisons).

---

## 🛡️ Sécurité & Avertissement

Cet outil est fourni à des fins d'audit de sécurité, d'évaluation d'hygiène AD et de défense réseau (*Blue Team*). L'utilisateur est seul responsable de son utilisation conformément aux lois et réglementations en vigueur. Ne jamais exécuter d'audit sans autorisation explicite du propriétaire du système.

---

## 📄 Licence & Contact

- **Licence :** MIT — voir [LICENSE](LICENSE)
- **Auteur :** CyberPoulpe
- **GitHub :** [@CyberPoulpe](https://github.com/CyberPoulpe)
