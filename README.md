# AD Arsenal — Active Directory Enumerator

```
  █████╗ ██████╗      █████╗ ██████╗ ███████╗███████╗███╗   ██╗ █████╗ ██╗
 ██╔══██╗██╔══██╗    ██╔══██╗██╔══██╗██╔════╝██╔════╝████╗  ██║██╔══██╗██║
 ███████║██║  ██║    ███████║██████╔╝███████╗█████╗  ██╔██╗ ██║███████║██║
 ██╔══██║██║  ██║    ██╔══██║██╔══██╗╚════██║██╔══╝  ██║╚██╗██║██╔══██║██║
 ██║  ██║██████╔╝    ██║  ██║██║  ██║███████║███████╗██║ ╚████║██║  ██║███████╗
 ╚═╝  ╚═╝╚═════╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝
```

> Script d'énumération Active Directory via SMB · MSRPC · LDAP  

---

## Fonctionnalités

| Module | Techniques | Description |
|--------|-----------|-------------|
| **SMB** | SMBv1/v2/v3 | Partages, sessions actives |
| **SAMR** | MSRPC | Utilisateurs, groupes, RIDs |
| **LSARPC** | MSRPC | SIDs, politiques de sécurité |
| **LDAP** | LDAP/LDAPS | Utilisateurs, groupes, GPOs |
| **Kerberoasting** | Kerberos | Comptes avec SPN |
| **AS-REP Roasting** | Kerberos | Comptes sans pré-auth |
| **ACLs** | LDAP | Droits dangereux (adminCount) |
| **GPOs** | LDAP | Group Policy Objects |
| **Domain Admins** | LDAP | Membres du groupe DA |
| **Password Policy** | LDAP | Politique de mots de passe |

---

## Installation

```bash
git clone https://github.com/<username>/ad-arsenal.git
cd ad-arsenal
pip install -r requirements.txt
```

**requirements.txt**
```
impacket
ldap3
colorama
```

---

## Utilisation

```bash
# Authentification classique
python3 ad_enum.py -t 192.168.10.1 -d corp.local -u admin -p 'P@ss123'

# Pass-the-Hash (NTLM)
python3 ad_enum.py -t 192.168.10.1 -d corp.local -u admin -H aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Session nulle (sans credentials)
python3 ad_enum.py -t 192.168.10.1 -d corp.local --null-session

# SMB uniquement
python3 ad_enum.py -t 192.168.10.1 -d corp.local -u admin -p 'P@ss123' --smb-only

# LDAP uniquement
python3 ad_enum.py -t 192.168.10.1 -d corp.local -u admin -p 'P@ss123' --ldap-only

# Exporter les résultats en JSON
python3 ad_enum.py -t 192.168.10.1 -d corp.local -u admin -p 'P@ss123' --output results.json
```

---

## Options

```
  -t, --target        IP du contrôleur de domaine
  -d, --domain        Nom du domaine (ex: corp.local)
  -u, --user          Nom d'utilisateur
  -p, --password      Mot de passe
  -H, --hashes        Hashes NTLM (LM:NT)
  --null-session      Session nulle (sans credentials)
  --smb-only          Enumération SMB/MSRPC uniquement
  --ldap-only         Enumération LDAP uniquement
  --output            Fichier de sortie JSON
  -v, --verbose       Mode verbose
```

---

## Exemple de sortie

```
════════════════════════════════════════════════════════════
  UTILISATEURS — LDAP
════════════════════════════════════════════════════════════

[+] [ACTIVE] Administrator           [ADMIN]
[+] [ACTIVE] john.doe
[+] [ACTIVE] svc_sql                 [AS-REP ROASTABLE] [ADMIN]
[CRITICAL] svc_backup               SPN: MSSQLSvc/dc01.corp.local:1433

════════════════════════════════════════════════════════════
  RÉSUMÉ DE L'ÉNUMÉRATION
════════════════════════════════════════════════════════════

  Statistiques :
  ├── Utilisateurs         : 24
  ├── Groupes              : 12
  ├── Machines             : 8
  ├── Contrôleurs domaine  : 1
  ├── Domain Admins        : 3
  ├── GPOs                 : 5
  ├── Kerberoastable       : 2
  └── AS-REP Roastable     : 1
```
# PrivEsc Scanner — Linux Privilege Escalation Enumerator

```
 ██████╗ ██████╗ ██╗██╗   ██╗███████╗███████╗ ██████╗
 ██╔══██╗██╔══██╗██║██║   ██║██╔════╝██╔════╝██╔════╝
 ██████╔╝██████╔╝██║██║   ██║█████╗  ███████╗██║
 ██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝██╔══╝  ╚════██║██║
 ██║     ██║  ██║██║ ╚████╔╝ ███████╗███████║╚██████╗
 ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝╚══════╝ ╚═════╝
```

> Script d'énumération automatisée des vecteurs d'escalade de privilèges Linux  
> Génère un rapport HTML interactif et un rapport JSON  

---

## Modules d'énumération

| Module | Description | Techniques |
|--------|-------------|-----------|
| **System Info** | Kernel, OS, user, architecture | Kernel CVE detection |
| **Sudo** | Permissions sudo, version | GTFOBins, LD_PRELOAD, CVE-2021-3156, CVE-2019-14287 |
| **SUID/SGID** | Binaires avec bit SUID | GTFOBins SUID |
| **Capabilities** | Linux capabilities dangereuses | cap_setuid, cap_dac_read_search, cap_sys_admin |
| **Cron Jobs** | Tâches planifiées éditables | Cron Hijacking, Script Creation |
| **PATH** | Répertoires inscriptibles dans PATH | PATH Hijacking |
| **Writable Files** | Fichiers sensibles inscriptibles | Passwd/Shadow manipulation, SSH keys |
| **Network** | Services internes, Docker socket | Port forwarding, Docker escape |

---

## Installation & Utilisation

```bash
git clone https://github.com/<username>/privesc-scanner.git
cd privesc-scanner

# Lancer le scan (aucune dépendance externe)
python3 privesc_scanner.py

# Spécifier un chemin de sortie pour le rapport HTML
python3 privesc_scanner.py --output /tmp/mon_rapport.html

# JSON uniquement
python3 privesc_scanner.py --json-only
```

---

## Exemple de sortie terminal

```
════════════════════════════════════════════════════════
  2. SUDO PERMISSIONS
════════════════════════════════════════════════════════

  [!!!] [SUDO/GTFOBins] NOPASSWD sudo on 'find' → GTFOBins shell escalation
        ↳ CMD: sudo find . -exec /bin/bash \; -quit
        ↳ GTFOBins: https://gtfobins.github.io/gtfobins/find/#sudo

  [!!!] [SUDO/CVE] Sudo 1.8.21 vulnerable to CVE-2021-3156 (Baron Samedit)
        ↳ CMD: git clone https://github.com/blasty/CVE-2021-3156 ...

════════════════════════════════════════════════════════
  SCAN SUMMARY
════════════════════════════════════════════════════════

  Total findings : 12
  Critical       : 4
  High           : 5

  ⚡ Top exploit vectors:
    • [SUDO/GTFOBins] NOPASSWD sudo on 'find'
    • [SUID] SUID binary: /usr/bin/python3
    • [CAPABILITIES] /usr/bin/python3 has cap_setuid
```

---

## Rapport HTML

Le rapport HTML généré inclut :
- **Dashboard** avec compteurs par sévérité
- **Cartes filtrables** : Critical / High / Medium / Info
- **Commandes d'exploitation** directement copiables
- **Liens GTFOBins** pour chaque vecteur
- **Informations système** complètes

---

## Structure du projet

```
privesc-scanner/
├── privesc_scanner.py    # Script principal
├── README.md             # Documentation
└── samples/
    ├── report.html       # Exemple rapport HTML
    └── report.json       # Exemple rapport JSON
```

---

## CVE couverts

| CVE | Description | Condition |
|-----|-------------|-----------|
| CVE-2021-3156 | Baron Samedit — sudo heap overflow | sudo < 1.9.5p2 |
| CVE-2021-4034 | PwnKit — pkexec LPE | pkexec SUID |
| CVE-2019-14287 | Sudo user -1 bypass | sudo < 1.8.28 |
| CVE-2016-5195 | DirtyCow — kernel race condition | kernel 4.4 / 4.8 |

## Avertissement légal

> Ce script est développé **uniquement à des fins éducatives et de tests de sécurité autorisés**.  
> Toute utilisation sur un système sans autorisation explicite est **illégale**.  
> L'auteur décline toute responsabilité en cas d'utilisation abusive.

---

