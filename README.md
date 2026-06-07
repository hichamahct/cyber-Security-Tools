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
> Développé dans le cadre du PFE Red Team — 3D Smart Factory 2025/2026

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

---

## Structure du projet

```
ad-arsenal/
├── ad_enum.py          # Script principal
├── requirements.txt    # Dépendances Python
├── README.md           # Documentation
└── samples/
    └── output.json     # Exemple de rapport JSON
```

---

## Avertissement légal

> Ce script est développé **uniquement à des fins éducatives et de tests de sécurité autorisés**.  
> Toute utilisation sur un système sans autorisation explicite est **illégale**.  
> L'auteur décline toute responsabilité en cas d'utilisation abusive.

---

## Auteur

**Ahcynat Hicham** — Projet de Fin d'Études  
École Nationale Supérieure des Mines de Rabat (ENSMR)  
Option : Ingénierie des Données (IDATA)  
Organisme : 3D Smart Factory — 2025/2026
