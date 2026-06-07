#!/usr/bin/env python3

Usage:
    python3 ad_enum.py -t <DC_IP> -d <DOMAIN> -u <USER> -p <PASS>
    python3 ad_enum.py -t 192.168.10.1 -d corp.local -u admin -p 'P@ss123'
    python3 ad_enum.py -t 192.168.10.1 -d corp.local --null-session

Requirements:
    pip install impacket ldap3 colorama
"""

import argparse
import sys
import json
import datetime
from typing import Optional

# ── Impacket (SMB / MSRPC / RPC) ────────────────────────────────
try:
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, samr, lsat, lsad, epm
    from impacket.dcerpc.v5.rpcrt import DCERPCException
    from impacket.krb5.kerberosv5 import getKerberosTGT
    from impacket import nmb
except ImportError:
    print("[-] impacket non installé : pip install impacket")
    sys.exit(1)

# ── LDAP3 ────────────────────────────────────────────────────────
try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
    from ldap3.core.exceptions import LDAPException
except ImportError:
    print("[-] ldap3 non installé : pip install ldap3")
    sys.exit(1)

# ── Colorama (output coloré) ─────────────────────────────────────
try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
    RED    = Fore.RED
    GREEN  = Fore.GREEN
    YELLOW = Fore.YELLOW
    CYAN   = Fore.CYAN
    BLUE   = Fore.BLUE
    MAGENTA= Fore.MAGENTA
    WHITE  = Fore.WHITE
    RESET  = Style.RESET_ALL
    BOLD   = Style.BRIGHT
except ImportError:
    RED = GREEN = YELLOW = CYAN = BLUE = MAGENTA = WHITE = RESET = BOLD = ""


# ════════════════════════════════════════════════════════════════
#  BANNER
# ════════════════════════════════════════════════════════════════

def banner():
    print(f"""{RED}
  █████╗ ██████╗      █████╗ ██████╗ ███████╗███████╗███╗   ██╗ █████╗ ██╗
 ██╔══██╗██╔══██╗    ██╔══██╗██╔══██╗██╔════╝██╔════╝████╗  ██║██╔══██╗██║
 ███████║██║  ██║    ███████║██████╔╝███████╗█████╗  ██╔██╗ ██║███████║██║
 ██╔══██║██║  ██║    ██╔══██║██╔══██╗╚════██║██╔══╝  ██║╚██╗██║██╔══██║██║
 ██║  ██║██████╔╝    ██║  ██║██║  ██║███████║███████╗██║ ╚████║██║  ██║███████╗
 ╚═╝  ╚═╝╚═════╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝

    """)


# ════════════════════════════════════════════════════════════════
#  ARGUMENTS
# ════════════════════════════════════════════════════════════════

def parse_args():
    parser = argparse.ArgumentParser(
        description="AD Arsenal — Active Directory Enumerator",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-t", "--target",  required=True,  help="IP du contrôleur de domaine")
    parser.add_argument("-d", "--domain",  required=True,  help="Nom du domaine (ex: corp.local)")
    parser.add_argument("-u", "--user",    default="",     help="Nom d'utilisateur")
    parser.add_argument("-p", "--password",default="",     help="Mot de passe")
    parser.add_argument("-H", "--hashes",  default="",     help="Hashes NTLM (LM:NT)")
    parser.add_argument("--null-session",  action="store_true", help="Session nulle (sans credentials)")
    parser.add_argument("--kerberos",      action="store_true", help="Authentification Kerberos")
    parser.add_argument("--output",        default="",     help="Fichier de sortie JSON")
    parser.add_argument("--smb-only",      action="store_true", help="Enumération SMB uniquement")
    parser.add_argument("--ldap-only",     action="store_true", help="Enumération LDAP uniquement")
    parser.add_argument("-v", "--verbose", action="store_true", help="Mode verbose")
    return parser.parse_args()


# ════════════════════════════════════════════════════════════════
#  UTILITAIRES
# ════════════════════════════════════════════════════════════════

def log_info(msg):    print(f"{CYAN}[*]{RESET} {msg}")
def log_ok(msg):      print(f"{GREEN}[+]{RESET} {msg}")
def log_warn(msg):    print(f"{YELLOW}[!]{RESET} {msg}")
def log_error(msg):   print(f"{RED}[-]{RESET} {msg}")
def log_critical(msg):print(f"{RED}{BOLD}[CRITICAL]{RESET} {msg}")
def log_section(title):
    print(f"\n{BLUE}{BOLD}{'═'*60}{RESET}")
    print(f"{BLUE}{BOLD}  {title}{RESET}")
    print(f"{BLUE}{BOLD}{'═'*60}{RESET}\n")

def domain_to_dn(domain: str) -> str:
    """Convertit corp.local → DC=corp,DC=local"""
    return ",".join(f"DC={part}" for part in domain.split("."))


# ════════════════════════════════════════════════════════════════
#  MODULE SMB
# ════════════════════════════════════════════════════════════════

class SMBEnumerator:

    def __init__(self, target, domain, user, password, hashes, null_session):
        self.target       = target
        self.domain       = domain
        self.user         = user
        self.password     = password
        self.hashes       = hashes
        self.null_session = null_session
        self.smb          = None
        self.results      = {}

    def connect(self) -> bool:
        try:
            self.smb = SMBConnection(self.target, self.target, timeout=10)
            if self.null_session:
                self.smb.login("", "", "", "", "")
                log_ok(f"Connexion SMB — session nulle sur {self.target}")
            elif self.hashes:
                lm, nt = (self.hashes.split(":") + [""])[:2]
                self.smb.login(self.user, "", self.domain, lm, nt)
                log_ok(f"Connexion SMB — Pass-the-Hash : {self.domain}\\{self.user}")
            else:
                self.smb.login(self.user, self.password, self.domain)
                log_ok(f"Connexion SMB — {self.domain}\\{self.user}")
            return True
        except Exception as e:
            log_error(f"Connexion SMB échouée : {e}")
            return False

    def get_shares(self) -> list:
        log_section("PARTAGES SMB")
        shares = []
        try:
            for share in self.smb.listShares():
                name    = share["shi1_netname"][:-1]
                comment = share["shi1_remark"][:-1]
                shares.append({"name": name, "comment": comment})
                log_ok(f"  {YELLOW}{name:<20}{RESET} {comment}")
        except Exception as e:
            log_error(f"Erreur listShares : {e}")
        self.results["shares"] = shares
        return shares

    def get_sessions(self) -> list:
        log_section("SESSIONS ACTIVES — SMB")
        sessions = []
        try:
            rpctransport = transport.SMBTransport(
                self.target, 445, r"\srvsvc",
                self.user, self.password, self.domain
            )
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            from impacket.dcerpc.v5 import srvs
            dce.bind(srvs.MSRPC_UUID_SRVS)
            resp = srvs.hNetrSessionEnum(dce, "", None, 10)
            for session in resp["InfoStruct"]["SessionInfo"]["Level10"]["Buffer"]:
                user    = session["sesi10_username"][:-1]
                host    = session["sesi10_cname"][:-1]
                sessions.append({"user": user, "host": host})
                log_ok(f"  Utilisateur: {YELLOW}{user}{RESET} depuis {host}")
        except Exception as e:
            log_warn(f"Sessions SMB : {e}")
        self.results["sessions"] = sessions
        return sessions

    def enum_via_samr(self) -> dict:
        """Enumération utilisateurs/groupes via SAMR (MSRPC)"""
        log_section("ENUMÉRATION MSRPC — SAMR")
        results = {"users": [], "groups": [], "aliases": []}

        try:
            rpctransport = transport.SMBTransport(
                self.target, 445, r"\samr",
                self.user, self.password, self.domain
            )
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)

            resp      = samr.hSamrConnect(dce)
            serverHandle = resp["ServerHandle"]

            resp2     = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)
            domains   = resp2["Buffer"]["Buffer"]

            for domain_entry in domains:
                domain_name = domain_entry["Name"]
                log_info(f"Domaine SAMR : {YELLOW}{domain_name}{RESET}")

                resp3    = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domain_name)
                domainSid= resp3["DomainId"]

                resp4    = samr.hSamrOpenDomain(dce, serverHandle, domainId=domainSid)
                domainHandle = resp4["DomainHandle"]

                # ── Utilisateurs ──
                status   = True
                enumContext = 0
                log_info("Enumération des utilisateurs via SAMR...")
                while status:
                    try:
                        resp5 = samr.hSamrEnumerateUsersInDomain(
                            dce, domainHandle, enumerationContext=enumContext
                        )
                        for user_entry in resp5["Buffer"]["Buffer"]:
                            rid      = user_entry["RelativeId"]
                            username = user_entry["Name"]
                            results["users"].append({
                                "username": username,
                                "rid":      rid,
                                "domain":   domain_name
                            })
                            log_ok(f"  {GREEN}[USER]{RESET} {username:<30} RID: {rid}")
                        enumContext = resp5["EnumerationContext"]
                        if resp5["ErrorCode"] == 0:
                            status = False
                    except DCERPCException as e:
                        if "STATUS_MORE_ENTRIES" not in str(e):
                            status = False

                # ── Groupes ──
                status      = True
                enumContext = 0
                log_info("Enumération des groupes via SAMR...")
                while status:
                    try:
                        resp6 = samr.hSamrEnumerateGroupsInDomain(
                            dce, domainHandle, enumerationContext=enumContext
                        )
                        for group in resp6["Buffer"]["Buffer"]:
                            rid        = group["RelativeId"]
                            group_name = group["Name"]
                            results["groups"].append({
                                "name": group_name,
                                "rid":  rid,
                                "domain": domain_name
                            })
                            log_ok(f"  {BLUE}[GROUP]{RESET} {group_name:<30} RID: {rid}")
                        enumContext = resp6["EnumerationContext"]
                        if resp6["ErrorCode"] == 0:
                            status = False
                    except DCERPCException as e:
                        if "STATUS_MORE_ENTRIES" not in str(e):
                            status = False

        except Exception as e:
            log_error(f"Erreur SAMR : {e}")

        self.results["samr"] = results
        return results

    def enum_via_lsarpc(self) -> dict:
        """Enumération via LSARPC — SIDs, politiques"""
        log_section("ENUMÉRATION MSRPC — LSARPC")
        results = {"sids": [], "policy": {}}

        try:
            rpctransport = transport.SMBTransport(
                self.target, 445, r"\lsarpc",
                self.user, self.password, self.domain
            )
            dce = rpctransport.get_dce_rpc()
            dce.connect()
            dce.bind(lsat.MSRPC_UUID_LSAT)

            resp      = lsad.hLsarOpenPolicy2(dce, lsat.POLICY_LOOKUP_NAMES)
            policyHandle = resp["PolicyHandle"]

            # Informations domaine
            resp2     = lsad.hLsarQueryInformationPolicy2(
                dce, policyHandle, lsad.POLICY_INFORMATION_CLASS.PolicyPrimaryDomainInformation
            )
            domain_info = resp2["PolicyInformation"]["PolicyPrimaryDomainInfo"]
            domain_name = domain_info["Name"]
            domain_sid  = domain_info["Sid"].formatCanonical()
            results["policy"] = {"domain": domain_name, "sid": domain_sid}
            log_ok(f"  Domaine : {YELLOW}{domain_name}{RESET}")
            log_ok(f"  SID     : {YELLOW}{domain_sid}{RESET}")

        except Exception as e:
            log_error(f"Erreur LSARPC : {e}")

        self.results["lsarpc"] = results
        return results

    def run(self) -> dict:
        if not self.connect():
            return {}
        self.get_shares()
        self.get_sessions()
        self.enum_via_samr()
        self.enum_via_lsarpc()
        return self.results


# ════════════════════════════════════════════════════════════════
#  MODULE LDAP
# ════════════════════════════════════════════════════════════════

class LDAPEnumerator:

    def __init__(self, target, domain, user, password, hashes, null_session):
        self.target       = target
        self.domain       = domain
        self.user         = user
        self.password     = password
        self.hashes       = hashes
        self.null_session = null_session
        self.base_dn      = domain_to_dn(domain)
        self.conn         = None
        self.results      = {}

    def connect(self) -> bool:
        try:
            server = Server(self.target, port=389, get_info=ALL)

            if self.null_session:
                self.conn = Connection(server, authentication=ldap3.ANONYMOUS)
            elif self.hashes:
                nt = self.hashes.split(":")[-1] if ":" in self.hashes else self.hashes
                self.conn = Connection(
                    server,
                    user=f"{self.domain}\\{self.user}",
                    password=f"aad3b435b51404eeaad3b435b51404ee:{nt}",
                    authentication=NTLM
                )
            else:
                self.conn = Connection(
                    server,
                    user=f"{self.domain}\\{self.user}",
                    password=self.password,
                    authentication=NTLM
                )

            if self.conn.bind():
                log_ok(f"Connexion LDAP — {self.target}:389 — base: {self.base_dn}")
                return True
            else:
                log_error(f"Bind LDAP échoué : {self.conn.result}")
                return False
        except LDAPException as e:
            log_error(f"Connexion LDAP échouée : {e}")
            return False

    def search(self, search_filter: str, attributes: list) -> list:
        try:
            self.conn.search(
                self.base_dn,
                search_filter,
                search_scope=SUBTREE,
                attributes=attributes
            )
            return self.conn.entries
        except Exception as e:
            log_error(f"Erreur LDAP search : {e}")
            return []

    # ── Utilisateurs ─────────────────────────────────────────────

    def get_users(self) -> list:
        log_section("UTILISATEURS — LDAP")
        entries = self.search(
            "(objectCategory=person)",
            ["sAMAccountName", "displayName", "memberOf",
             "userAccountControl", "lastLogon", "pwdLastSet",
             "description", "adminCount", "mail"]
        )
        users = []
        for entry in entries:
            uac  = int(str(entry.userAccountControl)) if entry.userAccountControl else 0
            user = {
                "username":     str(entry.sAMAccountName),
                "displayName":  str(entry.displayName),
                "mail":         str(entry.mail),
                "description":  str(entry.description),
                "memberOf":     [str(g) for g in entry.memberOf] if entry.memberOf else [],
                "adminCount":   str(entry.adminCount),
                "disabled":     bool(uac & 0x2),
                "noExpiry":     bool(uac & 0x10000),
                "noPreauthReq": bool(uac & 0x400000),
            }
            users.append(user)
            status = f"{RED}[DISABLED]{RESET}" if user["disabled"] else f"{GREEN}[ACTIVE]{RESET}"
            asrep  = f" {YELLOW}[AS-REP ROASTABLE]{RESET}" if user["noPreauthReq"] else ""
            admin  = f" {RED}[ADMIN]{RESET}" if user["adminCount"] == "1" else ""
            log_ok(f"  {status} {user['username']:<25}{asrep}{admin}")

        self.results["users"] = users
        log_info(f"Total utilisateurs : {len(users)}")
        return users

    # ── Groupes ───────────────────────────────────────────────────

    def get_groups(self) -> list:
        log_section("GROUPES — LDAP")
        entries = self.search(
            "(objectCategory=group)",
            ["cn", "description", "member", "adminCount", "distinguishedName"]
        )
        groups = []
        for entry in entries:
            group = {
                "name":        str(entry.cn),
                "description": str(entry.description),
                "adminCount":  str(entry.adminCount),
                "dn":          str(entry.distinguishedName),
                "members":     [str(m) for m in entry.member] if entry.member else [],
            }
            groups.append(group)
            admin = f" {RED}[PRIVILEGED]{RESET}" if group["adminCount"] == "1" else ""
            log_ok(f"  {BLUE}[GROUP]{RESET} {group['name']:<35} membres: {len(group['members'])}{admin}")

        self.results["groups"] = groups
        log_info(f"Total groupes : {len(groups)}")
        return groups

    # ── Comptes Kerberoastable ────────────────────────────────────

    def get_kerberoastable(self) -> list:
        log_section("COMPTES KERBEROASTABLE — SPN")
        entries = self.search(
            "(&(objectCategory=person)(servicePrincipalName=*))",
            ["sAMAccountName", "servicePrincipalName",
             "memberOf", "adminCount", "pwdLastSet"]
        )
        accounts = []
        for entry in entries:
            acc = {
                "username":  str(entry.sAMAccountName),
                "spns":      [str(s) for s in entry.servicePrincipalName],
                "adminCount":str(entry.adminCount),
            }
            accounts.append(acc)
            log_critical(f"  {acc['username']:<30} SPN: {', '.join(acc['spns'])}")

        self.results["kerberoastable"] = accounts
        if not accounts:
            log_warn("Aucun compte Kerberoastable détecté")
        return accounts

    # ── Comptes AS-REP Roastable ──────────────────────────────────

    def get_asrep_roastable(self) -> list:
        log_section("COMPTES AS-REP ROASTABLE — DONT_REQ_PREAUTH")
        entries = self.search(
            "(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
            ["sAMAccountName", "memberOf", "adminCount"]
        )
        accounts = []
        for entry in entries:
            acc = {
                "username":  str(entry.sAMAccountName),
                "adminCount":str(entry.adminCount),
            }
            accounts.append(acc)
            log_critical(f"  {acc['username']:<30} [DONT_REQ_PREAUTH activé]")

        self.results["asrep_roastable"] = accounts
        if not accounts:
            log_warn("Aucun compte AS-REP Roastable détecté")
        return accounts

    # ── GPOs ──────────────────────────────────────────────────────

    def get_gpos(self) -> list:
        log_section("GROUP POLICY OBJECTS (GPOs)")
        entries = self.search(
            "(objectCategory=groupPolicyContainer)",
            ["displayName", "cn", "gPCFileSysPath",
             "versionNumber", "distinguishedName"]
        )
        gpos = []
        for entry in entries:
            gpo = {
                "name":    str(entry.displayName),
                "guid":    str(entry.cn),
                "path":    str(entry.gPCFileSysPath),
                "version": str(entry.versionNumber),
                "dn":      str(entry.distinguishedName),
            }
            gpos.append(gpo)
            log_ok(f"  {MAGENTA}[GPO]{RESET} {gpo['name']:<40} {gpo['guid']}")

        self.results["gpos"] = gpos
        log_info(f"Total GPOs : {len(gpos)}")
        return gpos

    # ── ACLs Intéressantes ────────────────────────────────────────

    def get_interesting_acls(self) -> list:
        log_section("ACLs INTÉRESSANTES — DROITS DANGEREUX")
        log_warn("Analyse des ACLs LDAP (GenericAll, WriteDACL, WriteOwner...)")

        dangerous_rights = [
            "GenericAll", "GenericWrite", "WriteDACL",
            "WriteOwner", "AllExtendedRights", "ForceChangePassword"
        ]

        entries = self.search(
            "(objectCategory=*)",
            ["nTSecurityDescriptor", "sAMAccountName",
             "distinguishedName", "objectCategory"]
        )

        acls = []
        log_warn("Vérification manuelle recommandée avec BloodHound pour les ACLs complètes")
        log_info("Recherche des objets avec adminSDHolder (adminCount=1)...")

        admin_objects = self.search(
            "(adminCount=1)",
            ["sAMAccountName", "distinguishedName", "objectCategory"]
        )

        for obj in admin_objects:
            acl = {
                "object":   str(obj.sAMAccountName),
                "dn":       str(obj.distinguishedName),
                "category": str(obj.objectCategory),
                "note":     "adminCount=1 — protégé par AdminSDHolder"
            }
            acls.append(acl)
            log_critical(f"  {acl['object']:<30} {acl['note']}")

        self.results["interesting_acls"] = acls
        return acls

    # ── Domain Admins ─────────────────────────────────────────────

    def get_domain_admins(self) -> list:
        log_section("MEMBRES — DOMAIN ADMINS")
        entries = self.search(
            "(&(objectCategory=group)(cn=Domain Admins))",
            ["member"]
        )
        admins = []
        for entry in entries:
            if entry.member:
                for member in entry.member:
                    dn_str = str(member)
                    cn     = dn_str.split(",")[0].replace("CN=", "")
                    admins.append(cn)
                    log_critical(f"  {RED}[DA]{RESET} {cn}")

        self.results["domain_admins"] = admins
        return admins

    # ── Politique de mots de passe ────────────────────────────────

    def get_password_policy(self) -> dict:
        log_section("POLITIQUE DE MOTS DE PASSE")
        entries = self.search(
            "(objectClass=domain)",
            ["minPwdLength", "lockoutThreshold",
             "maxPwdAge", "minPwdAge", "pwdHistoryLength",
             "lockoutDuration"]
        )
        policy = {}
        for entry in entries:
            policy = {
                "minPwdLength":     str(entry.minPwdLength),
                "lockoutThreshold": str(entry.lockoutThreshold),
                "pwdHistoryLength": str(entry.pwdHistoryLength),
            }
            log_ok(f"  Longueur minimale     : {YELLOW}{policy['minPwdLength']}{RESET}")
            log_ok(f"  Seuil de verrouillage : {YELLOW}{policy['lockoutThreshold']}{RESET}")
            log_ok(f"  Historique mdp        : {YELLOW}{policy['pwdHistoryLength']}{RESET}")
            if int(policy["lockoutThreshold"]) == 0:
                log_warn("  Aucun verrouillage de compte — brute force possible !")

        self.results["password_policy"] = policy
        return policy

    # ── Contrôleurs de domaine ────────────────────────────────────

    def get_domain_controllers(self) -> list:
        log_section("CONTRÔLEURS DE DOMAINE")
        entries = self.search(
            "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            ["cn", "dNSHostName", "operatingSystem",
             "operatingSystemVersion", "lastLogon"]
        )
        dcs = []
        for entry in entries:
            dc = {
                "name":    str(entry.cn),
                "dns":     str(entry.dNSHostName),
                "os":      str(entry.operatingSystem),
                "version": str(entry.operatingSystemVersion),
            }
            dcs.append(dc)
            log_ok(f"  {RED}[DC]{RESET} {dc['name']:<20} {dc['os']} {dc['version']}")

        self.results["domain_controllers"] = dcs
        return dcs

    # ── Computers ─────────────────────────────────────────────────

    def get_computers(self) -> list:
        log_section("MACHINES DU DOMAINE")
        entries = self.search(
            "(objectCategory=computer)",
            ["cn", "dNSHostName", "operatingSystem",
             "operatingSystemVersion", "lastLogon",
             "userAccountControl"]
        )
        computers = []
        for entry in entries:
            uac  = int(str(entry.userAccountControl)) if entry.userAccountControl else 0
            comp = {
                "name":     str(entry.cn),
                "dns":      str(entry.dNSHostName),
                "os":       str(entry.operatingSystem),
                "version":  str(entry.operatingSystemVersion),
                "disabled": bool(uac & 0x2),
            }
            computers.append(comp)
            status = f"{RED}[OFF]{RESET}" if comp["disabled"] else f"{GREEN}[ON]{RESET}"
            log_ok(f"  {status} {comp['name']:<25} {comp['os']}")

        self.results["computers"] = computers
        log_info(f"Total machines : {len(computers)}")
        return computers

    def run(self) -> dict:
        if not self.connect():
            return {}
        self.get_domain_controllers()
        self.get_password_policy()
        self.get_domain_admins()
        self.get_users()
        self.get_groups()
        self.get_computers()
        self.get_kerberoastable()
        self.get_asrep_roastable()
        self.get_gpos()
        self.get_interesting_acls()
        return self.results


# ════════════════════════════════════════════════════════════════
#  RAPPORT FINAL
# ════════════════════════════════════════════════════════════════

def print_summary(smb_results: dict, ldap_results: dict):
    log_section("RÉSUMÉ DE L'ÉNUMÉRATION")

    users      = ldap_results.get("users", [])
    groups     = ldap_results.get("groups", [])
    computers  = ldap_results.get("computers", [])
    kerberoast = ldap_results.get("kerberoastable", [])
    asrep      = ldap_results.get("asrep_roastable", [])
    gpos       = ldap_results.get("gpos", [])
    dcs        = ldap_results.get("domain_controllers", [])
    admins     = ldap_results.get("domain_admins", [])
    acls       = ldap_results.get("interesting_acls", [])
    shares     = smb_results.get("shares", [])

    print(f"""
  {BOLD}Statistiques :{RESET}
  ├── {GREEN}Utilisateurs         :{RESET} {len(users)}
  ├── {GREEN}Groupes              :{RESET} {len(groups)}
  ├── {GREEN}Machines             :{RESET} {len(computers)}
  ├── {GREEN}Contrôleurs domaine  :{RESET} {len(dcs)}
  ├── {GREEN}Domain Admins        :{RESET} {len(admins)}
  ├── {GREEN}GPOs                 :{RESET} {len(gpos)}
  ├── {GREEN}Partages SMB         :{RESET} {len(shares)}
  ├── {YELLOW}ACLs intéressantes   :{RESET} {len(acls)}
  ├── {RED}Kerberoastable       :{RESET} {len(kerberoast)}
  └── {RED}AS-REP Roastable     :{RESET} {len(asrep)}
    """)

    if kerberoast:
        print(f"  {RED}{BOLD}[CRITIQUE] Comptes Kerberoastable détectés :{RESET}")
        for acc in kerberoast:
            print(f"    → {acc['username']}")

    if asrep:
        print(f"  {RED}{BOLD}[CRITIQUE] Comptes AS-REP Roastable détectés :{RESET}")
        for acc in asrep:
            print(f"    → {acc['username']}")


def save_results(smb_results: dict, ldap_results: dict, output_file: str):
    report = {
        "timestamp": datetime.datetime.now().isoformat(),
        "smb":       smb_results,
        "ldap":      ldap_results,
    }
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=str)
    log_ok(f"Rapport sauvegardé : {output_file}")


# ════════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════════

def main():
    banner()
    args = parse_args()

    log_info(f"Cible      : {YELLOW}{args.target}{RESET}")
    log_info(f"Domaine    : {YELLOW}{args.domain}{RESET}")
    log_info(f"Utilisateur: {YELLOW}{args.user if args.user else 'NULL SESSION'}{RESET}")
    log_info(f"Base DN    : {YELLOW}{domain_to_dn(args.domain)}{RESET}")

    smb_results  = {}
    ldap_results = {}

    # ── SMB + MSRPC ──────────────────────────────────────────────
    if not args.ldap_only:
        smb = SMBEnumerator(
            args.target, args.domain,
            args.user, args.password,
            args.hashes, args.null_session
        )
        smb_results = smb.run()

    # ── LDAP ─────────────────────────────────────────────────────
    if not args.smb_only:
        ldap = LDAPEnumerator(
            args.target, args.domain,
            args.user, args.password,
            args.hashes, args.null_session
        )
        ldap_results = ldap.run()

    # ── Résumé ───────────────────────────────────────────────────
    print_summary(smb_results, ldap_results)

    # ── Export JSON ──────────────────────────────────────────────
    if args.output:
        save_results(smb_results, ldap_results, args.output)
    else:
        default_output = f"ad_enum_{args.target}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        save_results(smb_results, ldap_results, default_output)


if __name__ == "__main__":
    main()
