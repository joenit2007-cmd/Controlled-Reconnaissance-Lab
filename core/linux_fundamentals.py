"""
Linux Fundamentals module for Controlled Reconnaissance Lab.
Provides structured educational content, interactive permissions calculator,
safe Linux command execution simulator, and knowledge assessments.
"""
from typing import Dict, Any, List

LINUX_MODULES = [
    {
        "id": "files_dirs",
        "title": "1. Files & Directory Structure (FHS)",
        "badge": "Filesystem Hierarchy Standard",
        "summary": "Master the Linux directory layout and critical security-sensitive system paths.",
        "content": [
            {
                "section": "Critical Linux Paths",
                "points": [
                    {"path": "/etc", "desc": "Host-specific system-wide configuration files (e.g. /etc/passwd, /etc/shadow, /etc/ssh/sshd_config)."},
                    {"path": "/var/log", "desc": "System log files (auth.log, syslog, messages, nginx/apache access logs) vital for intrusion detection."},
                    {"path": "/proc", "desc": "Virtual pseudo-filesystem representing live kernel status and running process memory (e.g. /proc/cpuinfo, /proc/version, /proc/[PID]/cmdline)."},
                    {"path": "/dev", "desc": "Device files mapped to hardware (/dev/null, /dev/sda, /dev/urandom)."},
                    {"path": "/tmp & /var/tmp", "desc": "Temporary directories world-writable by default. Frequently targeted for staging recon tools and privilege escalation scripts."}
                ]
            },
            {
                "section": "Core Navigation & Search Commands",
                "commands": [
                    {"cmd": "ls -la /etc", "desc": "List all files including hidden dotfiles with permissions, owners, and modification timestamps."},
                    {"cmd": "find / -perm -4000 -type f 2>/dev/null", "desc": "Search entire filesystem for binaries with SUID bit set (critical privilege escalation recon)."},
                    {"cmd": "grep -rnwi '/var/log/' -e 'failed'", "desc": "Recursively search logs for authentication failures or error signatures."},
                    {"cmd": "file /bin/ls", "desc": "Determine true file type and ELF architecture independent of file extension."}
                ]
            }
        ]
    },
    {
        "id": "permissions",
        "title": "2. Linux File Permissions & Special Bits",
        "badge": "Access Controls",
        "summary": "Understand discretionary access controls (DAC), octal notation, and dangerous privilege bits.",
        "content": [
            {
                "section": "Permission Triads",
                "points": [
                    {"type": "Read (r = 4)", "desc": "View file contents or list directory entries."},
                    {"type": "Write (w = 2)", "desc": "Modify or truncate file contents; add or remove entries inside directory."},
                    {"type": "Execute (x = 1)", "desc": "Run file as program or script; traverse/cd into directory."}
                ]
            },
            {
                "section": "Special Privilege Bits",
                "points": [
                    {"bit": "SUID (Set Owner UID = 4000)", "desc": "Executes binary with owner permissions (commonly root). Example: /usr/bin/passwd. If misconfigured on scripts or utilities like find/vim, leads to root takeover."},
                    {"bit": "SGID (Set Group ID = 2000)", "desc": "Executes with group permissions or ensures files created inherit parent directory's group."},
                    {"bit": "Sticky Bit (1000)", "desc": "Indicated by 't' (e.g. /tmp drwxrwxrwt). Only file owner or root can delete files inside."}
                ]
            }
        ]
    },
    {
        "id": "users_groups",
        "title": "3. Users, Groups & Authentication",
        "badge": "Identity Management",
        "summary": "Examine account storage, password hash protections, and sudo privileges.",
        "content": [
            {
                "section": "Authentication Files",
                "points": [
                    {"file": "/etc/passwd", "desc": "World-readable user account database: username:x:UID:GID:gecos:home_dir:shell. UID 0 indicates root privileges."},
                    {"file": "/etc/shadow", "desc": "Restricted file (0640 or 0600 root:shadow) containing salt and hashed passwords (e.g., $6$ = SHA-512, $y$ = yescrypt)."},
                    {"file": "/etc/group", "desc": "Defines group memberships, such as sudo, wheel, docker, and adm."},
                    {"file": "/etc/sudoers", "desc": "Configures granular sudo rules; editable safely via 'visudo'. Look out for 'NOPASSWD: ALL'."}
                ]
            },
            {
                "section": "Identity Commands",
                "commands": [
                    {"cmd": "id", "desc": "Display current user UID, primary GID, and supplemental group memberships."},
                    {"cmd": "sudo -l", "desc": "List privileges allowed and forbidden for current user via sudoers configuration."},
                    {"cmd": "who -a / w", "desc": "Check currently logged-in interactive users and active terminal TTYs."}
                ]
            }
        ]
    },
    {
        "id": "processes",
        "title": "4. Processes & Service Control",
        "badge": "System Operations",
        "summary": "Inspect active workloads, identify rogue processes, and master process signaling.",
        "content": [
            {
                "section": "Process Identification",
                "commands": [
                    {"cmd": "ps aux", "desc": "Display all running processes across all users (BSD style). Shows USER, PID, %CPU, %MEM, and COMMAND line."},
                    {"cmd": "top / htop", "desc": "Real-time interactive process viewer showing memory and CPU usage."},
                    {"cmd": "systemctl list-units --type=service --state=running", "desc": "List all active background systemd daemon services."},
                    {"cmd": "ss -tulpn / netstat -tulpn", "desc": "Show listening TCP/UDP sockets mapped to active process PIDs."}
                ]
            },
            {
                "section": "Process Signals",
                "points": [
                    {"signal": "SIGTERM (15)", "desc": "Polite termination request allowing graceful cleanup."},
                    {"signal": "SIGKILL (9)", "desc": "Immediate kernel kill, non-catchable. Use when process is unresponsive."},
                    {"signal": "SIGHUP (1)", "desc": "Hangup signal, commonly instructs daemons to reload configuration without restarting."}
                ]
            }
        ]
    },
    {
        "id": "security_hardening",
        "title": "5. Basic Linux Security & Hardening",
        "badge": "Defensive Security",
        "summary": "Implement defense-in-depth: firewall rules, SSH configuration, and audit trails.",
        "content": [
            {
                "section": "Hardening Best Practices",
                "points": [
                    {"topic": "SSH Hardening", "desc": "Disable root login ('PermitRootLogin no'), enforce public key authentication ('PasswordAuthentication no'), and change default port 22."},
                    {"topic": "Host Firewall (UFW/nftables)", "desc": "Default deny incoming policy ('ufw default deny incoming') and only allow essential ports."},
                    {"topic": "Intrusion Prevention", "desc": "Deploy Fail2ban to ban IPs exhibiting repeated failed SSH authentication attempts."},
                    {"topic": "File Integrity Monitoring", "desc": "Utilize AIDE (Advanced Intrusion Detection Environment) or Lynis for periodic host audits."}
                ]
            }
        ]
    }
]

def calculate_permissions(user_r: bool, user_w: bool, user_x: bool,
                          group_r: bool, group_w: bool, group_x: bool,
                          other_r: bool, other_w: bool, other_x: bool,
                          suid: bool = False, sgid: bool = False, sticky: bool = False) -> Dict[str, Any]:
    """Calculate octal, symbolic string, and security evaluation for permissions."""
    u_val = (4 if user_r else 0) + (2 if user_w else 0) + (1 if user_x else 0)
    g_val = (4 if group_r else 0) + (2 if group_w else 0) + (1 if group_x else 0)
    o_val = (4 if other_r else 0) + (2 if other_w else 0) + (1 if other_x else 0)
    special_val = (4 if suid else 0) + (2 if sgid else 0) + (1 if sticky else 0)

    octal_str = f"{special_val}{u_val}{g_val}{o_val}" if special_val > 0 else f"{u_val}{g_val}{o_val}"

    # Symbolic string calculation
    def get_triad(r, w, x, special_char, special_upper):
        chars = ["r" if r else "-", "w" if w else "-"]
        if special_char:
            chars.append(special_char if x else special_upper)
        else:
            chars.append("x" if x else "-")
        return "".join(chars)

    sym_u = get_triad(user_r, user_w, user_x, "s" if suid else None, "S" if suid else None)
    sym_g = get_triad(group_r, group_w, group_x, "s" if sgid else None, "S" if sgid else None)
    sym_o = get_triad(other_r, other_w, other_x, "t" if sticky else None, "T" if sticky else None)
    symbolic = f"-{sym_u}{sym_g}{sym_o}"

    # Security Risk Assessment
    risks = []
    level = "Secure"

    if other_w:
        risks.append("CRITICAL: World-writable permission granted. Any user on system can overwrite this file.")
        level = "High Risk"
    if suid:
        risks.append("WARNING: SUID bit enabled. Binary runs with file owner privileges. High potential for privilege escalation if flawed.")
        if level != "High Risk":
            level = "Medium Risk"
    if sgid:
        risks.append("NOTICE: SGID bit enabled. Inherits group execution context.")
    if octal_str.endswith("777"):
        risks.append("CRITICAL: 0777 allows unrestricted read, write, and execute by anyone on the host.")
        level = "High Risk"
    elif octal_str.endswith("755"):
        risks.append("Standard binary/directory configuration: Owner full control, others read and execute.")
    elif octal_str.endswith("600"):
        risks.append("Optimal secure setting for sensitive private files (SSH private keys, credential vaults).")
        level = "Very Secure"

    return {
        "octal": octal_str,
        "symbolic": symbolic,
        "chmod_cmd": f"chmod {octal_str} target_file",
        "risk_level": level,
        "assessment": risks
    }

SIMULATED_COMMANDS = {
    "ls -la /etc/passwd": (
        "-rw-r--r-- 1 root root 2842 Nov 20 10:14 /etc/passwd\n"
        "[Security Note] Correct permissions: 644 (rw-r--r--). Readable by all, writable only by root."
    ),
    "ls -la /etc/shadow": (
        "-rw-r----- 1 root shadow 1891 Nov 20 10:14 /etc/shadow\n"
        "[Security Note] Restricted permissions: 640 or 600. Critical password hash file inaccessible to unprivileged users."
    ),
    "id": (
        "uid=1000(student) gid=1000(student) groups=1000(student),4(adm),24(cdrom),27(sudo),100(users)\n"
        "[Security Note] User is member of 'sudo' group; verify sudoers policy with 'sudo -l'."
    ),
    "whoami": (
        "student\n"
        "[Security Note] Current interactive user shell."
    ),
    "cat /etc/os-release": (
        "NAME=\"Ubuntu\"\nVERSION=\"24.04 LTS (Noble Numbat)\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n"
        "[Security Note] OS identity reconnaissance aids in targeting known kernel/software vulnerability matrices."
    ),
    "ps aux | head -n 8": (
        "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
        "root           1  0.0  0.1 169336 12848 ?        Ss   09:00   0:02 /sbin/init\n"
        "root           2  0.0  0.0      0     0 ?        S    09:00   0:00 [kthreadd]\n"
        "systemd+     540  0.0  0.2  89400 18232 ?        Ssl  09:00   0:00 /lib/systemd/systemd-resolved\n"
        "root         720  0.0  0.1  15892  9820 ?        Ss   09:00   0:00 /usr/sbin/sshd -D\n"
        "student     1205  0.0  0.3  28400 24800 pts/0    Ss   09:15   0:00 -bash\n"
        "[Security Note] Inspect COMMAND column to discover hidden local services or unquoted script invocations."
    ),
    "find / -perm -4000 -type f 2>/dev/null": (
        "/usr/bin/passwd\n"
        "/usr/bin/sudo\n"
        "/usr/bin/su\n"
        "/usr/bin/newgrp\n"
        "/usr/bin/gpasswd\n"
        "[Security Note] Standard SUID binaries. Always cross-reference with GTFOBins (e.g. vim, nmap, find) for privilege escalation vectors."
    ),
    "ufw status": (
        "Status: active\n"
        "To                         Action      From\n"
        "--                         ------      ----\n"
        "22/tcp                     ALLOW       192.168.1.0/24\n"
        "80/tcp                     ALLOW       Anywhere\n"
        "443/tcp                    ALLOW       Anywhere\n"
        "[Security Note] UFW active: Port 22 SSH restricted to trusted management subnet."
    )
}

def simulate_linux_command(command: str) -> Dict[str, Any]:
    """Execute safe simulated Linux command with security annotations."""
    cmd_clean = command.strip()
    if cmd_clean in SIMULATED_COMMANDS:
        return {
            "command": cmd_clean,
            "output": SIMULATED_COMMANDS[cmd_clean],
            "status": "success"
        }

    # Partial match fallback
    for k, v in SIMULATED_COMMANDS.items():
        if cmd_clean.startswith(k.split()[0]):
            return {
                "command": cmd_clean,
                "output": v,
                "status": "simulated"
            }

    return {
        "command": cmd_clean,
        "output": f"bash: {cmd_clean}: command simulated in lab sandbox.\nTry: 'id', 'ls -la /etc/passwd', 'ls -la /etc/shadow', 'ps aux | head -n 8', 'find / -perm -4000 -type f 2>/dev/null', or 'ufw status'.",
        "status": "info"
    }

QUIZ_QUESTIONS = [
    {
        "id": 1,
        "question": "Which octal permission represents read, write, and execute for Owner, and read-only for Group and Others?",
        "options": ["744", "755", "644", "700"],
        "correct": 0,
        "explanation": "Owner: r+w+x = 4+2+1 = 7. Group: r = 4. Others: r = 4. Total: 744."
    },
    {
        "id": 2,
        "question": "What is the primary security danger of setting the SUID bit on an executable script or editor binary?",
        "options": [
            "It slows down system execution speed",
            "It executes with the file owner's privileges (often root), enabling privilege escalation",
            "It encrypts the binary file contents",
            "It exposes the binary over network port 80"
        ],
        "correct": 1,
        "explanation": "SUID causes the program to execute with permissions of the file owner. If root owns the file and the binary allows shell escapes, an attacker gains root."
    },
    {
        "id": 3,
        "question": "Which file stores hashed user passwords and password expiration policies on modern Linux systems?",
        "options": ["/etc/passwd", "/etc/shadow", "/etc/security", "/var/log/auth.log"],
        "correct": 1,
        "explanation": "/etc/shadow is restricted (root only) and stores the password hashes, while /etc/passwd is world-readable and stores user account metadata."
    },
    {
        "id": 4,
        "question": "What Linux command displays all running processes across all users with full command line details?",
        "options": ["ps aux", "kill -9", "service list", "whoami"],
        "correct": 0,
        "explanation": "'ps aux' provides a snapshot of all running processes across all users with CPU, memory, and full command arguments."
    },
    {
        "id": 5,
        "question": "Which signal should be sent to a Linux process to request polite, graceful termination?",
        "options": ["SIGKILL (9)", "SIGTERM (15)", "SIGSTOP (19)", "SIGHUP (1)"],
        "correct": 1,
        "explanation": "SIGTERM (signal 15) allows the process to catch the signal, flush buffers, and close open files gracefully. SIGKILL (9) halts execution abruptly."
    }
]

def evaluate_quiz(answers: Dict[str, int]) -> Dict[str, Any]:
    """Score quiz submission and return breakdown."""
    score = 0
    total = len(QUIZ_QUESTIONS)
    results = []

    for q in QUIZ_QUESTIONS:
        qid_str = str(q["id"])
        user_choice = answers.get(qid_str)
        is_correct = (user_choice == q["correct"])
        if is_correct:
            score += 1

        results.append({
            "id": q["id"],
            "question": q["question"],
            "user_choice": user_choice,
            "correct_choice": q["correct"],
            "is_correct": is_correct,
            "explanation": q["explanation"]
        })

    percent = int((score / total) * 100)
    passed = percent >= 70

    return {
        "score": score,
        "total": total,
        "percentage": percent,
        "passed": passed,
        "feedback": "Outstanding knowledge of Linux security fundamentals!" if passed else "Review the Linux Fundamentals modules and try again.",
        "results": results
    }
