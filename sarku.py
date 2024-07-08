import subprocess
import whois
import dns.resolver
import sys
import os

def run_sublist3r(target):
    print("[*] Running Sublist3r...")
    subprocess.run(["python", "sublist3r.py", "-d", target])

def run_theharvester(target):
    print("[*] Running theHarvester...")
    subprocess.run(["theHarvester", "-d", target, "-b", "all"])

def run_whois(target):
    print("[*] Running whois...")
    w = whois.whois(target)
    print(w)

def run_dnsenum(target):
    print("[*] Running DNS Enumeration...")
    resolver = dns.resolver.Resolver()
    try:
        answers = resolver.query(target, 'A')
        for answer in answers:
            print(f'A record: {answer}')
    except dns.resolver.NoAnswer:
        print("No A record found")

def run_nmap(target):
    print("[*] Running Nmap...")
    subprocess.run(["nmap", "-sV", target])

def run_dirsearch(target):
    print("[*] Running Dirsearch...")
    subprocess.run(["python3", "dirsearch/dirsearch.py", "-u", target])

def run_zap(target):
    print("[*] Running OWASP ZAP...")
    subprocess.run(["zap-cli", "quick-scan", target])

def run_nikto(target):
    print("[*] Running Nikto...")
    subprocess.run(["nikto", "-h", target])

def run_sqlmap(target):
    print("[*] Running Sqlmap...")
    subprocess.run(["sqlmap", "-u", target, "--batch"])

def run_metasploit(target):
    print("[*] Running Metasploit...")
    subprocess.run(["msfconsole", "-q", "-x", f"use auxiliary/scanner/http/dir_scanner\nset RHOSTS {target}\nrun"])

def run_xsstrike(target):
    print("[*] Running XSStrike...")
    subprocess.run(["xsstrike", "-u", target])

def run_empire():
    print("[*] Running Empire...")
    subprocess.run(["empire"])

def run_mimikatz():
    print("[*] Running Mimikatz...")
    subprocess.run(["mimikatz.exe"])

def run_seclists():
    print("[*] Accessing SecLists...")
    subprocess.run(["ls", "SecLists/"])

def run_ffuf(target):
    print("[*] Running ffuf...")
    subprocess.run(["ffuf", "-u", f"{target}/FUZZ", "-w", "SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt"])

def run_shodan(target):
    print("[*] Running Shodan search...")
    subprocess.run(["shodan", "host", target])

def run_cyberchef():
    print("[*] Opening CyberChef...")
    # Adjust the command based on how you open CyberChef locally or via browser
    subprocess.run(["firefox", "https://gchq.github.io/CyberChef/"])

def run_recon(target):
    run_sublist3r(target)
    run_theharvester(target)
    run_whois(target)
    run_dnsenum(target)

def run_scan(target):
    run_nmap(target)
    run_dirsearch(target)

def run_vuln(target):
    run_zap(target)
    run_nikto(target)
    run_sqlmap(target)

def run_exploit(target):
    run_metasploit(target)
    run_sqlmap(target)
    run_xsstrike(target)

def run_post_exploit():
    run_empire()
    run_mimikatz()

def run_misc(target):
    run_seclists()
    run_ffuf(target)
    run_shodan(target)
    run_cyberchef()

def run_help():
    print("""
Usage: sarku -s (target URL) -m (recon|scan|vuln|exploit|post|misc|all)
       sarku -h  (show this help message)
       sarku -i  (install required tools)
    """)

def install_tools():
    print("[*] Installing required tools...")
    # Add installation commands here based on your system and package manager
    subprocess.run(["apt-get", "install", "-y", "python3-pip"])
    subprocess.run(["pip3", "install", "shodan"])
    # Add more installation commands as needed

def run_sarku(target, mode):
    if mode == "recon" or mode == "all":
        run_recon(target)
    if mode == "scan" or mode == "all":
        run_scan(target)
    if mode == "vuln" or mode == "all":
        run_vuln(target)
    if mode == "exploit" or mode == "all":
        run_exploit(target)
    if mode == "post" or mode == "all":
        run_post_exploit()
    if mode == "misc" or mode == "all":
        run_misc(target)

if __name__ == "__main__":
    if len(sys.argv) < 3 or sys.argv[1] == "-h":
        run_help()
        sys.exit(0)
    elif sys.argv[1] == "-i":
        install_tools()
        sys.exit(0)

    target_url = sys.argv[2]
    mode = sys.argv[4] if len(sys.argv) > 3 and sys.argv[3] == "-m" else "all"

    run_sarku(target_url, mode)
