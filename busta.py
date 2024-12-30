import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
import sys
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def check_tool_installed(tool):
    """Check if a tool is installed, and attempt to install if not."""
    try:
        # Attempt to check version of the tool
        subprocess.run([tool, "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logging.info(f"[INFO] {tool} is already installed.")
    except FileNotFoundError:
        logging.error(f"[ERROR] {tool} is not found in the system path.")
        install_tool(tool)
    except subprocess.CalledProcessError:
        logging.error(f"[ERROR] {tool} failed to run correctly. Attempting to install...")
        install_tool(tool)

def install_tool(tool):
    """Install the required tool."""
    try:
        if tool == "amass":
            logging.info(f"[INFO] Installing {tool}...")
            subprocess.run(["sudo", "apt-get", "install", "amass", "-y"], check=True)
            logging.info(f"[INFO] {tool} installed successfully.")
        elif tool == "sublist3r":
            logging.info(f"[INFO] Installing {tool}...")
            subprocess.run([sys.executable, "-m", "pip", "install", "sublist3r"], check=True)
            logging.info(f"[INFO] {tool} installed successfully.")
        elif tool == "httpx":
            logging.info(f"[INFO] Installing {tool} using Go...")
            subprocess.run(["sudo", "apt-get", "install", "golang", "-y"], check=True)
            subprocess.run(["go", "install", "github.com/projectdiscovery/httpx/cmd/httpx@latest"], check=True)
            logging.info(f"[INFO] {tool} installed successfully.")
        elif tool == "ffuf":
            logging.info(f"[INFO] Installing {tool}...")
            subprocess.run(["sudo", "apt-get", "install", "ffuf", "-y"], check=True)
            logging.info(f"[INFO] {tool} installed successfully.")
        elif tool == "nmap":
            logging.info(f"[INFO] Installing {tool}...")
            subprocess.run(["sudo", "apt-get", "install", "nmap", "-y"], check=True)
            logging.info(f"[INFO] {tool} installed successfully.")
        else:
            logging.error(f"[ERROR] Unsupported tool: {tool}. Unable to install.")
            sys.exit(1)
    except subprocess.CalledProcessError as e:
        logging.error(f"[ERROR] Failed to install {tool}: {e}")
        sys.exit(1)

def run_amass(domain):
    """Run Amass to enumerate subdomains."""
    logging.info(f"[INFO] Running Amass for subdomain enumeration on {domain}...")
    output_file = f"amass_{domain}.txt"
    try:
        subprocess.run(["amass", "enum", "-d", domain, "-o", output_file], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"[ERROR] Amass failed: {e}")
    return output_file

def run_sublist3r(domain):
    """Run Sublist3r to enumerate subdomains."""
    logging.info(f"[INFO] Running Sublist3r for subdomain enumeration on {domain}...")
    output_file = f"sublist3r_{domain}.txt"
    try:
        subprocess.run(["sublist3r", "-d", domain, "-o", output_file], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"[ERROR] Sublist3r failed: {e}")
    return output_file

def merge_subdomains(files):
    """Merge subdomains from multiple files into a unique list."""
    subdomains = set()
    for file in files:
        if os.path.exists(file):
            with open(file, "r") as f:
                subdomains.update(line.strip() for line in f if line.strip())
    merged_file = "merged_subdomains.txt"
    with open(merged_file, "w") as f:
        f.write("\n".join(sorted(subdomains)))
    logging.info(f"[INFO] Merged subdomains saved to {merged_file}")
    return merged_file

def probe_subdomains(subdomains_file):
    """Probe subdomains to check which are alive."""
    logging.info("[INFO] Probing subdomains for live hosts...")
    alive_file = "alive_subdomains.txt"
    try:
        subprocess.run(["httpx", "-l", subdomains_file, "-o", alive_file], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"[ERROR] HTTPX probing failed: {e}")
    logging.info(f"[INFO] Live subdomains saved to {alive_file}")
    return alive_file

def run_nmap(subdomain):
    """Scan for open ports on a subdomain using Nmap."""
    output_file = f"nmap_{subdomain.replace('.', '_')}.txt"
    logging.info(f"[INFO] Scanning {subdomain} for open ports using Nmap...")
    try:
        subprocess.run(["nmap", "-p", "1-65535", subdomain, "-oN", output_file], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"[ERROR] Nmap failed for {subdomain}: {e}")
    logging.info(f"[INFO] Nmap scan results saved to {output_file}")

def run_dirbusting(subdomain, wordlist):
    """Run directory brute-forcing on a subdomain."""
    output_file = f"dirbusting_{subdomain.replace('.', '_')}.txt"
    logging.info(f"[INFO] Running directory brute-forcing on {subdomain}...")
    try:
        subprocess.run([
            "ffuf", "-u", f"http://{subdomain}/FUZZ", "-w", wordlist, "-o", output_file
        ], check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"[ERROR] FFUF failed for {subdomain}: {e}")
    logging.info(f"[INFO] Directory brute-forcing results saved to {output_file}")

def main():
    if len(sys.argv) != 3:
        logging.error("Usage: python3 script.py <root_domain> <wordlist>")
        sys.exit(1)

    domain = sys.argv[1].strip()
    wordlist = sys.argv[2].strip()

    if not os.path.exists(wordlist):
        logging.error(f"[ERROR] Wordlist file {wordlist} does not exist.")
        sys.exit(1)

    # Check if necessary tools are installed
    for tool in ["amass", "sublist3r", "httpx", "ffuf", "nmap"]:
        check_tool_installed(tool)

    # Subdomain enumeration
    amass_output = run_amass(domain)
    sublist3r_output = run_sublist3r(domain)

    # Merge and probe subdomains
    merged_subdomains = merge_subdomains([amass_output, sublist3r_output])
    alive_subdomains = probe_subdomains(merged_subdomains)

    # Directory brute-forcing and port scanning
    with open(alive_subdomains, "r") as f:
        subdomains = [line.strip() for line in f if line.strip()]

    with ThreadPoolExecutor(max_workers=5) as executor:
        for subdomain in subdomains:
            executor.submit(run_dirbusting, subdomain, wordlist)
            executor.submit(run_nmap, subdomain)

if __name__ == "__main__":
    main()
