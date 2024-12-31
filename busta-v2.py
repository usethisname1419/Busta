import os
import sys
import subprocess
import time
import logging
from colorama import Fore

# Set up logging
logging.basicConfig(filename="scan_report.log", level=logging.INFO, format="%(asctime)s - %(message)s")
logging.info("Starting scan...")

# Function to install missing tools
def install_tools():
    tools = ["amass", "sublist3r", "nmap", "gobuster", "httpx"]
    for tool in tools:
        try:
            subprocess.run([tool, "-h"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError:
            print(f"{Fore.RED}[-] {tool} not found. Installing...")
            if tool == "httpx":
                subprocess.run(["go", "install", "github.com/projectdiscovery/httpx/cmd/httpx@latest"], check=True)
            else:
                subprocess.run(["apt-get", "install", "-y", tool], check=True)
            print(f"{Fore.GREEN}[+] {tool} installed successfully!")
            logging.info(f"{tool} installed successfully.")

# Check if required arguments are provided
def validate_input():
    if len(sys.argv) != 3:
        print(f"{Fore.WHITE}Usage: python3 bb.py <root_domain> <wordlist_for_busting>")
        sys.exit()
    return sys.argv[1], sys.argv[2]

# Function to run Amass for subdomain enumeration
def run_amass(domain):
    print(f"{Fore.BLUE}[?] Running Amass for subdomain enumeration...")
    logging.info("Running Amass for subdomain enumeration...")
    result = subprocess.run(["amass", "enum", "-d", domain, "-o", "amass_subdomains.txt"], capture_output=True, text=True)
    if result.returncode == 0:
        print(f"{Fore.GREEN}[+] Amass subdomain enumeration completed!")
        logging.info("Amass subdomain enumeration completed.")

        # Print each subdomain as it's processed
        with open("amass_subdomains.txt", "r") as f:
            print(f"{Fore.YELLOW}[!] Found subdomains:")
            for line in f:
                subdomain = line.strip()
                print(f"  {Fore.GREEN}[+] {subdomain}")
    else:
        print(f"{Fore.RED}[-] Amass failed: {result.stderr}")
        logging.error(f"Amass failed: {result.stderr}")


def run_sublist3r(domain):
    print(f"{Fore.BLUE}[?] Running Sublist3r for subdomain enumeration...")
    logging.info("Running Sublist3r for subdomain enumeration...")
    result = subprocess.run(["sublist3r", "-d", domain, "-o", "sublist3r_subdomains.txt"], capture_output=True, text=True)
    if result.returncode == 0:
        print(f"{Fore.GREEN}[+] Sublist3r subdomain enumeration completed!")
        logging.info("Sublist3r subdomain enumeration completed.")

        # Print each subdomain as it's processed
        with open("sublist3r_subdomains.txt", "r") as f:
            print(f"{Fore.YELLOW}[!] Found subdomains:")
            for line in f:
                subdomain = line.strip()
                print(f"  {Fore.GREEN}[+] {subdomain}")
    else:
        print(f"{Fore.RED}[-] Sublist3r failed: {result.stderr}")
        logging.error(f"Sublist3r failed: {result.stderr}")


# Function to check live subdomains using httpx
def check_live_subdomains():
    print(f"{Fore.BLUE}[?] Checking live subdomains using httpx...")
    logging.info("Checking live subdomains using httpx...")
    with open("amass_subdomains.txt", "r") as amass_file, open("sublist3r_subdomains.txt", "r") as sublist3r_file:
        subdomains = set(amass_file.readlines() + sublist3r_file.readlines())
   
    live_subdomains = []
    for subdomain in subdomains:
        subdomain = subdomain.strip()
        result = subprocess.run(["httpx", "-silent", "-l", subdomain], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            live_subdomains.append(subdomain)
   
    with open("live_subdomains.txt", "w") as output:
        for subdomain in live_subdomains:
            output.write(subdomain + "\n")
    print(f"{Fore.GREEN}[+] Live subdomains saved to live_subdomains.txt")
    logging.info("Live subdomains saved to live_subdomains.txt.")

# Function to run Gobuster for directory busting
def run_gobuster(subdomain, wordlist):
    print(f"{Fore.BLUE}[?] Running Gobuster for directory busting on {subdomain}...")
    logging.info(f"Running Gobuster for directory busting on {subdomain}...")
    result = subprocess.run(["gobuster", "dir", "-k", "--url", f"http://{subdomain}", "-w", wordlist, "--wildcard", "--random-agent"], capture_output=True, text=True)
    if result.returncode == 0:
        print(f"{Fore.GREEN}[+] Gobuster directory busting completed for {subdomain}!")
        logging.info(f"Gobuster directory busting completed for {subdomain}.")
    else:
        print(f"{Fore.RED}[-] Gobuster failed for {subdomain}: {result.stderr}")
        logging.error(f"Gobuster failed for {subdomain}: {result.stderr}")

# Function to scan open ports with Nmap
def run_nmap(subdomain):
    print(f"{Fore.BLUE}[?] Running Nmap for open ports on {subdomain}...")
    logging.info(f"Running Nmap for open ports on {subdomain}...")
    result = subprocess.run(["nmap", "-p-", subdomain], capture_output=True, text=True)
    if result.returncode == 0:
        print(f"{Fore.GREEN}[+] Nmap scan completed for {subdomain}.")
        logging.info(f"Nmap scan completed for {subdomain}.")
    else:
        print(f"{Fore.RED}[-] Nmap failed for {subdomain}: {result.stderr}")
        logging.error(f"Nmap failed for {subdomain}: {result.stderr}")
     
def run_dig(subdomain):
    print(f"{Fore.BLUE}[?] Running dig for DNS records on {subdomain}...")
    logging.info(f"Running dig for DNS records on {subdomain}...")
    dns_records = {}

    # Record types to query
    record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]
    for record in record_types:
        result = subprocess.run(["dig", subdomain, record, "+short"], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            records = result.stdout.strip().split("\n")
            dns_records[record] = records
            print(f"{Fore.GREEN}[+] {record} records for {subdomain}: {records}")
        else:
            logging.warning(f"No {record} records found for {subdomain}.")
   
    # Log DNS records
    for record, entries in dns_records.items():
        logging.info(f"{record} records for {subdomain}: {', '.join(entries)}")
   
    return dns_records    
       
def generate_report(domain, subdomains, live_subdomains, gobuster_results, nmap_results, dns_results):
    with open("final_report.txt", "w") as f:
        f.write(f"Scan Report for Domain: {domain}\n\n")
       
        f.write("=== All Subdomains ===\n")
        for sub in subdomains:
            f.write(f"{sub}\n")
       
        f.write("\n=== Live Subdomains ===\n")
        for sub in live_subdomains:
            f.write(f"{sub}\n")
         
        f.write("\n=== DNS Records ===\n")
        for sub, records in dns_results.items():
            f.write(f"\nSubdomain: {sub}\n")
            for record, entries in records.items():
                f.write(f"{record}:\n")
                for entry in entries:
                    f.write(f"  {entry}\n")
       
        f.write("\n=== Gobuster Results ===\n")
        for sub, directories in gobuster_results.items():
            f.write(f"\nSubdomain: {sub}\n")
            for dir in directories:
                f.write(f"{dir}\n")
       
        f.write("\n=== Nmap Results ===\n")
        for sub, ports in nmap_results.items():
            f.write(f"\nSubdomain: {sub}\n")
            for port in ports:
                f.write(f"{port}\n")
   
    print(f"{Fore.CYAN}[?] Final report saved to 'final_report.txt'")
    logging.info("Final report saved to 'final_report.txt'.")

# Main function to coordinate all tasks
def main():
    domain, wordlist = validate_input()
    install_tools()

    print(f"{Fore.BLUE}[?] Starting scan for domain {domain}...")

    # Run Amass for subdomains
    run_amass(domain)

    # Run Sublist3r for subdomains
    run_sublist3r(domain)

    # Check live subdomains using httpx
    check_live_subdomains()

    # Read live subdomains
    with open("live_subdomains.txt", "r") as live_file:
        live_subdomains = live_file.readlines()
    dns_results = {}
    for subdomain in live_subdomains:
        subdomain = subdomain.strip()
        dns_results[subdomain] = run_dig(subdomain)
   
    # Run Gobuster for each live subdomain
    for subdomain in live_subdomains:
        subdomain = subdomain.strip()
        run_gobuster(subdomain, wordlist)
   
    # Run Nmap for each live subdomain
    for subdomain in live_subdomains:
        subdomain = subdomain.strip()
        run_nmap(subdomain)

    generate_report(domain, subdomains, live_subdomains, gobuster_results, nmap_results, dns_results)

if __name__ == "__main__":
    main()

