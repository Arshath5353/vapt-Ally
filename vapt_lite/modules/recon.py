import socket
import requests
import shodan
import builtwith
from urllib.parse import urlparse
import concurrent.futures

# Your Shodan API Key
SHODAN_API_KEY = "b8AYCxyXi40vROZaW51pgjKktxDFckFs"

def check_port(ip, port):
    """Quick socket connection to test if a port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)  # Fast timeout
            if s.connect_ex((ip, port)) == 0:
                return port
    except Exception:
        pass
    return None

def perform_recon(url):
    """Gathers IP, headers, Shodan intelligence, and tech stack."""
    
    recon_data = {
        "ip": "Unknown",
        "server": "Information Not Disclosed",
        "waf": "None Detected",
        "ports": [],
        "tech": "Undetermined"
    }

    try:
        if not url.startswith("http"):
            url = "http://" + url

        # Clean the domain
        domain = urlparse(url).netloc.split(':')[0]

        # 1. Get IP
        try:
            recon_data["ip"] = socket.gethostbyname(domain)
        except Exception:
            pass

        # 2. Get Headers (Server & WAF) - WITH ANTI-BOT HEADERS
        try:
            headers_spoof = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
            response = requests.head(url, headers=headers_spoof, timeout=5, allow_redirects=True)
            headers = response.headers
            
            if "Server" in headers:
                recon_data["server"] = headers["Server"]
                
            waf_signatures = ['cloudflare', 'imperva', 'sucuri', 'akamai', 'incapsula', 'awswaf']
            header_string = str(headers).lower()
            for waf in waf_signatures:
                if waf in header_string:
                    recon_data["waf"] = waf.capitalize()
                    break
        except requests.exceptions.Timeout:
            recon_data["waf"] = "Strict Firewall/WAF (Timed Out)"
        except Exception:
            pass

        # 3. Port Discovery (Shodan + Fallback)
        if recon_data["ip"] != "Unknown":
            # Attempt Shodan first
            try:
                api = shodan.Shodan(SHODAN_API_KEY)
                host_info = api.host(recon_data["ip"])
                recon_data["ports"] = host_info.get("ports", [])
            except Exception:
                pass

            # FALLBACK: Active quick scan
            if not recon_data["ports"]:
                common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 3306, 3389, 8080, 8443]
                found_ports = []
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                    futures = [executor.submit(check_port, recon_data["ip"], p) for p in common_ports]
                    for future in concurrent.futures.as_completed(futures):
                        res = future.result()
                        if res:
                            found_ports.append(res)
                
                recon_data["ports"] = sorted(found_ports)

        # 4. Technology Fingerprinting (FIXED HANGING ISSUE)
        try:
            # Wrap builtwith in a strict timeout thread to prevent indefinite hanging
            def get_tech():
                return builtwith.parse(url)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as tech_executor:
                future = tech_executor.submit(get_tech)
                tech = future.result(timeout=5)  # 5 second absolute timeout
                
            if isinstance(tech, dict) and tech:
                tech_list = []
                for category, items in tech.items():
                    tech_list.extend(items)
                recon_data["tech"] = ", ".join(list(set(tech_list)))
                
        except concurrent.futures.TimeoutError:
            recon_data["tech"] = "Analysis Timed Out (Strict WAF)"
        except Exception as e:
            pass

    except Exception as e:
        print(f"Recon Error: {e}")

    return recon_data

def find_subdomains(domain):
    """Queries multiple APIs for instant subdomain enumeration with fallbacks."""
    subdomains = set()
    
    # 1. Clean the domain string
    if "://" in domain:
        domain = domain.split("://")[-1]
    domain = domain.split("/")[0].split(":")[0]
    
    if domain.startswith("www."):
        domain = domain[4:]

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"}

    # METHOD 1: crt.sh (Primary)
    try:
        res = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", headers=headers, timeout=10)
        if res.status_code == 200:
            data = res.json()
            for entry in data:
                name = entry.get('name_value', '')
                if name:
                    clean_names = name.split('\n')
                    for n in clean_names:
                        n = n.replace('*.', '').strip()
                        if n and n != domain and n.endswith(domain): 
                            subdomains.add(n)
    except Exception:
        pass # If crt.sh fails, just move to the next method

    # METHOD 2: HackerTarget API (Fallback)
    if not subdomains:
        try:
            res = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", headers=headers, timeout=10)
            if res.status_code == 200 and "error" not in res.text.lower():
                lines = res.text.split('\n')
                for line in lines:
                    sub = line.split(',')[0].strip()
                    if sub and sub != domain and sub.endswith(domain):
                        subdomains.add(sub)
        except Exception:
            pass

    # METHOD 3: AlienVault OTX API (Second Fallback)
    if not subdomains:
        try:
            res = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", headers=headers, timeout=10)
            if res.status_code == 200:
                data = res.json()
                for entry in data.get('passive_dns', []):
                    sub = entry.get('hostname', '').strip()
                    if sub and sub != domain and sub.endswith(domain):
                        subdomains.add(sub)
        except Exception:
            pass

    return sorted(list(subdomains))