import nmap
import aiohttp
import asyncio
import random
import re
import ssl
import socket
import builtwith
import requests
import concurrent.futures
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qsl, urlencode

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Mobile/15E148 Safari/604.1"
]

SECRET_PATTERNS = {
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}"
}

def get_random_headers():
    return {"User-Agent": random.choice(USER_AGENTS)}

async def fetch(session, url, method="GET", data=None):
    """Core async fetcher with UA rotation and proper aiohttp timeout."""
    timeout = aiohttp.ClientTimeout(total=5)
    try:
        if method == "GET":
            async with session.get(url, headers=get_random_headers(), timeout=timeout, allow_redirects=True) as res:
                return res.status, await res.text(), res.headers
        elif method == "POST":
            async with session.post(url, headers=get_random_headers(), data=data, timeout=timeout, allow_redirects=True) as res:
                return res.status, await res.text(), res.headers
    except Exception:
        return None, None, None

async def scan_secrets_and_headers(session, url, vulns):
    status, text, headers = await fetch(session, url)
    if not status: return

    # FEATURE 1: EXPANDED SECURITY HEADERS ANALYSIS
    if headers:
        headers_lower = {k.lower(): v for k, v in headers.items()}
        required_headers = {
            "strict-transport-security": ("Missing HSTS Header", "Medium", "The server does not enforce HTTP Strict Transport Security (HSTS).", "Configure the web server to include the 'Strict-Transport-Security' header."),
            "x-frame-options": ("Clickjacking Vulnerability", "Medium", "The 'X-Frame-Options' header is missing.", "Implement 'X-Frame-Options: DENY' or 'SAMEORIGIN'."),
            "content-security-policy": ("Missing CSP Header", "Low", "Content-Security-Policy is not set, increasing risk of XSS.", "Implement a strict Content-Security-Policy."),
            "x-content-type-options": ("Missing MIME Sniffing Protection", "Low", "X-Content-Type-Options is missing.", "Set 'X-Content-Type-Options: nosniff'.")
        }
        
        for header, (v_type, sev, desc, rem) in required_headers.items():
            if header not in headers_lower:
                vulns.append({
                    "type": v_type, "severity": sev, "url": url,
                    "description": desc, "remediation": rem
                })

    if text:
        for name, pattern in SECRET_PATTERNS.items():
            matches = set(re.findall(pattern, text))
            for match in matches:
                vulns.append({
                    "type": f"Exposed {name}", "severity": "Critical", "url": url,
                    "description": f"Hardcoded sensitive secret found in source code: {match[:8]}...",
                    "remediation": "Revoke this key immediately in the provider dashboard and remove it from the code."
                })

# FEATURE 5: URL PARAMETER INJECTION
async def scan_url_parameters(session, url, vulns):
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    
    sqli_payload = "' OR 1=1--"
    xss_payload = "\"><script>alert('VAPT')</script>"
    
    urls_to_test = []

    if parsed_url.query:
        params = parse_qsl(parsed_url.query)
        for i in range(len(params)):
            sqli_params = params.copy()
            sqli_params[i] = (sqli_params[i][0], sqli_params[i][1] + sqli_payload)
            urls_to_test.append((f"{base_url}?{urlencode(sqli_params)}", "SQLi"))
            
            xss_params = params.copy()
            xss_params[i] = (xss_params[i][0], xss_params[i][1] + xss_payload)
            urls_to_test.append((f"{base_url}?{urlencode(xss_params)}", "XSS"))
    else:
        urls_to_test.append((f"{base_url}?id=1{sqli_payload}", "SQLi"))
        urls_to_test.append((f"{base_url}?search={xss_payload}", "XSS"))

    for test_url, attack_type in urls_to_test:
        status, res_text, _ = await fetch(session, test_url)
        if not res_text: continue

        if attack_type == "SQLi" and any(e in res_text.lower() for e in ["sql syntax", "mysql", "ora-", "postgresql"]):
            vulns.append({
                "type": "URL Parameter SQL Injection (GET)", "severity": "Critical", "url": test_url,
                "description": "Injecting characters into the URL parameters triggered a database error.",
                "remediation": "Use Prepared Statements (Parameterized Queries) and sanitize all GET request variables."
            })

        if attack_type == "XSS" and xss_payload in res_text:
            vulns.append({
                "type": "URL Parameter Reflected XSS (GET)", "severity": "High", "url": test_url,
                "description": "Malicious payload in the URL parameter was reflected unescaped into the webpage.",
                "remediation": "Implement strict input validation and HTML entity encoding before rendering URL parameters."
            })

async def scan_forms(session, url, vulns):
    status, text, headers = await fetch(session, url)
    if not text: return

    soup = BeautifulSoup(text, 'html.parser')
    forms = soup.find_all('form')
    
    sqli_payload = "' OR 1=1--"
    xss_payload = "\"><script>alert('VAPT')</script>"

    for form in forms:
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        target_url = urljoin(url, action)

        inputs = form.find_all(['input', 'textarea'])
        data_sqli = {}
        data_xss = {}

        for inp in inputs:
            name = inp.get('name')
            if name:
                data_sqli[name] = sqli_payload
                data_xss[name] = xss_payload

        if method == "post" and data_sqli:
            status, res_text, _ = await fetch(session, target_url, "POST", data_sqli)
            if res_text and any(e in res_text.lower() for e in ["sql syntax", "mysql", "ora-", "postgresql"]):
                vulns.append({
                    "type": "Form-Based SQL Injection (POST)", "severity": "Critical", "url": target_url,
                    "description": f"Form submission triggered database errors indicating SQLi vulnerability.",
                    "remediation": "Rewrite database queries to use Prepared Statements (Parameterized Queries)."
                })

            status, res_text, _ = await fetch(session, target_url, "POST", data_xss)
            if res_text and xss_payload in res_text:
                vulns.append({
                    "type": "Form-Based Reflected XSS", "severity": "High", "url": target_url,
                    "description": "Form input was reflected directly into the DOM without sanitization.",
                    "remediation": "Implement strict input validation and context-aware HTML entity encoding."
                })

# FEATURE 3: ASYNCHRONOUS DIRECTORY FUZZING (EXPANDED)
async def fuzz_directories(session, url, vulns):
    common_paths = [
        '/admin', '/.git/config', '/backup.zip', '/robots.txt', 
        '/phpinfo.php', '/.env', '/config.php.bak', '/server-status',
        '/.DS_Store', '/wp-config.php.bak', '/api/v1/users'
    ]
    tasks = []
    
    for path in common_paths:
        target_url = url.rstrip('/') + path
        tasks.append(fetch(session, target_url))
    
    results = await asyncio.gather(*tasks)
    
    for i, res in enumerate(results):
        status, text, headers = res
        if status == 200:
            path = common_paths[i]
            severity = "High" if any(x in path for x in ['git', 'backup', 'phpinfo', '.env', 'config']) else "Info"
            vulns.append({
                "type": "Exposed Sensitive Directory/File", "severity": severity, "url": url.rstrip('/') + path,
                "description": f"Accessible path found at {path}.", 
                "remediation": "Restrict access via .htaccess, remove the file, or use server configurations."
            })

# FEATURE 6: ADMIN PANEL HUNTER & MINI BRUTE-FORCE
async def hunt_admin_panels(session, url, vulns):
    admin_paths = [
        '/admin', '/administrator', '/wp-login.php', 
        '/admin.php', '/login', '/admin/login.php', '/manager/html'
    ]
    
    tasks = []
    for path in admin_paths:
        target_url = url.rstrip('/') + path
        tasks.append(fetch(session, target_url))
    
    results = await asyncio.gather(*tasks)
    
    for i, res in enumerate(results):
        status, text, headers = res
        
        if status == 200 and text and any(kw in text.lower() for kw in ['password', 'login', 'sign in', 'username']):
            path_found = admin_paths[i]
            target_url = url.rstrip('/') + path_found
            
            vulns.append({
                "type": "Exposed Administrative Interface", 
                "severity": "Medium", 
                "url": target_url,
                "description": f"A publicly accessible login panel was discovered at '{path_found}'.",
                "remediation": "Restrict access to administrative interfaces using IP whitelisting or a VPN. Enforce MFA."
            })
            
            brute_data = {"log": "admin", "pwd": "admin", "username": "admin", "password": "admin"} 
            brute_status, brute_text, _ = await fetch(session, target_url, "POST", brute_data)
            
            if brute_text and any(success_kw in brute_text.lower() for success_kw in ['dashboard', 'welcome admin', 'logout']):
                vulns.append({
                    "type": "Broken Authentication (Default Credentials)", 
                    "severity": "Critical", 
                    "url": target_url,
                    "description": "Successfully bypassed the login panel using default credentials (admin:admin).",
                    "remediation": "Immediately change default administrative passwords and enforce a strong password policy."
                })

async def run_async_engine(url, vulns):
    async with aiohttp.ClientSession() as session:
        await asyncio.gather(
            scan_secrets_and_headers(session, url, vulns),
            scan_forms(session, url, vulns),
            fuzz_directories(session, url, vulns),
            scan_url_parameters(session, url, vulns),
            hunt_admin_panels(session, url, vulns)
        )

# FEATURE 2: SSL/TLS CERTIFICATE CHECKER
def check_ssl_certificate(url, vulns):
    if not url.startswith("https"):
        return
        
    domain = urlparse(url).netloc.split(':')[0]
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                days_left = (expire_date - datetime.utcnow()).days
                
                if days_left < 30:
                    severity = "High" if days_left < 0 else "Medium"
                    vulns.append({
                        "type": "SSL/TLS Certificate Issue", "severity": severity, "url": url,
                        "description": f"SSL Certificate expires in {days_left} days." if days_left >= 0 else "SSL Certificate is EXPIRED.",
                        "remediation": "Renew and deploy a valid SSL/TLS certificate immediately."
                    })
    except Exception:
        pass

# FEATURE 4: AUTOMATED CVE MAPPING
def map_cves(url, vulns):
    try:
        def get_tech():
            return builtwith.parse(url)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            tech = executor.submit(get_tech).result(timeout=5)
            
        if isinstance(tech, dict) and tech:
            tech_list = set()
            for items in tech.values():
                tech_list.update(items)
                
            for t in tech_list:
                try:
                    api_url = f"https://cve.circl.lu/api/search/{t.replace(' ', '/')}"
                    res = requests.get(api_url, timeout=3)
                    if res.status_code == 200 and res.json():
                        if len(res.json()) > 0:
                            vulns.append({
                                "type": "Outdated Component / Known CVEs", "severity": "High", "url": "Infrastructure",
                                "description": f"The component '{t}' has known public vulnerabilities (CVEs).",
                                "remediation": f"Update '{t}' to the latest stable and secure version."
                            })
                except Exception:
                    continue
    except Exception:
        pass

# FEATURE 7: WAF DETECTION (NEW)
def detect_waf(url, vulns):
    try:
        res = requests.get(url, headers=get_random_headers(), timeout=5)
        headers = {k.lower(): v.lower() for k, v in res.headers.items()}
        cookies = res.cookies.get_dict()
        
        waf_name = None
        
        # Checking for common WAF signatures in HTTP Headers
        if 'cf-ray' in headers or 'cloudflare' in headers.get('server', ''):
            waf_name = "Cloudflare"
        elif 'x-sucuri-id' in headers or 'sucuri' in headers.get('server', ''):
            waf_name = "Sucuri WAF"
        elif 'x-amz-cf-id' in headers or 'cloudfront' in headers.get('server', ''):
            waf_name = "AWS WAF / CloudFront"
        elif 'akamai' in headers.get('server', '') or 'x-akamai-request-id' in headers:
            waf_name = "Akamai"
        elif 'incap_ses' in str(cookies) or 'imperva' in headers.get('server', ''):
            waf_name = "Imperva / Incapsula"
        elif 'x-fw-rid' in headers:
            waf_name = "Barracuda WAF"
            
        if waf_name:
            vulns.append({
                "type": "Web Application Firewall (WAF) Detected", 
                "severity": "Info", 
                "url": url,
                "description": f"The target environment is protected by a Web Application Firewall: {waf_name}.",
                "remediation": "This is an informational finding. Penetration testing payloads may be actively blocked or rate-limited by this firewall infrastructure."
            })
    except Exception:
        pass

def scan_vulnerabilities(url):
    vulns = []
    if not url.startswith("http"):
        url = "http://" + url
    parsed = urlparse(url)
    domain = parsed.netloc if parsed.netloc else parsed.path

    # Synchronous Scans (SSL, CVEs, WAF, and Nmap)
    check_ssl_certificate(url, vulns)
    map_cves(url, vulns)
    detect_waf(url, vulns) # Firing the new WAF scanner

    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=domain, arguments='-Pn -F -T4 --host-timeout 10s --max-retries 1')
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    if nm[host][proto][port]['state'] == 'open':
                        vulns.append({
                            "type": "Exposed Network Port", "severity": "Medium", "url": f"{host}:{port}", 
                            "description": f"Port {port} is open.", "remediation": "Close the port if not strictly required via Firewall."
                        })
    except Exception as e:
        print(f"Nmap Error: {e}")

    # Fire the Asynchronous Scanning Engine
    asyncio.run(run_async_engine(url, vulns))

    return vulns