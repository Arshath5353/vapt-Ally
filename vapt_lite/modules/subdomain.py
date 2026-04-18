import requests

def find_subdomains(domain):
    """
    Uses multiple OSINT APIs (HackerTarget, crt.sh, AlienVault) 
    to guarantee subdomain discovery.
    """
    subdomains = set()
    
    # Clean the domain (e.g., periyaruniversity.ac.in)
    base_domain = domain.replace("www.", "").strip('/')
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}

    # --- API 1: HackerTarget (Fast & Highly Reliable) ---
    try:
        ht_url = f"https://api.hackertarget.com/hostsearch/?q={base_domain}"
        ht_res = requests.get(ht_url, headers=headers, timeout=10)
        if ht_res.status_code == 200 and "error" not in ht_res.text.lower():
            for line in ht_res.text.split('\n'):
                if ',' in line:
                    sub = line.split(',')[0].strip().lower()
                    if sub.endswith(base_domain) and sub != base_domain:
                        subdomains.add(sub)
    except Exception:
        pass # If it fails, move to the next API

    # --- API 2: crt.sh (Certificate Transparency) ---
    try:
        crt_url = f"https://crt.sh/?q=%25.{base_domain}&output=json"
        crt_res = requests.get(crt_url, headers=headers, timeout=10)
        if crt_res.status_code == 200:
            for entry in crt_res.json():
                name = entry.get('name_value', '')
                for sub in name.split('\n'):
                    sub = sub.strip().lower()
                    if not sub.startswith('*') and sub != base_domain and sub.endswith(base_domain):
                        subdomains.add(sub)
    except Exception:
        pass # If it fails, move to the next API

    # --- API 3: JLDC / AlienVault (Passive DNS) ---
    try:
        jldc_url = f"https://jldc.me/anom/v3/subdomains/{base_domain}"
        jldc_res = requests.get(jldc_url, headers=headers, timeout=10)
        if jldc_res.status_code == 200:
            for sub in jldc_res.json():
                sub = sub.strip().lower()
                if not sub.startswith('*') and sub != base_domain:
                    subdomains.add(sub)
    except Exception:
        pass

    # --- FAILSAFE: Tiny Active Check ---
    # If your internet/college network blocked all 3 APIs, do a micro-check
    if not subdomains:
        wordlist = ["www", "mail", "webmail", "erp", "portal", "admin"]
        for word in wordlist:
            sub = f"{word}.{base_domain}"
            try:
                # Just requesting the headers to be fast
                if requests.head(f"http://{sub}", timeout=2).status_code < 400:
                    subdomains.add(sub)
            except requests.exceptions.RequestException:
                continue

    return sorted(list(subdomains))