# 🛡️ VAPT Ally
**Automated Vulnerability Assessment and Penetration Testing (VAPT) Engine**

VAPT Ally is a custom-built, full-stack cybersecurity application designed to act as an automated security analyst. It performs Dynamic Application Security Testing (DAST) combined with Infrastructure Reconnaissance to identify web application flaws and misconfigurations before adversaries can exploit them.

## 🚀 Features
* **Infrastructure Reconnaissance:** Probes the target server to detect underlying tech stacks, Web Application Firewalls (WAF), and open network ports.
* **Automated Spider/Crawler:** Maps the internal structure of the target website to discover hidden paths and endpoints.
* **Active Vulnerability Scanning:** Injects test payloads into forms and parameters to detect application-layer flaws.
* **Passive Security Analysis:** Analyzes HTTP responses for misconfigurations, missing headers, and exposed secrets.
* **Intelligent Risk Scoring:** Quantifies discovered vulnerabilities using a weighted severity matrix to generate a dynamic Risk Score (0-100).
* **Automated Reporting:** Compiles all intelligence into a professional, downloadable PDF assessment report.

## ⚙️ Technology Stack
* **Backend:** Python, Flask, Asyncio
* **Security Modules:** `python-nmap` (Port Scanning), `requests` & `beautifulsoup4` (Crawling/Scraping), `builtwith` (Fingerprinting)
* **Frontend:** HTML5, CSS3, Vanilla JS (Responsive, Custom Dark-Mode UI using Jinja2)
* **Reporting:** `reportlab` (PDF Generation)
* **DevOps / Deployment:** Docker, Render Cloud Hosting

## 🔍 Vulnerabilities Detected
VAPT Ally's custom scanning engine is currently capable of detecting flaws that map directly to the **OWASP Top 10**:
1. **Injection Flaws (SQLi & XSS):** Injects payloads (`' OR 1=1--`, `<script>`) to verify if the server reflects malicious scripts or leaks database syntax errors.
2. **Security Misconfigurations:** Flags missing critical HTTP headers (CSP, HSTS, X-Frame-Options).
3. **Sensitive Data Exposure:** Utilizes asynchronous fuzzing and regex patterns to locate exposed backups (`.zip`), environment files (`.env`), and leaked API keys.
4. **Insecure Network Services:** Detects unsecured open administrative ports (e.g., FTP, Telnet) using Nmap integration.

## 🔮 Future Roadmap
* **Nuclei Integration:** Expand payload database to scan for 6,000+ known CVEs.
* **Authenticated Scanning:** Allow session-cookie injection to scan private dashboards.
* **AI-Powered Remediation:** Integrate LLM APIs to provide custom, code-level fixes tailored to the target's specific tech stack.

---
*Developed as a comprehensive showcase of full-stack engineering and offensive security automation.*
