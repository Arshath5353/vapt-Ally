# 🛡️ VAPT Ally

### AI-Powered Automated Vulnerability Assessment & Penetration Testing Platform

VAPT Ally is a full-stack cybersecurity platform that automates **Vulnerability Assessment and Penetration Testing (VAPT)** by combining infrastructure reconnaissance, intelligent web crawling, OWASP vulnerability detection, AI-powered security analysis, and automated report generation into a single dashboard.

The platform is designed to help security professionals, penetration testers, and students quickly identify common web application vulnerabilities, understand their security impact, and generate professional assessment reports.

---

## 🎥 Demo

> 📹 **2-Minute Project Demonstration**
>
> *(Add your YouTube or GitHub Release video link here)*

---

## 📸 Screenshots

### Dashboard
*(Add Screenshot Here)*

### AI Security Analyst
*(Add Screenshot Here)*

### PDF Report
*(Add Screenshot Here)*

---

# ✨ Features

### 🌐 Infrastructure Reconnaissance

- Technology fingerprinting
- Server identification
- Web Application Firewall (WAF) detection
- Open port discovery
- IP address resolution

---

### 🕷️ Advanced Web Crawler

- Recursive same-origin crawling
- URL normalization
- JavaScript endpoint extraction
- robots.txt parsing
- sitemap.xml discovery
- Swagger/OpenAPI detection
- Form discovery
- Session cookie support

---

### 🔍 Vulnerability Scanner

Detects common web application vulnerabilities including:

- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Missing Security Headers
- Clickjacking Protection Issues
- Sensitive File Exposure
- Exposed Administrative Interfaces
- Directory Enumeration
- Information Disclosure

---

### 🤖 AI Security Analyst

Powered by **Google Gemini API**

Automatically generates:

- Executive Summary
- Overall Security Posture
- Attack Surface Summary
- Business Impact Analysis
- OWASP Top 10 Mapping
- Immediate Remediation
- Long-Term Recommendations

---

### 📊 Risk Assessment

- Dynamic Risk Score (0–100)
- Risk Level Classification
- Severity Distribution
- Executive Dashboard

---

### 📄 Automated Reporting

Generate professional PDF reports containing:

- Executive Summary
- Infrastructure Intelligence
- Vulnerability Findings
- Risk Analysis
- Discovered Subdomains
- Crawled Endpoints
- Remediation Recommendations

---

# 🛠 Technology Stack

## Backend

- Python
- Flask
- Asyncio

## Frontend

- HTML5
- CSS3
- JavaScript
- Jinja2 Templates

## Security Libraries

- python-nmap
- requests
- aiohttp
- beautifulsoup4
- lxml
- builtwith

## AI

- Google Gemini API

## Reporting

- ReportLab

## Database

- SQLite

## Deployment

- Docker
- Render

---

# 🔐 Vulnerabilities Detected

Current scanning capabilities include:

| Category | Detection |
|----------|-----------|
| Injection | SQL Injection |
| Injection | Cross-Site Scripting (XSS) |
| Security Misconfiguration | Missing HSTS |
| Security Misconfiguration | Missing CSP |
| Security Misconfiguration | Missing X-Frame-Options |
| Security Misconfiguration | Missing X-Content-Type-Options |
| Information Disclosure | Exposed Backup Files |
| Information Disclosure | Exposed Environment Files |
| Information Disclosure | Exposed Admin Panels |
| Infrastructure | Open Ports |
| Infrastructure | Technology Fingerprinting |
| Infrastructure | Subdomain Enumeration |

---

# 🚀 Installation

Clone the repository

```bash
git clone https://github.com/Arshath5353/vapt-Ally.git
```

Navigate to the project

```bash
cd vapt-Ally/vapt_lite
```

Install dependencies

```bash
pip install -r requirements.txt
```

Create a `.env` file

```env
GEMINI_API_KEY=YOUR_API_KEY
SECRET_KEY=YOUR_SECRET_KEY
```

Run the application

```bash
python app.py
```

Open

```
http://127.0.0.1:5000
```

---

# 📂 Project Structure

```
vapt-Ally
│
├── vapt_lite
│   ├── modules
│   │   ├── crawler.py
│   │   ├── scanner.py
│   │   ├── recon.py
│   │   ├── ai_analyst.py
│   │   ├── risk.py
│   │   ├── history_db.py
│   │   ├── pdf_gen.py
│   │   └── subdomain.py
│   │
│   ├── static
│   ├── templates
│   ├── reports
│   ├── app.py
│   ├── requirements.txt
│   └── Dockerfile
```

---

# 🛣️ Future Roadmap

- Nuclei Integration
- Authenticated Scanning
- CVE Detection
- API Security Testing
- JWT Analysis
- SSRF Detection
- CSRF Detection
- AI-Powered Vulnerability Remediation
- Multi-threaded Scanning
- Scan Scheduling
- Email Report Delivery

---

# 👨‍💻 Author

**Mohamed Arshath**

B.Tech Computer Science & Engineering (Cyber Security)

SRM Institute of Science and Technology

GitHub:
https://github.com/Arshath5353

---

# ⭐ Support

If you found this project useful, consider giving it a **⭐ Star** on GitHub.

---

## ⚠️ Disclaimer

This tool is intended **only for authorized security testing and educational purposes**. Always obtain proper permission before scanning or testing any target systems.
