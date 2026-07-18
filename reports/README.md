# 🛡️ VAPT Ally

<<<<<<< HEAD
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
=======
<p align="center">
  <b>AI-Powered Automated Vulnerability Assessment & Penetration Testing Platform</b><br>
  A Full-Stack Cybersecurity Application for Reconnaissance, Vulnerability Detection, Risk Analysis, and Professional Security Reporting.
</p>

---

## 📖 Overview

VAPT Ally is an AI-powered web security assessment platform built to automate Vulnerability Assessment and Penetration Testing (VAPT). It combines infrastructure reconnaissance, web crawling, vulnerability detection, AI-powered security analysis, and PDF report generation into a single dashboard.

The application helps security analysts identify common web application vulnerabilities, assess the overall security posture of a target, calculate a risk score, and generate professional assessment reports.

---

## ✨ Features

### 🔍 Infrastructure Reconnaissance

- Detect target IP Address
- Identify Web Server
- Detect Technology Stack
- Identify WAF (Web Application Firewall)
- Discover Open Ports
- HTTP Header Analysis

---

### 🌐 Subdomain Enumeration

- Automatically discovers subdomains
- Expands external attack surface visibility
- Displays discovered assets in the dashboard

---

### 🕷️ Intelligent Web Crawler

- Crawls internal pages
- Maps website structure
- Collects forms
- Finds hidden endpoints
- Extracts URLs for further testing

---

### 🚨 Automated Vulnerability Scanner

Detects common web security issues including:

- SQL Injection
- Cross Site Scripting (XSS)
- Missing Security Headers
- Exposed Sensitive Files
- Directory Enumeration
- Information Disclosure
- Security Misconfiguration

---

### 📊 Risk Assessment Engine

Automatically calculates:

- Overall Risk Score (0–100)
- Risk Level
- Severity Distribution
- Total Vulnerabilities
>>>>>>> 53b7109 (Update VAPT Ally)

---

### 🤖 AI Security Analyst

<<<<<<< HEAD
Powered by **Google Gemini API**

Automatically generates:

- Executive Summary
- Overall Security Posture
- Attack Surface Summary
- Business Impact Analysis
=======
Powered by **Google Gemini AI**

Generates an executive security report including:

- Executive Summary
- Overall Security Posture
- Attack Surface Analysis
- Highest Priority Findings
- Business Impact
>>>>>>> 53b7109 (Update VAPT Ally)
- OWASP Top 10 Mapping
- Immediate Remediation
- Long-Term Recommendations

---

<<<<<<< HEAD
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
=======
### 📄 PDF Report Generation

Generate a downloadable professional assessment report containing:

- Executive Summary
- Infrastructure Intelligence
- Risk Score
- Vulnerability Details
- AI Analysis
- Recommended Fixes

---

## 🏗️ Architecture

```
                User
                 │
                 ▼
        Flask Web Dashboard
                 │
     ┌───────────┼───────────┐
     │           │           │
     ▼           ▼           ▼
 Recon      Web Crawler   Scanner
     │           │           │
     └───────┬───┴───────────┘
             ▼
      Risk Assessment
             │
             ▼
      Gemini AI Analysis
             │
             ▼
      PDF Report Generator
```

---

## ⚙️ Technology Stack

### Backend
>>>>>>> 53b7109 (Update VAPT Ally)

- Python
- Flask
- Asyncio

<<<<<<< HEAD
## Frontend
=======
### Frontend
>>>>>>> 53b7109 (Update VAPT Ally)

- HTML5
- CSS3
- JavaScript
- Jinja2 Templates

<<<<<<< HEAD
## Security Libraries
=======
### Security Libraries
>>>>>>> 53b7109 (Update VAPT Ally)

- python-nmap
- requests
- aiohttp
<<<<<<< HEAD
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
=======
- BeautifulSoup4
- builtwith
- lxml

### AI

- Google Gemini API

### Reporting

- ReportLab

### Deployment
>>>>>>> 53b7109 (Update VAPT Ally)

- Docker
- Render

---

<<<<<<< HEAD
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
=======
## 📂 Project Structure

```
vapt_lite/

│
├── app.py
├── requirements.txt
├── Dockerfile
│
├── modules/
│   ├── recon.py
│   ├── crawler.py
│   ├── scanner.py
│   ├── risk.py
│   ├── subdomain.py
│   ├── ai_analyst.py
│   ├── pdf_gen.py
│   └── history_db.py
│
├── templates/
│   ├── index.html
│   └── dashboard.html
│
├── static/
│   ├── style.css
│   └── dashboard.js
│
├── reports/
│
└── scan_results.json
```

---

## 🛠️ Installation
>>>>>>> 53b7109 (Update VAPT Ally)

Clone the repository

```bash
<<<<<<< HEAD
git clone https://github.com/Arshath5353/vapt-Ally.git
```

Navigate to the project

```bash
cd vapt-Ally/vapt_lite
=======
git clone https://github.com/yourusername/VAPT-Ally.git
```

Move into the project

```bash
cd VAPT-Ally/vapt_lite
```

Create a virtual environment

```bash
python -m venv .venv
```

Activate

### Windows

```bash
.venv\Scripts\activate
```

### Linux / macOS

```bash
source .venv/bin/activate
>>>>>>> 53b7109 (Update VAPT Ally)
```

Install dependencies

```bash
pip install -r requirements.txt
```

<<<<<<< HEAD
Create a `.env` file

```env
GEMINI_API_KEY=YOUR_API_KEY
SECRET_KEY=YOUR_SECRET_KEY
```

Run the application
=======
---

## 🔑 Environment Variables

Create a `.env` file in the project root.

```env
GEMINI_API_KEY=your_google_gemini_api_key

SHODAN_API_KEY=your_shodan_api_key
```

---

## ▶️ Run
>>>>>>> 53b7109 (Update VAPT Ally)

```bash
python app.py
```

<<<<<<< HEAD
Open
=======
Visit
>>>>>>> 53b7109 (Update VAPT Ally)

```
http://127.0.0.1:5000
```

---

<<<<<<< HEAD
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
=======
## 🛡️ Vulnerabilities Detected

Current detection capabilities include:

- SQL Injection
- Cross Site Scripting (XSS)
- Missing HSTS
- Missing X-Frame-Options
- Missing Content Security Policy
- Sensitive File Exposure
- Robots.txt Disclosure
- Exposed Admin Panels
- Open Ports
- Information Disclosure

---

## 📈 Risk Scoring

Severity weights

| Severity | Score |
|----------|------:|
| Critical | 40 |
| High | 20 |
| Medium | 10 |
| Low | 5 |
| Info | 1 |

Risk Levels

- 🟢 Low
- 🟡 Medium
- 🟠 High
- 🔴 Critical

---

## 🤖 AI Security Analysis

Google Gemini AI automatically analyzes scan results and provides:

- Executive Summary
- Security Posture
- Attack Surface Summary
- Business Impact
- OWASP Mapping
- Immediate Fixes
- Long-Term Recommendations

This reduces manual analysis time while producing professional reports suitable for security teams.

---

## 📄 Sample Report

The generated report includes:

- Infrastructure Intelligence
- Risk Score
- AI Security Analyst
- Vulnerability Details
- Subdomains
- Crawled Paths
- Professional PDF Export

---

## 🚀 Future Improvements

- Authentication Support
- Session-Based Scanning
- CVE Detection
- Nuclei Integration
- API Security Testing
- SSRF Detection
- Command Injection Detection
- Directory Bruteforcing
- Screenshot Capture
- Multi-threaded Scanning
- Scheduled Scans
- Scan History Dashboard
- Email Report Delivery
- CVSS v3 Scoring
- VirusTotal Integration
- AbuseIPDB Integration

---

## 👨‍💻 Author

**Mohamed Arshath**

B.Tech Computer Science and Engineering (Cyber Security)
>>>>>>> 53b7109 (Update VAPT Ally)

SRM Institute of Science and Technology

GitHub:
https://github.com/Arshath5353

---

<<<<<<< HEAD
# ⭐ Support

If you found this project useful, consider giving it a **⭐ Star** on GitHub.

---

## ⚠️ Disclaimer

This tool is intended **only for authorized security testing and educational purposes**. Always obtain proper permission before scanning or testing any target systems.
=======
## ⭐ If you found this project useful

Please consider giving it a ⭐ on GitHub.
>>>>>>> 53b7109 (Update VAPT Ally)
