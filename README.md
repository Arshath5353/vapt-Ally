# 🛡️ VAPT Ally

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

---

### 🤖 AI Security Analyst

Powered by **Google Gemini AI**

Generates an executive security report including:

- Executive Summary
- Overall Security Posture
- Attack Surface Analysis
- Highest Priority Findings
- Business Impact
- OWASP Top 10 Mapping
- Immediate Remediation
- Long-Term Recommendations

---

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

- Python
- Flask
- Asyncio

### Frontend

- HTML5
- CSS3
- JavaScript
- Jinja2 Templates

### Security Libraries

- python-nmap
- requests
- aiohttp
- BeautifulSoup4
- builtwith
- lxml

### AI

- Google Gemini API

### Reporting

- ReportLab

### Deployment

- Docker
- Render

---

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

Clone the repository

```bash
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
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

## 🔑 Environment Variables

Create a `.env` file in the project root.

```env
GEMINI_API_KEY=your_google_gemini_api_key

SHODAN_API_KEY=your_shodan_api_key
```

---

## ▶️ Run

```bash
python app.py
```

Visit

```
http://127.0.0.1:5000
```

---

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

SRM Institute of Science and Technology

GitHub:
https://github.com/Arshath5353

---

## ⭐ If you found this project useful

Please consider giving it a ⭐ on GitHub.
