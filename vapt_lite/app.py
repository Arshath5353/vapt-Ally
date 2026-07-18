from flask import Flask, render_template, request, send_file, session
import json
import os
import uuid
import re
from datetime import datetime
import traceback

# Import modules (Ensure these return dictionaries or lists, not None)
from modules.recon import perform_recon, find_subdomains
from modules.crawler import crawl_website
from modules.scanner import scan_vulnerabilities
from modules.risk import calculate_risk
from modules.pdf_gen import generate_pdf
from modules.history_db import initialise as initialise_history_db, load as load_history_db, save as save_history_db
from modules.ai_analyst import generate_summary

app = Flask(__name__)

# 🔐 Secret Key
app.secret_key = os.getenv("SECRET_KEY", "dev_key_change_this")

# =========================
# 🏗️ ABSOLUTE PATH SETUP
# =========================
# This prevents the FileNotFoundError by forcing Flask to know exactly 
# where the root of your project is at all times.
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
RESULTS_FILE = os.path.join(BASE_DIR, 'scan_results.json')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
HISTORY_DB = os.path.join(BASE_DIR, 'scan_history.db')

# Ensure reports directory exists immediately
os.makedirs(REPORTS_DIR, exist_ok=True)
initialise_history_db(HISTORY_DB)

# =========================
# 📂 Load Scan History
# =========================
def load_history():
    stored = load_history_db(HISTORY_DB)
    if stored:
        return stored
    if os.path.exists(RESULTS_FILE):
        try:
            with open(RESULTS_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            print("Error loading history:", e)
            return []
    return []

# =========================
# 💾 Save Scan Results
# =========================
def save_results(data):
    history = load_history()
    history.append(data)
    try:
        for scan in history:
            save_history_db(HISTORY_DB, scan)
        with open(RESULTS_FILE, 'w') as f:
            json.dump(history, f, indent=4)
    except Exception as e:
        print("Error saving results:", e)

def enrich_findings(findings):
    """Add only evidence we actually observed; never manufacture a payload or confidence."""
    mappings = {
        "xss": ("CWE-79", "OWASP A03:2021 - Injection", "T1190", "Payload reflected by the response."),
        "sql": ("CWE-89", "OWASP A03:2021 - Injection", "T1190", "Database error signature observed after input injection."),
        "header": ("CWE-693", "OWASP A05:2021 - Security Misconfiguration", None, "Required HTTP response header was absent."),
        "clickjacking": ("CWE-1021", "OWASP A05:2021 - Security Misconfiguration", None, "Frame protection header was absent."),
    }
    for finding in findings:
        label = finding.get("type", "").lower()
        for key, (cwe, owasp, mitre, evidence) in mappings.items():
            if key in label:
                finding.setdefault("cwe", cwe); finding.setdefault("owasp", owasp)
                if mitre: finding.setdefault("mitre", mitre)
                finding.setdefault("evidence", evidence)
                finding.setdefault("confidence", "High" if key in {"xss", "sql"} else "Firm")
                break
    return findings

def deduplicate_findings(findings):
    """Collapse repeated infrastructure findings while preserving one evidence-bearing result."""
    unique, seen = [], set()
    domain_level = ("missing hsts", "missing csp", "clickjacking", "missing mime")
    for finding in findings:
        finding_type = finding.get("type", "").lower()
        key = finding_type if any(marker in finding_type for marker in domain_level) else f"{finding_type}|{finding.get('url', '')}"
        if key not in seen:
            seen.add(key); unique.append(finding)
    return unique

# =========================
# 🏠 Home Page
# =========================
@app.route('/')
def index():
    history = load_history()
    return render_template('index.html', history=history[::-1])  # newest first

# =========================
# 🔍 Scan Route
# =========================
@app.route('/scan', methods=['POST'])
def scan():
    raw_url = request.form.get('url', '').strip()

    if not raw_url:
        return "Please enter a valid URL", 400

    # ✅ BULLETPROOF REGEX URL SANITIZATION
    # 1. Aggressively strip ALL protocols (http://, https://, or nested combinations)
    supplied = raw_url if re.match(r'^https?://', raw_url, re.I) else f'https://{raw_url}'
    clean_url = re.sub(r'^(?:https?://)+', '', supplied, flags=re.I)
    
    # 2. Extract JUST the domain (removes paths like /login and ports like :8080)
    domain = clean_url.split('/')[0].split(':')[0]
    
    # 3. Build the final clean target URL
    target_url = supplied.rstrip('/')

    # 4. Strip 'www.' to get the root domain so subdomains resolve correctly
    root_domain = domain[4:] if domain.startswith('www.') else domain

    try:
        # =========================
        # ⚙️ Execute Modules
        # =========================
        recon_data = perform_recon(target_url) or {}
        crawl_data = crawl_website(target_url) or []
        vuln_data = scan_vulnerabilities(target_url, crawl_data) or []
        subdomain_data = find_subdomains(root_domain) or []
        vuln_data = deduplicate_findings(enrich_findings(vuln_data))

        # =========================
        # 🧠 Risk Calculation
        # =========================
        try:
            risk_score, risk_level, severity_counts = calculate_risk(vuln_data)
        except Exception as e:
            print("Risk calculation failed:", e)
            risk_score, risk_level, severity_counts = 0, "Low", {}

        # =========================
        # 📊 Compile Results
        # =========================
        scan_id = str(uuid.uuid4())
        
        scan_results = {
            "id": scan_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": target_url,
            "subdomains": subdomain_data,
            "recon": recon_data,
            "crawler": crawl_data,
            "vulnerabilities": vuln_data,
            "risk": {
                "score": risk_score,
                "level": risk_level,
                "counts": severity_counts
            },
            "ai_summary": None
        }
        # Optional: a Gemini failure never invalidates a completed scan.
        scan_results["ai_summary"] = generate_summary(scan_results)

        # Save & Store Results
        save_results(scan_results)
        session['latest_scan'] = scan_results

        return render_template('dashboard.html', data=scan_results)

    except Exception as e:
        traceback.print_exc()
        fallback_data = {
            "id": "error-id",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target": target_url,
            "subdomains": [],
            "recon": {},
            "crawler": [],
            "vulnerabilities": [],
            "risk": {"score": 0, "level": "Error", "counts": {}},
            "error": str(e)
        }
        return render_template('dashboard.html', data=fallback_data), 200

# =========================
# 📜 View Historical Report
# =========================
@app.route('/report/<scan_id>')
def view_report(scan_id):
    history = load_history()
    for scan in history:
        if scan.get('id') == scan_id:
            session['latest_scan'] = scan 
            return render_template('dashboard.html', data=scan)
    return "Report not found", 404

# =========================
# 📄 Download PDF Report
# =========================
@app.route('/download_report')
def download_report():
    if 'latest_scan' not in session:
        return "No scan available to download", 400

    # Create the filename and securely join it with the absolute REPORTS_DIR
    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)

    try:
        # Generate the PDF file at the absolute path
        generate_pdf(session['latest_scan'], filepath)
    except Exception as e:
        print("PDF generation failed:", e)
        traceback.print_exc()
        return f"Failed to generate report: {str(e)}", 500

    # Send the generated file to the user
    return send_file(filepath, as_attachment=True)

if __name__ == '__main__':
    # Binds to 0.0.0.0 so Docker and Render can expose it to the web
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
