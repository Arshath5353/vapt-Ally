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

# Ensure reports directory exists immediately
os.makedirs(REPORTS_DIR, exist_ok=True)

# =========================
# 📂 Load Scan History
# =========================
def load_history():
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
        with open(RESULTS_FILE, 'w') as f:
            json.dump(history, f, indent=4)
    except Exception as e:
        print("Error saving results:", e)

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
    clean_url = re.sub(r'^(?:https?://)+', '', raw_url.lower())
    
    # 2. Extract JUST the domain (removes paths like /login and ports like :8080)
    domain = clean_url.split('/')[0].split(':')[0]
    
    # 3. Build the final clean target URL
    target_url = 'http://' + domain

    # 4. Strip 'www.' to get the root domain so subdomains resolve correctly
    root_domain = domain[4:] if domain.startswith('www.') else domain

    try:
        # =========================
        # ⚙️ Execute Modules
        # =========================
        recon_data = perform_recon(target_url) or {}
        crawl_data = crawl_website(target_url) or []
        vuln_data = scan_vulnerabilities(target_url) or []
        subdomain_data = find_subdomains(root_domain) or []

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
            }
        }

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