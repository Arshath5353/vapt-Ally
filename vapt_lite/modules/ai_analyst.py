import os
from dotenv import load_dotenv
from google import genai

# -----------------------------
# Load API Key
# -----------------------------
load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")

if not API_KEY:
    raise RuntimeError(
        "GEMINI_API_KEY not found.\n"
        "Create a .env file containing:\n"
        "GEMINI_API_KEY=YOUR_API_KEY"
    )

client = genai.Client(api_key=API_KEY)

# Try models in order until one works.
# Update this list over time if Google changes model availability.
MODELS = [
    "gemini-2.5-flash-lite",
    "gemini-flash-latest",
    "gemini-3.5-flash",
    "gemini-3.1-flash-lite",
    "gemini-2.0-flash",
]


def generate_summary(scan):
    findings = scan.get("vulnerabilities", [])

    if findings:
        findings_text = ""

        for i, finding in enumerate(findings, start=1):
            findings_text += f"""
Finding {i}
Title: {finding.get("type", "Unknown")}
Severity: {finding.get("severity", "Unknown")}
URL: {finding.get("url", "N/A")}
Description: {finding.get("description", "")}
Evidence: {finding.get("evidence", "")}

"""
    else:
        findings_text = "No vulnerabilities detected."

    prompt = f"""
You are a Senior Penetration Tester and Security Consultant.

Analyze the following VAPT scan.

Target:
{scan.get("target")}

Risk Score:
{scan.get("risk", {}).get("score")}

Risk Level:
{scan.get("risk", {}).get("level")}

Technology Stack:
{scan.get("recon", {}).get("tech_stack")}

Discovered Subdomains:
{scan.get("subdomains")}

Findings:

{findings_text}

Generate a professional security assessment.

Include:

# Executive Summary

# Overall Security Posture

# Attack Surface Summary

# Highest Priority Findings

# Business Impact

# OWASP Top 10 Mapping

# Immediate Remediation

# Long-Term Recommendations

Rules:

- Only analyze the supplied findings.
- Do NOT invent vulnerabilities.
- Be concise.
- Return Markdown.
"""

    last_error = None

    for model_name in MODELS:
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=prompt,
            )

            if response.text:
                return response.text

        except Exception as e:
            last_error = str(e)
            continue

    if last_error:

        if "RESOURCE_EXHAUSTED" in last_error or "429" in last_error:
            return (
                "⚠️ Gemini API quota exceeded.\n\n"
                "The vulnerability scan completed successfully, "
                "but the AI summary could not be generated."
            )

        if "404" in last_error or "NOT_FOUND" in last_error:
            return (
                "⚠️ None of the configured Gemini models are currently available.\n"
                "Please verify your project's available models or update the "
                "MODELS list in ai_analyst.py."
            )

        return f"AI analysis failed:\n\n{last_error}"

    return "No AI response generated."