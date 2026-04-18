def calculate_risk(vulns):
    """Calculates a risk score out of 100 based on vulnerability severity."""
    score = 0
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    
    weights = {
        "Critical": 40,
        "High": 25,
        "Medium": 10,
        "Low": 5,
        "Info": 0
    }
    
    for vuln in vulns:
        sev = vuln.get("severity", "Info")
        severity_counts[sev] += 1
        score += weights.get(sev, 0)
        
    # Cap score at 100
    final_score = min(score, 100)
    
    if final_score >= 70:
        level = "Critical"
    elif final_score >= 40:
        level = "High"
    elif final_score >= 15:
        level = "Medium"
    elif final_score > 0:
        level = "Low"
    else:
        level = "Secure"
        
    return final_score, level, severity_counts