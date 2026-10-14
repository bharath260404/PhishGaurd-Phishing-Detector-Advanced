SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "bank", "confirm", "free", "bonus"
]

def java_check(url):
    lower = url.lower()
    score = 0.0
    reasons = []
    
    # long URL
    length = len(url)
    if length > 75:
        score += 2.0
        reasons.append("Long URL (>75 chars)")
    elif length > 50:
        score += 1.0
        reasons.append("Moderately long URL (50-75 chars)")
    
    # @ symbol
    if "@" in lower:
        score += 3.0
        reasons.append("'@' symbol present")
    
    # HTTPS
    if not lower.startswith("https://"):
        score += 1.5
        reasons.append("No HTTPS prefix")
    else:
        score -= 0.5
    
    # IP address
    def has_ip(s):
        for p in s.split("/"):
            if __import__("re").match(r"\d+\.\d+\.\d+\.\d+(:\d+)?", p):
                return True
        return False
    if has_ip(lower):
        score += 3.0
        reasons.append("IP address instead of domain")
    
    # Keywords
    kw = 0
    for k in SUSPICIOUS_KEYWORDS:
        if k in lower:
            kw += 1
            reasons.append(f"Suspicious word: '{k}'")
    score += min(3, kw) * 1.0
    
    # Dots
    dots = lower.count(".")
    if dots > 3:
        score += 0.5
        reasons.append("Many subdomains")
    
    if score >= 6.0:
        risk = "HIGH"
    elif score >= 3.0:
        risk = "MEDIUM"
    else:
        risk = "LOW"
    
    return {
        "url": url,
        "score": round(score, 1),
        "risk": risk,
        "reasons": reasons if reasons else ["No obvious heuristic issues"],
        "label": "HIGH RISK" if risk == "HIGH" else ("MEDIUM RISK" if risk == "MEDIUM" else "LOW RISK"),
        "color": "#ef4444" if risk == "HIGH" else ("#f59e0b" if risk == "MEDIUM" else "#22c55e"),
    }