"""
Phishing URL & Email Analyzer
--------------------------------
Analyzes a URL (or a block of email text containing URLs) for common
phishing red flags using heuristic rules, and returns a risk score with
human-readable explanations.

This is an educational/awareness tool - not a replacement for enterprise
email security. It's built around the kinds of red flags taught in
security-awareness training (mismatched domains, urgency keywords,
suspicious link structure, brand impersonation, etc.)

Usage:
    from phishing_checker import analyze_url, analyze_text

    result = analyze_url("http://paypa1-secure-login.tk/verify")
    result = analyze_text(email_body_text)
"""

import re
from urllib.parse import urlparse

# Well-known brands commonly impersonated in phishing attacks.
# Used to flag domains that look like a typo/lookalike of a trusted brand.
KNOWN_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook",
    "netflix", "bankofamerica", "chase", "wellsfargo", "instagram",
    "linkedin", "dhl", "fedex", "ups", "outlook", "office365", "dropbox",
]

# TLDs frequently abused in phishing campaigns (free/cheap registration).
SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work",
    ".click", ".loan", ".men", ".zip", ".review",
]

# Common URL shorteners - hide the real destination.
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly",
]

# Words that create urgency/fear - classic social engineering triggers.
URGENCY_KEYWORDS = [
    "verify your account", "urgent", "suspended", "act now", "confirm your identity",
    "unusual activity", "click here immediately", "limited time", "your account will be closed",
    "security alert", "password expires", "update your payment", "reset your password now",
]

URL_REGEX = re.compile(r"https?://[^\s<>\"']+")


def levenshtein_distance(a, b):
    """Simple edit-distance calculation, used for typosquat detection."""
    if len(a) < len(b):
        return levenshtein_distance(b, a)
    if len(b) == 0:
        return len(a)

    previous_row = range(len(b) + 1)
    for i, char_a in enumerate(a):
        current_row = [i + 1]
        for j, char_b in enumerate(b):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (char_a != char_b)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def analyze_url(url):
    """
    Analyze a single URL for phishing indicators.
    Returns a dict: {url, score (0-100), risk_level, reasons: [...]}
    """
    reasons = []
    score = 0

    url = url.strip()
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
    except ValueError:
        return {"url": url, "score": 100, "risk_level": "HIGH", "reasons": ["Malformed URL"]}

    domain = (parsed.netloc or "").lower()
    domain_no_port = domain.split(":")[0]
    full_url_lower = url.lower()

    # 1. IP address instead of domain name
    is_ip_address = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain_no_port))
    if is_ip_address:
        score += 30
        reasons.append("Uses a raw IP address instead of a domain name")

    # 2. '@' symbol in URL (browser ignores everything before it - classic trick)
    if "@" in url:
        score += 25
        reasons.append("Contains '@' symbol, which can hide the real destination")

    # 3. No HTTPS
    if parsed.scheme != "https":
        score += 10
        reasons.append("Does not use HTTPS encryption")

    # 4. Suspicious / cheap TLD
    if any(domain_no_port.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 20
        reasons.append(f"Uses a top-level domain often associated with abuse ({domain_no_port})")

    # 5. Excessive subdomains (e.g. secure.login.paypal.verify-account.com)
    subdomain_count = domain_no_port.count(".")
    if subdomain_count >= 3 and not is_ip_address:
        score += 15
        reasons.append("Unusually high number of subdomains")

    # 6. Excessive hyphens (e.g. paypal-account-verify-secure.com)
    if domain_no_port.count("-") >= 2:
        score += 10
        reasons.append("Domain contains multiple hyphens, common in lookalike domains")

    # 7. URL shortener
    if any(shortener in domain_no_port for shortener in URL_SHORTENERS):
        score += 15
        reasons.append("Uses a URL shortener, which hides the real destination")

    # 8. Brand impersonation / typosquatting check.
    # Checks the full first label AND each hyphen-separated chunk of it,
    # so "paypa1-secure-login.tk" is caught via the "paypa1" chunk, not just
    # the whole label.
    domain_root = domain_no_port.split(".")[0] if domain_no_port else ""
    chunks_to_check = {domain_root} | set(domain_root.split("-"))
    flagged_brand = None
    for brand in KNOWN_BRANDS:
        if brand == domain_root:
            continue  # exact match to the real brand's own domain, not flagged
        for chunk in chunks_to_check:
            if not chunk or brand == chunk:
                continue
            distance = levenshtein_distance(chunk, brand)
            if 0 < distance <= 2 and len(chunk) >= 4:
                flagged_brand = (brand, "typosquat")
                break
            if brand in domain_root and brand != domain_root:
                flagged_brand = (brand, "embedded")
                break
        if flagged_brand:
            break

    if flagged_brand:
        brand, kind = flagged_brand
        if kind == "typosquat":
            score += 30
            reasons.append(f"Domain closely resembles the brand '{brand}' (possible typosquat)")
        else:
            score += 20
            reasons.append(f"Brand name '{brand}' embedded in a different domain")

    # 9. Long, obfuscated-looking URL
    if len(url) > 90:
        score += 10
        reasons.append("Unusually long URL, often used to obscure the real destination")

    # 10. Urgency keywords in the URL path itself
    if any(word in full_url_lower for word in ["verify", "confirm", "secure", "update", "login", "account"]):
        score += 5
        reasons.append("URL path contains words commonly used in phishing links")

    score = min(score, 100)
    if score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    if not reasons:
        reasons.append("No common phishing indicators detected")

    return {"url": url, "score": score, "risk_level": risk_level, "reasons": reasons}


def analyze_text(text):
    """
    Analyze a block of text (e.g. pasted email body) for:
      - any URLs found within it (each analyzed individually)
      - urgency/social-engineering language in the text itself
    Returns a dict with 'urls' (list of analyze_url results) and
    'language_flags' (list of matched urgency phrases).
    """
    urls_found = URL_REGEX.findall(text)
    url_results = [analyze_url(u) for u in urls_found]

    text_lower = text.lower()
    language_flags = [phrase for phrase in URGENCY_KEYWORDS if phrase in text_lower]

    return {
        "urls": url_results,
        "language_flags": language_flags,
        "url_count": len(urls_found),
    }


if __name__ == "__main__":
    # Quick manual test / demo when run directly
    test_urls = [
        "https://www.google.com",
        "http://paypa1-secure-login.tk/verify-account",
        "http://192.168.1.55/login",
        "https://bit.ly/3xample",
        "https://accounts.google.com/signin",
    ]
    for test_url in test_urls:
        result = analyze_url(test_url)
        print(f"\nURL: {result['url']}")
        print(f"Risk: {result['risk_level']} (score: {result['score']})")
        for reason in result["reasons"]:
            print(f"  - {reason}")
