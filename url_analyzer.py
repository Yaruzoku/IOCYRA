import ipaddress
import os
from urllib.parse import urlparse

import vt
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")

SUSPICIOUS_KEYWORDS = {
    "verify": 10,
    "verification": 10,
    "password": 15,
    "credential": 15,
    "wallet": 10,
    "payment": 10,
    "signin": 5,
    "download": 5,
}

def is_ip_address(hostname):
    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False

def find_suspicious_keywords(url):
    found_keywords = []

    url_lower = url.lower()

    for keyword, weight in SUSPICIOUS_KEYWORDS.items():
        if keyword in url_lower:
            found_keywords.append({
                "keyword": keyword,
                "weight": weight
            })

    return found_keywords

def has_suspicious_characters(url):
    return "@" in url

def has_punycode(hostname):
    if not hostname:
        return False

    return "xn--" in hostname.lower()

def has_non_standard_port(parsed):
    if parsed.port is None:
        return False

    standard_ports = {
        "http": 80,
        "https": 443,
    }

    return parsed.port != standard_ports.get(parsed.scheme.lower())

def count_subdomains(hostname):
    if not hostname:
        return 0

    parts = hostname.split(".")

    if len(parts) <= 2:
        return 0

    return len(parts) - 2

def count_encoded_characters(url):
    return url.count("%")

def has_excessive_encoding(url):
    return url.count("%") >= 5

def has_repeated_slashes(url):
    return "//" in urlparse(url).path

def check_virustotal(url):
    client = vt.Client(VT_API_KEY)

    try:
        url_id = vt.url_id(url)
        url_object = client.get_object(f"/urls/{url_id}")

        stats = url_object.last_analysis_stats

        detected = stats.get("malicious", 0) + stats.get("suspicious", 0)

        total_engines = (
            stats.get("malicious", 0)
            + stats.get("suspicious", 0)
            + stats.get("harmless", 0)
            + stats.get("undetected", 0)
        )

        detection_ratio = f"{detected}/{total_engines}"

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "detected": detected,
            "detection_ratio": detection_ratio,
        }

    except vt.error.APIError as error:
        error_type = error.args[0] if error.args else "UnknownError"

        if error_type == "NotFoundError":
            return None

        if error_type in {"QuotaExceededError", "TooManyRequestsError"}:
            return {
                "error": "VirusTotal API quota or rate limit reached."
            }

        if error_type in {"WrongCredentialsError", "AuthenticationRequiredError"}:
            return {
                "error": "VirusTotal API authentication failed."
            }

        return {
            "error": f"VirusTotal API error: {error_type}"
        }

    finally:
        client.close()

def validate_url(url):
    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        return False

    if not parsed.hostname:
        return False

    return True

def analyze_url(url):
    parsed = urlparse(url)

    uses_https = parsed.scheme.lower() == "https"
    is_ip = is_ip_address(parsed.hostname)
    url_length = len(url)
    is_long = url_length > 100
    suspicious_keywords = find_suspicious_keywords(url)
    has_suspicious_chars = has_suspicious_characters(url)
    has_punycode_domain = has_punycode(parsed.hostname)
    has_non_standard = has_non_standard_port(parsed)
    subdomain_count = count_subdomains(parsed.hostname)
    encoded_character_count = count_encoded_characters(url)
    has_excessive_encoded_chars = has_excessive_encoding(url)
    has_repeated_slashes_found = has_repeated_slashes(url)

    return {
        "url": url,
        "scheme": parsed.scheme,
        "hostname": parsed.hostname,
        "uses_https": uses_https,
        "is_ip_address": is_ip,
        "url_length": url_length,
        "is_long": is_long,
        "suspicious_keywords": suspicious_keywords,
        "has_suspicious_characters": has_suspicious_chars,
        "has_punycode": has_punycode_domain,
        "has_non_standard_port": has_non_standard,
        "subdomain_count": subdomain_count,
        "encoded_character_count": encoded_character_count,
        "has_excessive_encoding": has_excessive_encoded_chars,
        "has_repeated_slashes": has_repeated_slashes_found,
    }

def calculate_risk_score(analysis):
    score = 0
    findings = []

    if analysis["is_ip_address"]:
        score += 25
        findings.append("Uses an IP address instead of a domain (+25)")

    if analysis["is_long"]:
        score += 10
        findings.append("Unusually long URL (+10)")

    if analysis["has_suspicious_characters"]:
        score += 15
        findings.append("Contains @ character (+15)")

    if analysis["has_punycode"]:
        score += 10
        findings.append("Contains a Punycode domain (+10)")

    if analysis["has_non_standard_port"]:
        score += 10
        findings.append("Uses a non-standard port (+10)")

    if not analysis["uses_https"]:
        score += 5
        findings.append("Uses HTTP instead of HTTPS (+5)")

    if analysis["subdomain_count"] >= 3:
        score += 10
        findings.append(
            f"Uses multiple subdomains ({analysis['subdomain_count']}) (+10)"

        )

    if analysis["has_excessive_encoding"]:
        score += 10
        findings.append(
            f"Excessive URL encoding ({analysis['encoded_character_count']} encoded characters) (+10)"
        )

    if analysis["has_repeated_slashes"]:
        score += 5
        findings.append("Contains repeated slashes (+5)")

    for finding in analysis["suspicious_keywords"]:
        score += finding["weight"]
        findings.append(
            f"Suspicious keyword: {finding['keyword']} (+{finding['weight']})"
        )

    score = min(score, 100)

    return score, findings

def get_verdict(score):
    if score < 25:
        return "Low Risk"
    elif score < 50:
        return "Caution"
    elif score < 75:
        return "Suspicious"
    else:
        return "High Risk"

def analyze(url):
    url = normalize_url(url)

    if not validate_url(url):
        raise ValueError("Invalid URL")

    analysis = analyze_url(url)
    score, findings = calculate_risk_score(analysis)
    verdict = get_verdict(score)

    return {
        "url": url,
        "score": score,
        "verdict": verdict,
        "findings": findings,
        "analysis": analysis,
    }

def normalize_url(url):
    return url.strip()

def print_report(result):
    print("Maltrace URL Analysis")
    print("---------------------")
    print("Risk Score:", result["score"])
    print("Verdict:", result["verdict"])
    print("Findings:")

    if result["findings"]:
        for finding in result["findings"]:
            print("-", finding)
    else:
        print("- No suspicious indicators detected")

if __name__ == "__main__":
    result = analyze("https://example.com/login")
    print_report(result)

    stats = check_virustotal(result["url"])

    print()
    print("VirusTotal:")

    if stats is None:
        print("Unavailable - URL has not been analyzed by VirusTotal.")
    elif "error" in stats:
        print("Unavailable -", stats["error"])
    else:
        print("Detection ratio:", stats["detection_ratio"])
        print("Malicious:", stats["malicious"])
        print("Suspicious:", stats["suspicious"])