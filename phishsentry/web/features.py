"""Website analyzers that run on a saved page snapshot.

A snapshot is a folder written by experiments/collect_web.py:
    meta.json   url, final_url, label (1 phishing / 0 legitimate), collected_at,
                ssl {present, valid, days_to_expiry, issuer}, domain_age_days,
                blacklisted (Safe Browsing / PhishTank verdict at collection time)
    page.html   DOM after JavaScript ran (Playwright, Chromium)
    shot.png    full-viewport screenshot (used by the vision-LLM analyzer)

Analyzing a frozen snapshot (not the live URL) makes every experiment
repeatable, even after the phishing page has been taken down.

Each analyzer returns a list of Signal(name, weight, category, detail).
Weights >= CRITICAL_MIN are "critical" in the aggregation engine.
"""
import json, math, os, re
from dataclasses import dataclass, asdict
from urllib.parse import urlparse
from bs4 import BeautifulSoup


@dataclass
class Signal:
    name: str
    weight: float
    category: str
    detail: str = ""


SUSPICIOUS_TLDS = {"xyz", "top", "club", "online", "site", "live", "icu", "buzz", "monster", "rest",
                   "click", "link", "work", "fit", "cf", "ga", "gq", "ml", "tk", "zip", "mov"}
BRANDS = ["paypal", "apple", "microsoft", "office365", "outlook", "google", "amazon", "netflix", "facebook",
          "instagram", "whatsapp", "linkedin", "dhl", "fedex", "sbi", "hdfc", "icici", "axisbank", "paytm",
          "phonepe", "airtel", "jio", "irctc", "incometax", "flipkart", "chase", "wellsfargo", "dropbox", "adobe"]
CRED_WORDS = re.compile(r"\b(password|passcode|otp|one[- ]time|cvv|card number|ssn|aadhaa?r|pan number|login|sign in|verify)\b", re.I)


def levenshtein(a, b):
    if len(a) < len(b): a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def registered_domain(host):
    parts = host.lower().split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "net", "org", "gov", "ac", "edu") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def entropy(s):
    if not s: return 0.0
    p = [s.count(c) / len(s) for c in set(s)]
    return -sum(x * math.log2(x) for x in p)


# ------------------------------------------------------------------ analyzers
def analyze_url(url):
    u = urlparse(url if "://" in url else "http://" + url)
    host = (u.hostname or "").lower(); sig = []
    if re.fullmatch(r"[\d.]+", host): sig.append(Signal("ip_host", 0.20, "url", host))
    if len(url) > 75: sig.append(Signal("long_url", 0.05, "url", f"{len(url)} chars"))
    if host.count(".") >= 4: sig.append(Signal("many_subdomains", 0.05, "url", host))
    if "@" in url: sig.append(Signal("at_symbol", 0.10, "url"))
    if host.split(".")[-1] in SUSPICIOUS_TLDS: sig.append(Signal("suspicious_tld", 0.05, "url", host.split(".")[-1]))
    if "xn--" in host: sig.append(Signal("punycode", 0.15, "url", host))
    if host.count("-") >= 3: sig.append(Signal("many_hyphens", 0.05, "url", host))
    if entropy(host.replace(".", "")) > 4.0: sig.append(Signal("random_looking_host", 0.05, "url"))
    return sig


def analyze_typosquat(url):
    host = (urlparse(url if "://" in url else "http://" + url).hostname or "").lower()
    reg = registered_domain(host); label = reg.split(".")[0]; sig = []
    if label in BRANDS:  # the brand's own registered domain
        return []
    tokens = [label] + [t for t in re.split(r"[-_]", label) if len(t) >= 4]
    for b in BRANDS:
        if any(levenshtein(t, b) in (1, 2) for t in tokens if abs(len(t) - len(b)) <= 2):
            sig.append(Signal("typosquatting", 0.25, "domain", f"{label} ~ {b}")); break
        if b in label:  # combo-squatting, e.g. paypal-secure-login
            sig.append(Signal("brand_combosquatting", 0.20, "domain", f"{b} inside {label}")); break
        if b in host:   # brand only in a subdomain, e.g. paypal.example-login.com
            sig.append(Signal("brand_in_subdomain", 0.20, "domain", f"{b} in {host}")); break
    return sig


def analyze_domain(meta):
    sig = []; age = meta.get("domain_age_days")
    if age is not None and age < 30: sig.append(Signal("new_domain", 0.20, "domain", f"{age} days old"))
    elif age is not None and age < 180: sig.append(Signal("young_domain", 0.05, "domain", f"{age} days old"))
    return sig


def analyze_ssl(meta):
    s = meta.get("ssl") or {}; sig = []
    if not s.get("present", False): sig.append(Signal("no_https", 0.10, "ssl"))
    elif not s.get("valid", True): sig.append(Signal("invalid_certificate", 0.20, "ssl", s.get("error", "")))
    elif s.get("days_to_expiry") is not None and s["days_to_expiry"] < 0:
        sig.append(Signal("expired_certificate", 0.20, "ssl"))
    return sig


def analyze_forms(soup, url):
    host = registered_domain(urlparse(url).hostname or ""); sig = []
    forms = soup.find_all("form")
    pw = soup.find_all("input", {"type": re.compile("password", re.I)})
    if pw: sig.append(Signal("password_field", 0.05, "forms", f"{len(pw)} field(s)"))
    for f in forms:
        act = (f.get("action") or "").strip()
        if act.startswith("http"):
            dest = registered_domain(urlparse(act).hostname or "")
            if dest and dest != host:
                sig.append(Signal("external_form_submission", 0.25, "forms", f"posts to {dest}")); break
        if act.startswith("mailto:"):
            sig.append(Signal("form_to_email", 0.20, "forms")); break
    return sig


def analyze_scripts_iframes(soup, html):
    sig = []
    for fr in soup.find_all("iframe"):
        st = (fr.get("style") or "").replace(" ", "").lower()
        if "display:none" in st or fr.get("width") in ("0", "1") or fr.get("height") in ("0", "1"):
            sig.append(Signal("hidden_iframe", 0.15, "scripts")); break
    if re.search(r"\b(eval\(|unescape\(|atob\(|fromCharCode)", html):
        sig.append(Signal("obfuscated_script", 0.10, "scripts"))
    if re.search(r"(document\.onkeydown|event\.button\s*==\s*2|contextmenu)", html):
        sig.append(Signal("disables_right_click_or_keys", 0.05, "scripts"))
    return sig


def analyze_links(soup, url):
    host = registered_domain(urlparse(url).hostname or "")
    hrefs = [a.get("href", "") for a in soup.find_all("a")]
    if not hrefs: return [Signal("no_links", 0.05, "links")]
    ext = [h for h in hrefs if h.startswith("http") and registered_domain(urlparse(h).hostname or "") != host]
    null = [h for h in hrefs if h in ("#", "", "javascript:void(0)", "javascript:void(0);")]
    sig = []
    if len(null) / len(hrefs) > 0.5: sig.append(Signal("mostly_empty_links", 0.10, "links", f"{len(null)}/{len(hrefs)}"))
    if len(ext) / len(hrefs) > 0.7: sig.append(Signal("link_divergence", 0.10, "links", f"{len(ext)}/{len(hrefs)} external"))
    return sig


def analyze_content(soup, url):
    text = soup.get_text(" ", strip=True)[:20000]; sig = []
    title = (soup.title.string if soup.title and soup.title.string else "").lower()
    host = (urlparse(url).hostname or "").lower()
    for b in BRANDS:
        if b in title and b not in host:
            sig.append(Signal("brand_title_mismatch", 0.20, "content", f"title mentions {b}")); break
    if len(CRED_WORDS.findall(text)) >= 3: sig.append(Signal("credential_language", 0.05, "content"))
    if not re.search(r"(privacy|terms|contact|about)", text, re.I):
        sig.append(Signal("no_legal_pages", 0.05, "legal"))
    return sig


ANALYZERS = {
    "url": lambda s, h, m, u: analyze_url(u),
    "typosquat": lambda s, h, m, u: analyze_typosquat(u),
    "domain": lambda s, h, m, u: analyze_domain(m),
    "ssl": lambda s, h, m, u: analyze_ssl(m),
    "forms": lambda s, h, m, u: analyze_forms(s, u),
    "scripts": lambda s, h, m, u: analyze_scripts_iframes(s, h),
    "links": lambda s, h, m, u: analyze_links(s, u),
    "content": lambda s, h, m, u: analyze_content(s, u),
}


def load_snapshot(folder):
    with open(os.path.join(folder, "meta.json"), encoding="utf-8") as f:
        meta = json.load(f)
    p = os.path.join(folder, "page.html")
    html = open(p, encoding="utf-8", errors="ignore").read() if os.path.exists(p) else ""
    return meta, html


def analyze_snapshot(folder, disabled=()):
    meta, html = load_snapshot(folder)
    url = meta.get("final_url") or meta["url"]
    soup = BeautifulSoup(html, "html.parser")
    signals = []
    for name, fn in ANALYZERS.items():
        if name not in disabled:
            signals += fn(soup, html, meta, url)
    return meta, signals


def signals_to_dict(signals):
    return [asdict(s) for s in signals]
