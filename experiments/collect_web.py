"""Collect live phishing + legitimate page snapshots for E3-E6 (Paper B).

Run once a day for 1-2 weeks, on a machine with internet access:
    pip install playwright python-whois requests && playwright install chromium
    python experiments/collect_web.py --phish 150 --legit 150

Sources
  phishing     OpenPhish community feed (https://openphish.com/feed.txt), optionally a
               PhishTank CSV you downloaded (--phishtank-csv)
  legitimate   Tranco top-1M list (https://tranco-list.eu), sampled from ranks 1-100k so the
               set is not only famous sites
Each URL becomes data/web/<label>_<sha>/ with meta.json, page.html, shot.png.

Safety: pages are only loaded and screenshotted, never submitted to. Run inside a
VM or a throwaway user account. Do not click, type or download anything on them.
Optional: set GSB_API_KEY to record the Google Safe Browsing verdict at collection time.
"""
import argparse, datetime, hashlib, io, json, os, random, socket, ssl, sys, zipfile
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "data", "web")


def openphish():
    import requests
    return [u.strip() for u in requests.get("https://openphish.com/feed.txt", timeout=30).text.splitlines() if u.strip()]


def tranco(top=100000):
    import requests
    z = zipfile.ZipFile(io.BytesIO(requests.get("https://tranco-list.eu/top-1m.csv.zip", timeout=120).content))
    rows = z.read(z.namelist()[0]).decode().splitlines()[:top]
    return ["https://" + r.split(",")[1] for r in rows]


def ssl_info(host):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=8) as s, ctx.wrap_socket(s, server_hostname=host) as t:
            c = t.getpeercert()
        exp = datetime.datetime.strptime(c["notAfter"], "%b %d %H:%M:%S %Y %Z")
        issuer = dict(x[0] for x in c.get("issuer", []))
        return {"present": True, "valid": True, "days_to_expiry": (exp - datetime.datetime.utcnow()).days,
                "issuer": issuer.get("organizationName")}
    except ssl.SSLCertVerificationError as e:
        return {"present": True, "valid": False, "error": str(e)[:120]}
    except Exception:
        return {"present": False, "valid": False}


def domain_age(host):
    try:
        import whois
        w = whois.whois(host); c = w.creation_date
        c = c[0] if isinstance(c, list) else c
        return (datetime.datetime.utcnow() - c).days if c else None
    except Exception:
        return None


def gsb(url):
    key = os.environ.get("GSB_API_KEY")
    if not key: return None
    import requests
    body = {"client": {"clientId": "phishsentry-research", "clientVersion": "0.1"},
            "threatInfo": {"threatTypes": ["SOCIAL_ENGINEERING", "MALWARE"], "platformTypes": ["ANY_PLATFORM"],
                           "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}]}}
    r = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}", json=body, timeout=15)
    return bool(r.json().get("matches"))


def snapshot(page, url, label, source):
    sha = hashlib.sha256(url.encode()).hexdigest()[:16]
    folder = os.path.join(OUT, f"{'phish' if label else 'legit'}_{sha}")
    if os.path.exists(os.path.join(folder, "meta.json")): return False
    try:
        resp = page.goto(url, timeout=20000, wait_until="load")
        page.wait_for_timeout(2500)
        html = page.content(); final = page.url
        os.makedirs(folder, exist_ok=True)
        page.screenshot(path=os.path.join(folder, "shot.png"))
        open(os.path.join(folder, "page.html"), "w", encoding="utf-8").write(html)
    except Exception as e:
        return False
    host = urlparse(final).hostname or ""
    meta = {"url": url, "final_url": final, "label": label, "source": source,
            "http_status": resp.status if resp else None,
            "collected_at": datetime.datetime.utcnow().isoformat() + "Z",
            "ssl": ssl_info(host) if final.startswith("https") else {"present": False},
            "domain_age_days": domain_age(host), "blacklisted": gsb(url)}
    json.dump(meta, open(os.path.join(folder, "meta.json"), "w", encoding="utf-8"), indent=1)
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--phish", type=int, default=150); ap.add_argument("--legit", type=int, default=150)
    ap.add_argument("--phishtank-csv", default=None); ap.add_argument("--seed", type=int, default=None)
    a = ap.parse_args(); random.seed(a.seed)
    ph = openphish()
    if a.phishtank_csv:
        import csv
        ph += [r["url"] for r in csv.DictReader(open(a.phishtank_csv, encoding="utf-8"))]
    random.shuffle(ph); lg = tranco(); random.shuffle(lg)
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        b = p.chromium.launch(headless=True)
        ctx = b.new_context(viewport={"width": 1280, "height": 800}, accept_downloads=False,
                            java_script_enabled=True, ignore_https_errors=True)
        page = ctx.new_page()
        for urls, label, n, src in ((ph, 1, a.phish, "openphish"), (lg, 0, a.legit, "tranco")):
            got = 0
            for u in urls:
                if got >= n: break
                if snapshot(page, u, label, src):
                    got += 1; print(f"[{label}] {got}/{n} {u[:80]}")
        b.close()
    print("snapshots now in", OUT, ":", len(os.listdir(OUT)))


if __name__ == "__main__":
    sys.exit(main())
