"""Smoke tests: the code runs end to end on tiny synthetic inputs.

These fake inputs are ONLY for checking the code. Never report their numbers.
Results are redirected to a temp folder so real results/ files are never touched.
    python -m pytest -q tests
"""
import json, os, subprocess, sys
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from phishsentry import sms, email_analyzer as E
from phishsentry.web import features as F, aggregate as A


def test_sms_explain():
    X = ["URGENT your SBI account is blocked, verify KYC at bit.ly/x1 now"] * 30 + ["see you at 5 for the project"] * 60
    y = np.array([1] * 30 + [0] * 60)
    m = sms.SMSEnsemble().fit(X, y)
    e = m.explain(X[0])
    assert e["label"] == "phishing" and "urgency" in e["detectors_fired"]


def test_email_auth():
    raw = (b"From: hr@vit.edu\nReturn-Path: <x@evil.test>\n"
           b"Authentication-Results: mx.google.com; spf=fail; dkim=none; dmarc=fail\nSubject: pay\n\nurgent")
    r = E.analyze(E.parse_eml(raw))
    assert r["flagged"] and r["flags"]["align"] and r["flags"]["dmarc"]


def _snap(d, url, label, html, ssl_ok=True, age=900):
    os.makedirs(d, exist_ok=True)
    json.dump({"url": url, "final_url": url, "label": label, "ssl": {"present": True, "valid": ssl_ok},
               "domain_age_days": age, "blacklisted": None}, open(os.path.join(d, "meta.json"), "w"))
    open(os.path.join(d, "page.html"), "w").write(html)


def test_web_pipeline(tmp_path):
    web = tmp_path / "web"
    for i in range(25):
        _snap(str(web / f"phish_{i}"), f"http://paypa1-secure-login{i}.xyz/verify", 1,
              '<title>PayPal login</title><form action="http://collect-data.top/p"><input type="password"></form>'
              '<a href="#">x</a><a href="#">y</a>', ssl_ok=False, age=3)
        _snap(str(web / f"legit_{i}"), f"https://example{i}.com/", 0,
              '<title>Example</title><a href="/about">About</a><a href="/privacy">Privacy</a><p>contact us</p>')
    meta, sig = F.analyze_snapshot(str(web / "phish_0"))
    names = {s.name for s in sig}
    assert {"typosquatting", "external_form_submission", "new_domain"} <= names
    assert A.trust_score(sig) < A.DEFAULT.suspicious
    env = dict(os.environ, PHISHSENTRY_WEB_DIR=str(web), PHISHSENTRY_RESULTS_DIR=str(tmp_path / "res"),
               PHISHSENTRY_FIG_DIR=str(tmp_path))
    subprocess.run([sys.executable, os.path.join(ROOT, "experiments", "e3_e4_e6_web.py")], env=env, check=True)
    r = json.load(open(tmp_path / "res" / "e3_web.json"))
    assert "ablation" in r and r["n"] == 50
