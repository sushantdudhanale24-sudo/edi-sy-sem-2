"""Baselines the paper compares against.

  url_rf      Random Forest on lexical URL features (classic ML approach, cf. Sahingoz et al. 2019)
  blacklist   whether the URL was on Google Safe Browsing / PhishTank AT COLLECTION TIME
              (stored in meta.json by the collector); shows zero-day misses
"""
import re
from urllib.parse import urlparse
import numpy as np
from sklearn.ensemble import RandomForestClassifier


def url_features(url):
    u = urlparse(url if "://" in url else "http://" + url)
    host = u.hostname or ""; path = u.path or ""
    return [len(url), len(host), host.count("."), host.count("-"), url.count("@"), url.count("//"),
            sum(c.isdigit() for c in url), int(bool(re.fullmatch(r"[\d.]+", host))),
            int(u.scheme == "https"), len(path), path.count("/"), url.count("="), url.count("?"),
            int("xn--" in host), len(set(host)) / max(1, len(host))]


class URLRandomForest:
    def __init__(self, seed=42):
        self.m = RandomForestClassifier(n_estimators=300, random_state=seed, n_jobs=-1, class_weight="balanced")

    def fit(self, urls, y):
        self.m.fit(np.array([url_features(u) for u in urls]), y); return self

    def predict_proba(self, urls):
        return self.m.predict_proba(np.array([url_features(u) for u in urls]))[:, 1]


def blacklist_score(meta):
    v = meta.get("blacklisted")
    return np.nan if v is None else float(bool(v))
