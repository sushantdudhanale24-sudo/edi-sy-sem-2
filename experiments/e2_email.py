"""E2 - Email: (a) content classifier on corpora, (b) authentication checks on a live set.

(a) python experiments/e2_email.py content --phish data/email/phishing.mbox --legit data/email/enron_ham/
    Nazario phishing corpus (mbox) + Enron or SpamAssassin ham (folder of raw messages).
(b) python experiments/e2_email.py auth --live data/email/live
    live/legit/*.eml : real messages you received (export from Gmail: More > Download message)
    live/spoof/*.eml : spoofed test messages your team sent FROM A DOMAIN YOU CONTROL to your own inbox
Outputs results/e2_email_content.json and results/e2_email_auth.json
"""
import argparse, glob, mailbox, os, sys, time, email
from email import policy
import numpy as np
from sklearn.model_selection import StratifiedKFold

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from phishsentry import email_analyzer as E, sms
from phishsentry.metrics import binary_metrics, mean_std, save_results, latency_summary


def load(path):
    if os.path.isdir(path):
        out = []
        for f in glob.glob(os.path.join(path, "**", "*"), recursive=True):
            if os.path.isfile(f):
                try: out.append(email.message_from_binary_file(open(f, "rb"), policy=policy.default))
                except Exception: pass
        return out
    return list(mailbox.mbox(path))


def content(a):
    ph = [E.body_text(m) for m in load(a.phish)]; lg = [E.body_text(m) for m in load(a.legit)]
    rs = np.random.RandomState(42)
    if len(lg) > a.max_legit: lg = list(rs.choice(lg, a.max_legit, replace=False))
    X = np.array(ph + lg, dtype=object); y = np.array([1] * len(ph) + [0] * len(lg))
    folds = {"heuristic": [], "naive_bayes": [], "stacked": []}
    for tr, te in StratifiedKFold(5, shuffle=True, random_state=42).split(X, y):
        nb = sms.NaiveBayesLayer().fit(X[tr], y[tr])
        h_tr = np.array([sms.heuristic_score(t) for t in X[tr]]); h_te = np.array([sms.heuristic_score(t) for t in X[te]])
        folds["heuristic"].append(binary_metrics(y[te], h_te, sms.tune_threshold(h_tr, y[tr])))
        folds["naive_bayes"].append(binary_metrics(y[te], nb.predict_proba(X[te])))
        st = sms.Stacker().fit({"heuristic": h_tr, "naive_bayes": nb.predict_proba(X[tr])}, X[tr], y[tr])
        folds["stacked"].append(binary_metrics(y[te], st.predict_proba({"heuristic": h_te, "naive_bayes": nb.predict_proba(X[te])}, X[te])))
    save_results("e2_email_content", {"n_phish": len(ph), "n_legit": len(lg),
                                      "summary": {k: mean_std(v) for k, v in folds.items()}})


def auth(a):
    rows = []
    for lab in ("legit", "spoof"):
        for f in glob.glob(os.path.join(a.live, lab, "*.eml")):
            m = E.parse_eml(open(f, "rb").read())
            t0 = time.perf_counter(); r = E.analyze(m); ms = (time.perf_counter() - t0) * 1000
            rows.append({"label": lab, **r["flags"], "flagged": r["flagged"], "ms": ms})
    if not rows: print("no .eml files under", a.live); return
    out = {}
    for c in list(E.AUTH_CHECKS) + ["flagged"]:
        sp = [r[c] for r in rows if r["label"] == "spoof"]; lg = [r[c] for r in rows if r["label"] == "legit"]
        out[c] = {"spoofs_caught_%": 100 * float(np.mean(sp)) if sp else None,
                  "false_alarms_%": 100 * float(np.mean(lg)) if lg else None}
    save_results("e2_email_auth", {"n_spoof": sum(r["label"] == "spoof" for r in rows),
                                   "n_legit": sum(r["label"] == "legit" for r in rows),
                                   "checks": out, "latency": latency_summary([r["ms"] for r in rows])})


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); sp = ap.add_subparsers(dest="cmd", required=True)
    c = sp.add_parser("content"); c.add_argument("--phish", required=True); c.add_argument("--legit", required=True)
    c.add_argument("--max-legit", type=int, default=5000)
    b = sp.add_parser("auth"); b.add_argument("--live", required=True)
    a = ap.parse_args(); content(a) if a.cmd == "content" else auth(a)
