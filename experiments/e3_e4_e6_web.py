"""E3 (detection vs baselines + ablation), E4 (aggregation vs additive, constant
tuning, sensitivity) and E6 (latency) on collected website snapshots.

    python experiments/e3_e4_e6_web.py              # uses data/web/*
Outputs results/e3_web.json, results/e4_aggregation.json, papers/figures/fig_sensitivity.png
Constants are tuned on a validation split (first 30% of a stratified split); every
reported number comes from the held-out test split.
"""
import glob, itertools, json, os, sys, time
import numpy as np
from sklearn.model_selection import train_test_split, StratifiedKFold

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from phishsentry.web import features as F, aggregate as A
from phishsentry.baselines import URLRandomForest, blacklist_score
from phishsentry.metrics import binary_metrics, save_results, latency_summary


def load_all():
    rows = []
    for d in sorted(glob.glob(os.path.join(os.environ.get("PHISHSENTRY_WEB_DIR") or os.path.join(ROOT, "data", "web"), "*"))):
        if os.path.exists(os.path.join(d, "meta.json")):
            t0 = time.perf_counter(); meta, sig = F.analyze_snapshot(d); ms = (time.perf_counter() - t0) * 1000
            rows.append({"dir": d, "meta": meta, "signals": sig, "y": int(meta["label"]), "ms": ms})
    return rows


def prob(rows, p=A.DEFAULT, additive=False, disabled=()):
    out = []
    for r in rows:
        sig = r["signals"] if not disabled else F.analyze_snapshot(r["dir"], disabled)[1]
        t = A.additive_trust(sig) if additive else A.trust_score(sig, p)
        out.append(A.phishing_probability(t))
    return np.array(out)


def tune(val, y):
    """Grid-search the aggregation constants on validation data by F1 at the 'suspicious' cut-off."""
    best, bp = -1, A.DEFAULT
    for cm, sc, ex, de in itertools.product([0.10, 0.15, 0.20], [0.5, 0.7, 0.9], [0.5, 0.75, 1.0], [0.93, 0.95, 0.97]):
        p = A.with_params(critical_min=cm, scale=sc, exponent=ex, decay=de)
        thr = 1 - p.suspicious / 100
        f = binary_metrics(y, prob(val, p), thr)["f1"]
        if f > best: best, bp = f, p
    return bp


def main():
    rows = load_all(); y = np.array([r["y"] for r in rows])
    if len(rows) < 40 or y.min() == y.max():
        print(f"Need snapshots of both classes in data/web (found {len(rows)}). Run collect_web.py first."); return
    idx = np.arange(len(rows))
    val_i, test_i = train_test_split(idx, test_size=0.7, stratify=y, random_state=42)
    val = [rows[i] for i in val_i]; test = [rows[i] for i in test_i]; yv, yt = y[val_i], y[test_i]
    p = tune(val, yv); thr = 1 - p.suspicious / 100

    res = {"n": len(rows), "n_phish": int(y.sum()), "n_legit": int(len(y) - y.sum()),
           "n_test": len(test), "tuned_params": p.__dict__}
    res["phishsentry"] = binary_metrics(yt, prob(test, p), thr)
    res["phishsentry_default_constants"] = binary_metrics(yt, prob(test), 1 - A.DEFAULT.suspicious / 100)
    res["additive_baseline"] = binary_metrics(yt, prob(test, additive=True), thr)

    # URL Random Forest baseline: trained on the validation part only (no test leakage)
    urls = lambda rs: [r["meta"].get("final_url") or r["meta"]["url"] for r in rs]
    rf = URLRandomForest().fit(urls(val), yv)
    res["url_random_forest"] = binary_metrics(yt, rf.predict_proba(urls(test)))
    bl = np.array([blacklist_score(r["meta"]) for r in test])
    if not np.isnan(bl).all():
        m = ~np.isnan(bl); res["blacklist_at_collection"] = binary_metrics(yt[m], bl[m]) | {"n": int(m.sum())}

    # ablation: drop one analyzer at a time
    full = res["phishsentry"]["f1"]
    res["ablation"] = {}
    for name in F.ANALYZERS:
        m = binary_metrics(yt, prob(test, p, disabled=(name,)), thr)
        res["ablation"][name] = {"f1": m["f1"], "delta_f1": m["f1"] - full, "fpr": m["fpr"]}

    # signal frequency (explanations)
    from collections import Counter
    cnt = {lab: Counter(s.name for r in rows if r["y"] == lab for s in r["signals"]) for lab in (0, 1)}
    res["signal_frequency"] = {k: {"phish_%": 100 * cnt[1][k] / max(1, y.sum()),
                                   "legit_%": 100 * cnt[0][k] / max(1, len(y) - y.sum())}
                               for k in set(cnt[0]) | set(cnt[1])}
    res["latency_heuristic"] = latency_summary([r["ms"] for r in rows])
    save_results("e3_web", res)

    # E4 sensitivity: vary each constant +/-20% around the tuned value
    sens = {}
    for field in ["critical_min", "scale", "exponent", "decay"]:
        base = getattr(p, field); pts = []
        for f in [0.8, 0.9, 1.0, 1.1, 1.2]:
            v = min(base * f, 0.999) if field == "decay" else base * f
            pts.append([float(v), binary_metrics(yt, prob(test, A.with_params(**{**p.__dict__, field: v})), thr)["f1"]])
        sens[field] = pts
    save_results("e4_aggregation", {"tuned": p.__dict__, "additive": res["additive_baseline"],
                                     "phishsentry": res["phishsentry"], "sensitivity": sens})
    try:
        import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
        plt.rcParams["font.family"] = "serif"
        fig, ax = plt.subplots(figsize=(3.4, 2.2), dpi=300)
        for field, pts in sens.items():
            ax.plot([0.8, 0.9, 1.0, 1.1, 1.2], [q[1] * 100 for q in pts], marker="o", ms=3, lw=1, label=field)
        ax.set_xlabel("constant / tuned value"); ax.set_ylabel("F1 (%)"); ax.legend(fontsize=6, frameon=False)
        ax.grid(alpha=0.3, lw=0.4); fig.tight_layout()
        fig.savefig(os.path.join(os.environ.get("PHISHSENTRY_FIG_DIR") or os.path.join(ROOT, "papers", "figures"), "fig_sensitivity.png"))
    except Exception as e:
        print("plot skipped:", e)


if __name__ == "__main__":
    main()
