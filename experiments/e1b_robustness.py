"""E1b - SMS robustness and explainability analysis (Paper A, Sec. V).

1. Obfuscation robustness: malicious test messages are rewritten with common
   evasion tricks (leetspeak, homoglyphs, split letters, defanged links) and
   re-scored. Models are trained on clean data only; perturbations touch only
   the test fold. We compare recall with and without the normalisation step.
2. Detector ablation inside stacked fusion: F1 change when one detector bit is removed.
3. Stacker coefficients (global explanation), averaged over folds.

    python experiments/e1b_robustness.py
Output: results/e1b_sms_robustness.json
"""
import argparse, os, random, re, sys
import numpy as np, pandas as pd
from sklearn.model_selection import StratifiedKFold

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from phishsentry import sms
from phishsentry.metrics import binary_metrics, mean_std, save_results

# ------------------------------------------------------------------ perturbations
LEET_FWD = {"o": "0", "i": "1", "e": "3", "a": "4", "s": "5"}
CYR = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х", "y": "у"}


def _words(t, rng, frac, fn):
    toks = t.split(" ")
    return " ".join(fn(w) if (len(w) > 3 and w.isalpha() and rng.random() < frac) else w for w in toks)


def leet(t, rng, frac=0.4):
    return _words(t, rng, frac, lambda w: "".join(LEET_FWD.get(c.lower(), c) if rng.random() < 0.5 else c for c in w))


def homoglyph(t, rng, frac=0.4):
    return _words(t, rng, frac, lambda w: "".join(CYR.get(c, c) if rng.random() < 0.5 else c for c in w))


def split_letters(t, rng, frac=0.25):
    return _words(t, rng, frac, lambda w: ".".join(w))


def defang(t, rng, frac=1.0):
    t = re.sub(r"https?://", lambda m: m.group(0).replace("http", "hxxp"), t)
    return re.sub(r"(?<=\w)\.(?=(com|in|ly|co|net|org|xyz|top|info)\b)", "[.]", t)


def combined(t, rng):
    return defang(split_letters(homoglyph(leet(t, rng, 0.25), rng, 0.25), rng, 0.15), rng)


ATTACKS = {"leetspeak": leet, "homoglyph": homoglyph, "split_letters": split_letters, "defanged_links": defang, "combined": combined}


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=os.path.join(ROOT, "data", "sms_mishra_soni_5971.csv"))
    ap.add_argument("--positive", nargs="+", default=["smishing", "spam"])
    ap.add_argument("--repeats", type=int, default=2)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    d = pd.read_csv(a.csv, encoding="latin-1"); d.columns = [c.lower() for c in d.columns]
    lab = d["label"].astype(str).str.strip().str.lower()
    X = d["text"].astype(str).values; y = lab.isin(a.positive).astype(int).values
    _, keep = np.unique(pd.Series(X).str.strip().str.lower().values, return_index=True)
    keep = np.sort(keep); X, y = X[keep], y[keep]
    rng = random.Random(a.seed)

    def scores(train_X, train_y, score_X, norm):
        f = (lambda arr: np.array([sms.normalize(t) for t in arr], dtype=object)) if norm else (lambda arr: arr)
        tx, sx = f(train_X), f(score_X)
        return {"heuristic": np.array([sms.heuristic_score(t) for t in sx]),
                "naive_bayes": sms.NaiveBayesLayer().fit(tx, train_y).predict_proba(sx)}, sx

    variants = ["naive_bayes", "stacked", "naive_bayes+norm", "stacked+norm"]
    rec = {atk: {v: [] for v in variants} for atk in ["clean"] + list(ATTACKS)}
    clean_fpr = {v: [] for v in variants}
    abl = {k: [] for k in sms.DETECTORS}; coefs = []
    splits = [(tr, te) for r in range(a.repeats)
              for tr, te in StratifiedKFold(5, shuffle=True, random_state=a.seed + r).split(X, y)]
    for k, (tr, te) in enumerate(splits, 1):
        fi, vi = next(StratifiedKFold(4, shuffle=True, random_state=a.seed).split(X[tr], y[tr])); fi, vi = tr[fi], tr[vi]
        models = {}
        for norm in (False, True):
            vsc, vx = scores(X[fi], y[fi], X[vi], norm)
            st = sms.Stacker().fit(vsc, vx, y[vi])
            thr_nb = sms.tune_threshold(vsc["naive_bayes"], y[vi]); thr_st = sms.tune_threshold(st.predict_proba(vsc, vx), y[vi])
            models[norm] = (st, thr_nb, thr_st)
            if not norm:
                coefs.append(st.coefficients())
        pos = te[y[te] == 1]
        test_sets = {"clean": X[te]}
        for name, fn in ATTACKS.items():
            pert = X[te].copy()
            for j, i in enumerate(te):
                if y[i] == 1: pert[j] = fn(X[i], rng)
            test_sets[name] = pert
        for atk, tx in test_sets.items():
            for norm in (False, True):
                sc, sx = scores(X[tr], y[tr], tx, norm)
                st, thr_nb, thr_st = models[norm]
                sfx = "+norm" if norm else ""
                for v, s, t in (("naive_bayes", sc["naive_bayes"], thr_nb), ("stacked", st.predict_proba(sc, sx), thr_st)):
                    m = binary_metrics(y[te], s, t)
                    rec[atk][v + sfx].append(m["recall"])
                    if atk == "clean": clean_fpr[v + sfx].append(m["fpr"])
        # detector ablation (clean, no normalisation)
        sc, sx = scores(X[tr], y[tr], X[te], False)
        st, _, thr_st = models[False]
        full = binary_metrics(y[te], st.predict_proba(sc, sx), thr_st)["f1"]
        vsc, vx = scores(X[fi], y[fi], X[vi], False)
        for det in sms.DETECTORS:
            saved = sms.DETECTORS.copy(); saved_w = sms.WEIGHTS.copy()
            sms.DETECTORS[det] = re.compile(r"(?!x)x") if det != "url" else sms.DETECTORS[det]
            if det == "url":
                orig = sms.URL_RE, sms.SHORT_RE; sms.URL_RE = sms.SHORT_RE = re.compile(r"(?!x)x")
            vs2 = {"heuristic": np.array([sms.heuristic_score(t) for t in vx]), "naive_bayes": vsc["naive_bayes"]}
            s2 = sms.Stacker().fit(vs2, vx, y[vi]); t2 = sms.tune_threshold(s2.predict_proba(vs2, vx), y[vi])
            ts2 = {"heuristic": np.array([sms.heuristic_score(t) for t in sx]), "naive_bayes": sc["naive_bayes"]}
            abl[det].append(binary_metrics(y[te], s2.predict_proba(ts2, sx), t2)["f1"] - full)
            sms.DETECTORS.update(saved); sms.WEIGHTS.update(saved_w)
            if det == "url": sms.URL_RE, sms.SHORT_RE = orig
        print(f"split {k}/{len(splits)} done")

    out = {"task": "malicious (" + "+".join(a.positive) + ") vs rest", "n": int(len(X)), "splits": len(splits),
           "recall": {atk: {v: {"mean": 100 * float(np.mean(r)), "std": 100 * float(np.std(r))} for v, r in d_.items()} for atk, d_ in rec.items()},
           "clean_fpr": {v: {"mean": 100 * float(np.mean(r)), "std": 100 * float(np.std(r))} for v, r in clean_fpr.items()},
           "detector_ablation_delta_f1_pts": {k: {"mean": 100 * float(np.mean(v)), "std": 100 * float(np.std(v))} for k, v in abl.items()},
           "stacker_coefficients": {k: float(np.mean([c[k] for c in coefs])) for k in coefs[0]},
           "example_attacks": {name: fn("URGENT: verify your account now at http://sbi-kyc.com or it will be blocked", random.Random(1)) for name, fn in ATTACKS.items()}}
    for atk in rec:
        print(f"{atk:15s}", "  ".join(f"{v}={out['recall'][atk][v]['mean']:.1f}" for v in variants))
    print("clean FPR", {v: round(x["mean"], 2) for v, x in out["clean_fpr"].items()})
    print("ablation", {k: round(v["mean"], 2) for k, v in out["detector_ablation_delta_f1_pts"].items()})
    save_results("e1b_sms_robustness", out)


if __name__ == "__main__":
    main()
