"""E1 - SMS smishing detection: each layer vs the fused ensemble.

Outputs results/e1_sms_<tag>.json, read by the paper builder.

  python experiments/e1_sms.py                                   # heuristic + NB
  python experiments/e1_sms.py --transformer distilbert-base-uncased   # + transformer (Colab/GPU)
  python experiments/e1_sms.py --positive smishing spam --tag smishing_plus_spam
"""
import argparse, os, sys, time
import numpy as np, pandas as pd
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import confusion_matrix

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from phishsentry import sms
from phishsentry.metrics import binary_metrics, mean_std, latency_summary, save_results, fmt


def load(csv, positive):
    d = pd.read_csv(csv, encoding="latin-1")
    d.columns = [c.strip().lower() for c in d.columns]
    d = d.dropna(subset=["text", "label"])
    lab = d["label"].astype(str).str.strip().str.lower()
    y = lab.isin({p.lower() for p in positive}).astype(int).values
    return d["text"].astype(str).values, y, lab.values


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=os.path.join(ROOT, "data", "sms_mishra_soni_5971.csv"))
    ap.add_argument("--positive", nargs="+", default=["smishing"])
    ap.add_argument("--transformer", default=None)
    ap.add_argument("--folds", type=int, default=5)
    ap.add_argument("--theta", type=float, default=0.6)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--repeats", type=int, default=5, help="repeated stratified k-fold with different seeds")
    ap.add_argument("--dedupe", action="store_true", default=True)
    ap.add_argument("--tag", default="smishing")
    a = ap.parse_args()

    X, y, raw = load(a.csv, a.positive)
    n_before = len(X)
    if a.dedupe:  # exact duplicates across folds would inflate scores
        _, keep = np.unique(pd.Series(X).str.strip().str.lower().values, return_index=True)
        keep = np.sort(keep); X, y, raw = X[keep], y[keep], raw[keep]
    print(f"{n_before} messages, {n_before - len(X)} exact duplicates removed -> {len(X)}; "
          f"{y.sum()} positive ({', '.join(a.positive)})")

    layers = ["heuristic", "naive_bayes"] + (["transformer"] if a.transformer else [])
    variants = layers + ["ensemble", "ensemble_no_override", "stacked"]
    folds = {v: [] for v in variants}
    thresholds = {v: [] for v in variants}
    cm = np.zeros((2, 2), int); weights = []; errors = []
    from collections import Counter
    fp_by_label = Counter(); fn_by_label = Counter()
    splits = [(tr, te) for r in range(a.repeats)
              for tr, te in StratifiedKFold(n_splits=a.folds, shuffle=True, random_state=a.seed + r).split(X, y)]

    def layer_scores(train_idx, score_idx):
        sc = {"heuristic": np.array([sms.heuristic_score(t) for t in X[score_idx]])}
        sc["naive_bayes"] = sms.NaiveBayesLayer().fit(X[train_idx], y[train_idx]).predict_proba(X[score_idx])
        if a.transformer:
            sc["transformer"] = sms.TransformerLayer(a.transformer).fit(X[train_idx], y[train_idx]).predict_proba(X[score_idx])
        return sc

    for k, (tr, te) in enumerate(splits, 1):
        inner = StratifiedKFold(n_splits=4, shuffle=True, random_state=a.seed)
        fi, vi = next(inner.split(X[tr], y[tr])); fi, vi = tr[fi], tr[vi]
        vsc = layer_scores(fi, vi)
        w = sms.tune_weights(vsc, y[vi]); weights.append(w)
        stack = sms.Stacker().fit(vsc, X[vi], y[vi])
        val_out = {l: vsc[l] for l in layers}
        val_out["ensemble"] = sms.fuse(vsc, w, a.theta)
        val_out["ensemble_no_override"] = sms.fuse(vsc, w, override_theta=9.0)
        val_out["stacked"] = stack.predict_proba(vsc, X[vi])
        thr = {v: sms.tune_threshold(val_out[v], y[vi]) for v in variants}
        sc = layer_scores(tr, te)
        test_out = {l: sc[l] for l in layers}
        test_out["ensemble"] = sms.fuse(sc, w, a.theta)
        test_out["ensemble_no_override"] = sms.fuse(sc, w, override_theta=9.0)
        test_out["stacked"] = stack.predict_proba(sc, X[te])
        for v in variants:
            folds[v].append(binary_metrics(y[te], test_out[v], thr[v])); thresholds[v].append(thr[v])
        st_hat = (test_out["stacked"] >= thr["stacked"]).astype(int)
        for i in te[(st_hat == 1) & (y[te] == 0)]: fp_by_label[raw[i]] += 1
        for i in te[(st_hat == 0) & (y[te] == 1)]: fn_by_label[raw[i]] += 1
        ens = test_out["ensemble"]
        cm += confusion_matrix(y[te], (ens >= thr["ensemble"]).astype(int), labels=[0, 1])
        for i in te[np.where((ens >= thr["ensemble"]).astype(int) != y[te])[0]][:15]:
            errors.append({"label": raw[i], "text": X[i][:160]})
        if k % a.folds == 0: print(f"repeat {k // a.folds} done")

    summary = {v: mean_std(f) for v, f in folds.items()}
    # Nadeau-Bengio corrected resampled t-test (accounts for overlapping training sets)
    from scipy import stats
    def nb_test(v1, v2, metric="f1"):
        d = np.array([x[metric] - z[metric] for x, z in zip(folds[v1], folds[v2])])
        J = len(d); ratio = 1 / (a.folds - 1)
        var = d.var(ddof=1)
        t = d.mean() / np.sqrt((1 / J + ratio) * var) if var > 0 else 0.0
        return {"mean_diff_pts": float(d.mean() * 100), "t": float(t), "p": float(2 * stats.t.sf(abs(t), J - 1))}
    tests = {f"stacked_vs_{v}": nb_test("stacked", v) for v in layers + ["ensemble"]}
    tests["ensemble_vs_naive_bayes"] = nb_test("ensemble", "naive_bayes")
    tests["override_effect"] = nb_test("ensemble", "ensemble_no_override")
    for k, v in tests.items(): print(f"{k:28s} diff={v['mean_diff_pts']:+.2f} pts  p={v['p']:.3f}")
    print("\nmethod                 P              R              F1             FPR")
    for v, s in summary.items():
        print(f"{v:22s} {fmt(s['precision'])}  {fmt(s['recall'])}  {fmt(s['f1'])}  {fmt(s['fpr'])}")

    # detector firing rates (explainability evidence)
    sig = pd.DataFrame([sms.heuristic_signals(t) for t in X])
    fire = {d: {"positive_%": float(sig[d][y == 1].mean() * 100), "negative_%": float(sig[d][y == 0].mean() * 100)}
            for d in sig.columns}

    # latency of the trained pipeline on 500 messages
    model = sms.SMSEnsemble(transformer=a.transformer, override_theta=a.theta).fit(X, y)
    rs = np.random.RandomState(a.seed).choice(len(X), min(500, len(X)), replace=False)
    lat = []
    for i in rs:
        t0 = time.perf_counter(); model.score([X[i]]); lat.append((time.perf_counter() - t0) * 1000)
    examples = [model.explain(t) | {"text": t} for t in [
        X[np.where(y == 1)[0][0]], X[np.where(y == 0)[0][0]]]]

    save_results(f"e1_sms_{a.tag}", {
        "dataset": os.path.basename(a.csv), "n_raw": int(n_before), "n": int(len(X)),
        "n_positive": int(y.sum()), "n_negative": int(len(y) - y.sum()), "positive_labels": a.positive,
        "label_counts": pd.Series(raw).value_counts().to_dict(),
        "folds": a.folds, "repeats": a.repeats, "significance": tests, "layers": layers, "theta": a.theta, "transformer": a.transformer,
        "summary": summary, "thresholds_per_fold": thresholds, "confusion": cm.tolist(), "weights_per_fold": weights,
        "detector_firing": fire, "stacked_errors_by_label": {"false_positives": dict(fp_by_label), "false_negatives": dict(fn_by_label), "per_repeat_divisor": a.repeats}, "latency": latency_summary(lat),
        "final_weights": model.weights, "examples": examples, "sample_errors": errors[:20]})


if __name__ == "__main__":
    main()
