"""Shared metrics so every experiment reports numbers the same way."""
import json, os, time
import numpy as np
from sklearn.metrics import (precision_score, recall_score, f1_score, accuracy_score,
                             roc_auc_score, confusion_matrix)


def binary_metrics(y_true, score, thr=0.5):
    y_true = np.asarray(y_true); score = np.asarray(score, dtype=float)
    y_hat = (score >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_hat, labels=[0, 1]).ravel()
    return {
        "precision": precision_score(y_true, y_hat, zero_division=0),
        "recall": recall_score(y_true, y_hat, zero_division=0),
        "f1": f1_score(y_true, y_hat, zero_division=0),
        "accuracy": accuracy_score(y_true, y_hat),
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
        "auc": roc_auc_score(y_true, score) if len(set(y_true.tolist())) > 1 else float("nan"),
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
    }


def mean_std(fold_dicts, keys=("precision", "recall", "f1", "accuracy", "fpr", "auc")):
    out = {}
    for k in keys:
        v = np.array([d[k] for d in fold_dicts], dtype=float) * 100
        out[k] = {"mean": float(np.nanmean(v)), "std": float(np.nanstd(v))}
    return out


def fmt(ms, digits=2):
    """'97.41 ± 0.52' from {'mean':..,'std':..}."""
    return f"{ms['mean']:.{digits}f} ± {ms['std']:.{digits}f}"


def time_ms(fn, *args, repeats=1):
    t0 = time.perf_counter()
    for _ in range(repeats):
        fn(*args)
    return (time.perf_counter() - t0) * 1000 / repeats


def latency_summary(ms_list):
    a = np.asarray(ms_list, dtype=float)
    return {"median_ms": float(np.median(a)), "p95_ms": float(np.percentile(a, 95)), "n": int(a.size)}


RESULTS_DIR = os.environ.get("PHISHSENTRY_RESULTS_DIR") or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")


def save_results(name, payload):
    """Write results/<name>.json. The paper builder reads only these files."""
    rd = os.environ.get("PHISHSENTRY_RESULTS_DIR") or RESULTS_DIR
    os.makedirs(rd, exist_ok=True)
    payload = dict(payload)
    payload["_generated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    import platform
    try:
        cpu = next((l.split(":", 1)[1].strip() for l in open("/proc/cpuinfo") if l.startswith("model name")), platform.processor())
    except Exception:
        cpu = platform.processor()
    payload["_machine"] = {"cpu": cpu, "logical_cpus": os.cpu_count(), "python": platform.python_version(),
                           "os": platform.system()}
    path = os.path.join(rd, f"{name}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=float)
    print(f"[saved] {path}")
    return path
