"""Risk aggregation engine (paper Sec. "Risk aggregation").

  critical risk  R_c = sum of weights >= CRITICAL_MIN
  minor risk     R_m = sum of weights <  CRITICAL_MIN
  diminishing    R_s = SCALE * R_m ** EXPONENT
  total          R_t = R_c + R_s
  trust          T   = 100 * DECAY ** (100 * R_t)      (bounded to [0, 100])
  label          T >= SAFE -> safe, T >= SUSPICIOUS -> suspicious, else high risk

All constants live in Params so E4 can tune them on validation data and
plot their sensitivity. ADDITIVE is the plain baseline the paper compares to.
"""
from dataclasses import dataclass, replace
import numpy as np


@dataclass(frozen=True)
class Params:
    critical_min: float = 0.15
    scale: float = 0.7
    exponent: float = 0.5
    decay: float = 0.95
    ai_decay: float = 0.90
    safe: float = 75.0
    suspicious: float = 45.0
    suspicious_ai: float = 40.0


DEFAULT = Params()


def risk(signals, p=DEFAULT):
    w = np.array([s.weight for s in signals], dtype=float)
    rc = float(w[w >= p.critical_min].sum()) if w.size else 0.0
    rm = float(w[w < p.critical_min].sum()) if w.size else 0.0
    rs = p.scale * (rm ** p.exponent) if rm > 0 else 0.0
    return rc, rm, rs, rc + rs


def trust_score(signals, p=DEFAULT, ai_flag=False):
    _, _, _, rt = risk(signals, p)
    base = p.ai_decay if ai_flag else p.decay
    return float(np.clip(100.0 * base ** (100.0 * rt), 0, 100))


def additive_trust(signals):
    """Baseline: every weight counts in full, linear penalty."""
    return float(np.clip(100.0 - 100.0 * sum(s.weight for s in signals), 0, 100))


def label(trust, p=DEFAULT, ai_flag=False):
    sus = p.suspicious_ai if ai_flag else p.suspicious
    return "safe" if trust >= p.safe else ("suspicious" if trust >= sus else "high_risk")


def phishing_probability(trust):
    """Monotone map used for ROC/AUC: low trust = high phishing probability."""
    return 1.0 - trust / 100.0


def with_params(**kw):
    return replace(DEFAULT, **kw)
