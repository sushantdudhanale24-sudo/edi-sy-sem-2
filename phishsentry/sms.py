"""SMS analysis engine: six heuristic detectors + Naive Bayes + transformer + fusion.

Matches the paper's description (Sec. "SMS analysis"):
  layer 1  urgency, credential, financial, URL, sentiment, pattern detectors -> S_h
  layer 2  TF-IDF + Multinomial Naive Bayes                                 -> S_nb
  layer 3  transformer encoder + logistic-regression head                  -> S_tr
  fusion   S = a*S_h + b*S_nb + c*S_tr  (a+b+c = 1, tuned on validation data)
  override S* = max(S, S_h) when S_h >= theta   (strong rule evidence is never ignored)

If your team's original detectors differ, edit DETECTORS / WEIGHTS here so the
paper describes exactly this code.
"""
import re
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score

# ------------------------------------------------------------------ detectors
URL_RE = re.compile(r"(https?://|www\.)\S+|\b[\w-]+\.(com|in|xyz|top|ly|co|info|link|site|online|club|net)\b", re.I)
SHORT_RE = re.compile(r"\b(bit\.ly|tinyurl|goo\.gl|t\.co|cutt\.ly|is\.gd|rb\.gy|shorturl)\b", re.I)

DETECTORS = {
    "urgency": re.compile(r"\b(urgent|immediately|within 24|today only|expires?|expiring|last chance|act now|verify now|asap|final notice)\b", re.I),
    "credential": re.compile(r"\b(otp|pin|password|passcode|cvv|kyc|aadhaa?r|pan card|login|log in|verify your|account details|card details|update your)\b", re.I),
    "financial": re.compile(r"(rs\.?|inr|₹|\$|£)\s?\d|\b(won|winner|prize|reward|cashback|refund|lottery|payment|bank|loan|credited|debited)\b", re.I),
    "url": None,  # handled by URL_RE / SHORT_RE
    "sentiment": re.compile(r"\b(blocked|suspended|deactivated|penalty|legal action|unauthori[sz]ed|fraud alert|locked|disconnected|arrest)\b", re.I),
    "pattern": re.compile(r"\b(dear (customer|user|member)|click (here|the link|below)|reply (yes|stop)|(call|text|whatsapp)\b.{0,20}\d{5,})", re.I),
}
WEIGHTS = {"urgency": 0.15, "credential": 0.25, "financial": 0.15,
           "url": 0.20, "sentiment": 0.10, "pattern": 0.15}

EXPLAIN = {
    "urgency": "pressure to act quickly",
    "credential": "asks for OTP, PIN, password or account details",
    "financial": "mentions money, prizes, refunds or bank actions",
    "url": "contains a link (shortened links weigh the same)",
    "sentiment": "fear or threat wording",
    "pattern": "known smishing template phrase",
}


# ------------------------------------------------------------------ normalisation (defence against obfuscation)
import unicodedata
HOMOGLYPHS = str.maketrans({"\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0445": "x",
                            "\u0443": "y", "\u0456": "i", "\u0458": "j", "\u0410": "A", "\u0415": "E", "\u041e": "O",
                            "\u0420": "P", "\u0421": "C", "\u039f": "O", "\u03bf": "o", "\u0391": "A", "\u0392": "B"})
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
SPACED = re.compile(r"\b(?:[A-Za-z][.\-_ *]){2,}[A-Za-z]\b")


def normalize(text):
    """Undo common evasion tricks before scoring: homoglyphs, leetspeak inside words,
    letters split by separators (v.e.r.i.f.y), and defanged links (hxxp, [.])."""
    t = unicodedata.normalize("NFKC", text).translate(HOMOGLYPHS)
    t = t.replace("hxxp", "http").replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".")
    t = SPACED.sub(lambda m: re.sub(r"[.\-_ *]", "", m.group(0)), t)
    # leetspeak only *inside* words (acc0unt, p@ypal, fr33): a letter before, a letter or word end after
    t = re.sub(r"(?<=[A-Za-z])[013457@$]{1,2}(?=[A-Za-z]|\b)", lambda m: m.group(0).translate(LEET), t)
    return t


def heuristic_signals(text):
    sig = {}
    for name, rx in DETECTORS.items():
        if name == "url":
            sig[name] = bool(URL_RE.search(text) or SHORT_RE.search(text))
        else:
            sig[name] = bool(rx.search(text))
    return sig


def heuristic_score(text):
    s = heuristic_signals(text)
    return min(1.0, sum(WEIGHTS[k] for k, v in s.items() if v))


# ------------------------------------------------------------------ layers
class NaiveBayesLayer:
    def __init__(self, alpha=0.1):
        self.vec = TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=2, sublinear_tf=True)
        self.nb = MultinomialNB(alpha=alpha)

    def fit(self, texts, y):
        self.nb.fit(self.vec.fit_transform(texts), y)
        return self

    def predict_proba(self, texts):
        return self.nb.predict_proba(self.vec.transform(texts))[:, 1]

    def top_terms(self, text, k=3):
        """Terms that pushed this message toward 'malicious' (for explanations)."""
        x = self.vec.transform([text])
        logp = self.nb.feature_log_prob_[1] - self.nb.feature_log_prob_[0]
        idx = x.nonzero()[1]
        names = self.vec.get_feature_names_out()
        ranked = sorted(idx, key=lambda i: -logp[i] * x[0, i])
        return [names[i] for i in ranked[:k] if logp[i] > 0]


class TransformerLayer:
    """Mean-pooled transformer embeddings + logistic regression head.
    Needs `pip install torch transformers`; runs on CPU or a free Colab GPU."""

    def __init__(self, model_name="distilbert-base-uncased", max_length=96):
        from transformers import AutoTokenizer, AutoModel
        import torch
        self.torch = torch
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.tok = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModel.from_pretrained(model_name).to(self.device).eval()
        self.max_length = max_length
        self.head = LogisticRegression(max_iter=3000, class_weight="balanced")
        self.name = model_name

    def embed(self, texts, bs=64):
        out = []
        with self.torch.no_grad():
            for i in range(0, len(texts), bs):
                b = self.tok(list(texts[i:i + bs]), padding=True, truncation=True,
                             max_length=self.max_length, return_tensors="pt").to(self.device)
                h = self.model(**b).last_hidden_state
                m = b["attention_mask"].unsqueeze(-1)
                out.append(((h * m).sum(1) / m.sum(1)).cpu().numpy())
        return np.vstack(out)

    def fit(self, texts, y):
        self.head.fit(self.embed(texts), y)
        return self

    def predict_proba(self, texts):
        return self.head.predict_proba(self.embed(texts))[:, 1]


# ------------------------------------------------------------------ fusion
def tune_weights(layer_scores, y, step=0.05):
    """Grid-search fusion weights (sum to 1) on validation data by F1."""
    names = list(layer_scores)
    grid = np.round(np.arange(0, 1 + 1e-9, step), 3)
    best_f, best_w = -1.0, None
    if len(names) == 2:
        combos = [(a, round(1 - a, 3)) for a in grid]
    else:
        combos = [(a, b, round(1 - a - b, 3)) for a in grid for b in grid if 1 - a - b >= -1e-9]
    for c in combos:
        w = dict(zip(names, c))
        s = sum(w[k] * layer_scores[k] for k in names)
        f = f1_score(y, (s >= 0.5).astype(int), zero_division=0)
        if f > best_f:
            best_f, best_w = f, w
    return {k: float(v) for k, v in best_w.items()}


def tune_threshold(score, y, grid=None):
    """Decision threshold that maximises F1 on validation data (never on test data)."""
    grid = np.round(np.arange(0.05, 0.96, 0.01), 2) if grid is None else grid
    f = [f1_score(y, (np.asarray(score) >= t).astype(int), zero_division=0) for t in grid]
    return float(grid[int(np.argmax(f))])


class Stacker:
    """Learned fusion: logistic regression over layer scores + the six detector flags.
    Its coefficients double as a global explanation of what the ensemble relies on."""

    def __init__(self):
        self.lr = LogisticRegression(max_iter=3000, class_weight="balanced")

    def _feats(self, layer_scores, texts):
        names = sorted(layer_scores)
        flags = np.array([[float(v) for v in heuristic_signals(t).values()] for t in texts])
        self.names = names + [f"det_{k}" for k in DETECTORS]
        return np.column_stack([np.asarray(layer_scores[n]) for n in names] + [flags])

    def fit(self, layer_scores, texts, y):
        self.lr.fit(self._feats(layer_scores, texts), y); return self

    def predict_proba(self, layer_scores, texts):
        return self.lr.predict_proba(self._feats(layer_scores, texts))[:, 1]

    def coefficients(self):
        return dict(zip(self.names, map(float, self.lr.coef_[0])))


def fuse(layer_scores, weights, override_theta=0.6):
    s = sum(weights[k] * np.asarray(layer_scores[k]) for k in weights)
    h = np.asarray(layer_scores["heuristic"])
    return np.where(h >= override_theta, np.maximum(s, h), s)


class SMSEnsemble:
    """Trained end-to-end analyzer used by the demo, the email module and latency tests."""

    def __init__(self, transformer=None, override_theta=0.6):
        self.nb = NaiveBayesLayer()
        self.tr = TransformerLayer(transformer) if transformer else None
        self.theta = override_theta
        self.weights = None

    def _scores(self, texts):
        sc = {"heuristic": np.array([heuristic_score(t) for t in texts]),
              "naive_bayes": self.nb.predict_proba(texts)}
        if self.tr:
            sc["transformer"] = self.tr.predict_proba(texts)
        return sc

    def fit(self, texts, y, val_frac=0.2, seed=42):
        texts = np.asarray(texts, dtype=object); y = np.asarray(y)
        rng = np.random.RandomState(seed); idx = rng.permutation(len(texts))
        n_val = int(len(texts) * val_frac); val, tr = idx[:n_val], idx[n_val:]
        self.nb.fit(texts[tr], y[tr])
        if self.tr: self.tr.fit(texts[tr], y[tr])
        self.weights = tune_weights(self._scores(texts[val]), y[val])
        self.nb.fit(texts, y)
        if self.tr: self.tr.fit(texts, y)
        return self

    def score(self, texts):
        return fuse(self._scores(texts), self.weights, self.theta)

    def explain(self, text):
        sc = {k: float(v[0]) for k, v in self._scores([text]).items()}
        final = float(fuse({k: np.array([v]) for k, v in sc.items()}, self.weights, self.theta)[0])
        fired = [k for k, v in heuristic_signals(text).items() if v]
        return {"score": final, "label": "phishing" if final >= 0.5 else "legitimate",
                "layer_scores": sc, "detectors_fired": fired,
                "reasons": [EXPLAIN[k] for k in fired], "nb_terms": self.nb.top_terms(text)}
