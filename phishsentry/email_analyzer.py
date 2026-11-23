"""Email analysis engine: sender authentication + content scoring.

Authentication verdicts are taken from the receiving server's
Authentication-Results header (RFC 8601), which Gmail and Outlook add after
running SPF (RFC 7208), DKIM (RFC 6376) and DMARC (RFC 7489). Header
alignment compares the From domain with the Return-Path domain.

Content is scored with the same SMS ensemble (subject + body text).
"""
import email, re
from email import policy

AUTH_CHECKS = ("spf", "dkim", "dmarc", "align")


def parse_eml(raw_bytes):
    return email.message_from_bytes(raw_bytes, policy=policy.default)


def _domain(addr):
    m = re.search(r"@([\w.-]+)", addr or "")
    return m.group(1).lower().rstrip(">") if m else ""


def org_domain(d):
    parts = d.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "ac", "gov", "org", "edu", "net") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def auth_verdicts(msg):
    ar = " ".join(str(h) for h in (msg.get_all("Authentication-Results") or [])).lower()
    get = lambda k: (re.search(rf"\b{k}=(\w+)", ar) or [None, "none"])[1]
    frm, rp = _domain(str(msg.get("From", ""))), _domain(str(msg.get("Return-Path", "")))
    aligned = bool(frm) and bool(rp) and org_domain(frm) == org_domain(rp)
    return {"spf": get("spf"), "dkim": get("dkim"), "dmarc": get("dmarc"),
            "from_domain": frm, "return_path_domain": rp, "aligned": aligned}


def auth_flags(v):
    return {"spf": v["spf"] != "pass", "dkim": v["dkim"] != "pass",
            "dmarc": v["dmarc"] != "pass", "align": not v["aligned"]}


def body_text(msg, limit=20000):
    parts = []
    try:
        for p in msg.walk():
            if p.get_content_type() in ("text/plain", "text/html"):
                try:
                    parts.append(str(p.get_content()))
                except Exception:
                    payload = p.get_payload(decode=True) or b""
                    parts.append(payload.decode("latin-1", "ignore"))
    except Exception:
        pass
    text = re.sub(r"<[^>]+>", " ", " ".join(parts))
    return f"{msg.get('Subject', '')} {text}"[:limit]


def analyze(msg, content_model=None, tau=0.5, require=("dmarc",)):
    """Flag if any required auth check fails, or content score >= tau."""
    v = auth_verdicts(msg); fl = auth_flags(v)
    content = float(content_model.score([body_text(msg)])[0]) if content_model else None
    flagged = any(fl[c] for c in require) or (content is not None and content >= tau)
    reasons = [f"{c.upper()} check failed" for c in AUTH_CHECKS if fl[c] and c != "align"]
    if fl["align"]:
        reasons.append(f"From domain ({v['from_domain']}) differs from Return-Path ({v['return_path_domain']})")
    if content is not None and content >= tau:
        reasons.append(f"message text scored {content:.2f} on the SMS/email ensemble")
    return {"flagged": flagged, "auth": v, "flags": fl, "content_score": content, "reasons": reasons}
