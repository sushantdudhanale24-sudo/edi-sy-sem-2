# phishsentry-research

One codebase behind two papers:

| Paper | Venue | Deadline | Built by | Experiments |
|---|---|---|---|---|
| **A** – Explainable learned fusion for robust SMS phishing detection | IEEE VCC 2027 (virtual, 6 pages) | 27 Nov 2026 | `papers/paper_a_vcc.js` | E1, E1b |
| **B** – Should a vision LLM revise or replace? Website phishing detection | ICMDRSE-2027 (Vishwakarma University, Pune) | 10 Jan 2027 | `papers/paper_b_icmdrse.js` | E3–E6 |

The papers never contain hand-typed numbers. Every value is read from `results/*.json`. Anything missing appears in the Word file as a **yellow [TBD]**, and is listed in `papers/out/*_MISSING_RESULTS.txt`.

## Status (24 Nov 2026)

| Experiment | Status | Result file |
|---|---|---|
| E1 SMS: malicious vs ham (T1), smishing vs rest (T2) | **Done** on the real Mishra & Soni dataset | `results/e1_sms_*.json` |
| E1b SMS robustness to obfuscation, detector ablation, stacking coefficients | **Done** | `results/e1b_sms_robustness.json` |
| Transformer layer | Not run (needs torch + internet); left as future work in Paper A | – |
| E2 email | Moved out of Paper A; keep for a later paper | `results/e2_email_*.json` |
| E3/E4/E6 website | Needs `collect_web.py` run daily for 1–2 weeks | `results/e3_web.json`, `results/e4_aggregation.json` |
| E5 LLM override | Needs E3 data + `OPENAI_API_KEY` | `results/e5_llm_override.json` |

**Paper A is complete except reference [18] (GitHub URL).** After pushing the repository, run:

```bash
echo '{"url": "https://github.com/<you>/phishsentry-research"}' > results/_github.json
node papers/paper_a_vcc.js
```

## What E1 found (real data, 5×5-fold CV, corrected t-test)

- **Malicious vs normal SMS (T1).** Stacked fusion gets 95.84% F1 at 0.59% FPR. That is +1.13 F1 over Naive Bayes (p = 0.015).
- **Smishing vs spam (T2).** About 86% F1 for every variant. 97% of the false alarms are spam, and only 0.05% of personal messages are flagged.
- **The original design.** Fixed-weight voting and the max-override from the earlier design give no measurable gain.
- **Obfuscation.** Combined attacks lower the stacked detector's recall by 2.2 points; normalisation restores it to 93.7%.
- **Which detectors matter.** pattern, financial and url carry the fused model. urgency, credential and sentiment barely matter for scoring.

## Layout

```
phishsentry/            the system (import it from experiments and the demo)
  sms.py                6 detectors, Naive Bayes, transformer, fixed fusion, stacked fusion, explanations
  email_analyzer.py     SPF / DKIM / DMARC from Authentication-Results, From vs Return-Path, content score
  web/features.py       8 website analyzers on a frozen snapshot
  web/aggregate.py      critical/minor signals, diminishing returns, trust decay (all constants in Params)
  web/llm.py            vision-LLM call (cached), modes off / replace / bounded
  baselines.py          URL Random Forest, blacklist-at-collection
  metrics.py            shared metrics; save_results() writes results/*.json
experiments/            e1_sms.py, e1b_robustness.py, e2_email.py, collect_web.py, e3_e4_e6_web.py, e5_llm_override.py
data/                   sms_mishra_soni_5971.csv (public, doi:10.17632/f45bkkt8pr.1), web/ snapshots
papers/                 lib/ieee.js (IEEE two-column layout), paper_a_vcc.js, paper_b_icmdrse.js,
                        authors.json, figures/, out/ (generated .docx)
tests/                  smoke tests on synthetic inputs (never report these numbers)
```

## How to run

```bash
pip install -r requirements.txt          # Python 3.10+
python -m pytest -q tests                # 3 smoke tests

# E1 (done; re-run to reproduce exactly - fixed seeds)
python experiments/e1_sms.py
python experiments/e1_sms.py --positive smishing spam --tag smishing_plus_spam
# E1 with transformer (Google Colab, GPU runtime): pip install torch transformers, then
python experiments/e1_sms.py --transformer distilbert-base-uncased
python experiments/e1_sms.py --positive smishing spam --tag smishing_plus_spam --transformer distilbert-base-uncased

# E2 email
python experiments/e2_email.py content --phish data/email/phishing.mbox --legit data/email/enron_ham/
python experiments/e2_email.py auth --live data/email/live      # live/legit/*.eml, live/spoof/*.eml

# E3-E6 website (run collection daily in a VM; it loads live phishing pages)
pip install playwright python-whois requests && playwright install chromium
python experiments/collect_web.py --phish 150 --legit 150
python experiments/e3_e4_e6_web.py
export OPENAI_API_KEY=...            # Windows: set OPENAI_API_KEY=...
python experiments/e5_llm_override.py --runs 3 --injection 30

# Rebuild both papers from whatever results exist
node papers/paper_a_vcc.js
node papers/paper_b_icmdrse.js
```

## Rules for the team

1. **Never type a number into the Word files by hand.** Re-run the experiment and rebuild the paper.
2. **If your original PhishSentry code differs** (detector regexes, weights, decay formula), change `phishsentry/` so it matches. Then re-run, so each paper describes the code you actually built.
3. **Do not submit the same paper to two venues.** Paper A covers SMS and email; Paper B covers the website engine. They cite each other and share no results.
4. **Spoofing tests** only from a domain you control, and only to your own inboxes. **Web collection** only in a VM: load pages, never submit anything.
5. Before submitting, check that `*_MISSING_RESULTS.txt` says 0 highlights. Then run plagiarism and PDF eXpress checks, and get sign-off from all authors.
