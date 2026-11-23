// Paper A - IEEE VCC 2027 (max 6 pages), SMS channel. Every number is read from results/*.json.
// Build:  node papers/paper_a_vcc.js   ->  papers/out/PaperA_VCC2027_PhishSentry.docx
const path = require("path"); const fs = require("fs");
const L = require("./lib/ieee");
const { P, H1, H2, Numbered, Eq, TableBlock, Figure, Abstract, Keywords, References, num, int, pm, pval, get, TBD } = L;

const S = "e1_sms_smishing", M = "e1_sms_smishing_plus_spam", R = "e1b_sms_robustness";
const sum = (f, v, k) => pm(`${f}:summary.${v}.${k}`);
const mean = (f, v, k, d = 2) => num(`${f}:summary.${v}.${k}.mean`, d);
const sig = (f, t) => get(`${f}:significance.${t}`);
const diff = (f, t) => { const s = sig(f, t); return s ? (s.mean_diff_pts >= 0 ? "+" : "−") + Math.abs(s.mean_diff_pts).toFixed(2) : TBD("TBD"); };
const pv = (f, t) => pval(`${f}:significance.${t}.p`);
const nraw = get(`${S}:n_raw`), n = get(`${S}:n`);
const dups = (nraw != null && n != null) ? String(nraw - n) : TBD("TBD");
const lc = (k) => int(`${S}:label_counts.${k}`);
const fpS = get(`${S}:stacked_errors_by_label.false_positives`) || {};
const fpTot = Object.values(fpS).reduce((a, b) => a + b, 0);
const spamShare = fpTot ? ((100 * (fpS.spam || 0)) / fpTot).toFixed(1) : TBD("TBD");
const hamFprPct = (get(`${S}:label_counts.ham`) && get(`${S}:repeats`))
  ? ((100 * (fpS.ham || 0)) / (get(`${S}:label_counts.ham`) * get(`${S}:repeats`))).toFixed(2) : TBD("TBD");
const lat = num(`${M}:latency.median_ms`, 2), lat95 = num(`${M}:latency.p95_ms`, 2);
const rr = (atk, v) => num(`${R}:recall.${atk}.${v}.mean`, 1);
const rdrop = (atk, v) => { const c = get(`${R}:recall.clean.${v}.mean`), a = get(`${R}:recall.${atk}.${v}.mean`);
  return (typeof c === "number" && typeof a === "number") ? (c - a).toFixed(1) : TBD("TBD"); };
const abl = (d) => { const v = get(`${R}:detector_ablation_delta_f1_pts.${d}.mean`); return typeof v === "number" ? (v >= 0 ? "+" : "−") + Math.abs(v).toFixed(2) : TBD("TBD"); };
const coef = (k) => num(`${R}:stacker_coefficients.${k}`, 2);
const DET = ["urgency", "credential", "financial", "url", "sentiment", "pattern"];

const body = [
  Abstract(
    `SMS phishing (smishing) reaches users on a personal channel where few filters and no explanations exist, and published detectors are often evaluated on a single split that mixes smishing with ordinary spam. We present the SMS engine of PhishSentry, which combines six interpretable heuristic detectors and a TF-IDF Naive Bayes model through a learned (stacked) fusion layer, and returns each verdict with the evidence behind it. On the public Mishra–Soni dataset (${int(`${S}:n`)} unique messages, 5×5-fold cross-validation, corrected significance tests), stacked fusion detects malicious SMS with ${mean(M, "stacked", "f1")}% F1 at a ${mean(M, "stacked", "fpr")}% false-positive rate, ${diff(M, "stacked_vs_naive_bayes")} points over Naive Bayes alone (p = ${pv(M, "stacked_vs_naive_bayes")}). Fixed-weight voting and a rule override, used in our earlier design, add nothing measurable. Separating smishing from commercial spam is harder (${mean(S, "stacked", "f1")}% F1), yet ${spamShare}% of those false alarms are spam and only ${hamFprPct}% of personal messages are flagged. Leetspeak, homoglyph, split-letter and defanged-link obfuscation lower the stacked detector\u2019s recall by at most ${rdrop("combined", "stacked")} points, and a normalisation step recovers most of the loss. A verdict takes ${lat} ms on one CPU core.`),
  Keywords("smishing, SMS phishing, mobile security, ensemble learning, stacking, explainable AI, adversarial obfuscation"),

  H1("Introduction"),
  P(`SMS remains a universal channel on mobile networks, and attackers exploit it to deliver phishing links, fake delivery and bank notices, and requests for one-time passwords [1], [2]. Smishing is effective because messages are short, arrive on a personal device, and are read in an environment with little filtering and no indication of why a message might be dangerous [2], [4]. Large language models now make convincing lure text cheap to produce [12], so filters must work on content that varies from message to message.`),
  P(`Many smishing detectors report high accuracy, but three gaps make their numbers hard to trust or use. First, evaluations often rely on one train/test split without significance testing, so small differences between methods may be noise. Second, smishing and commercial spam are frequently merged into one positive class, which hides where a detector actually fails. Third, few systems explain individual verdicts, which limits user trust and makes errors hard to audit [15].`),
  P(`This paper presents and evaluates the SMS engine of PhishSentry, a multi-channel phishing detector developed at Vishwakarma Institute of Technology. Our contributions are:`),
  ...Numbered([
    `A detector whose six interpretable heuristic bits are fused with a statistical text model by stacked generalisation [13]; it improves malicious-SMS detection over its strongest single layer with statistical significance, while fixed-weight voting does not (Sec. V-A).`,
    `An evaluation protocol that removes duplicate messages, uses repeated cross-validation with the corrected resampled t-test [14], tunes every threshold on validation data only, and reports the smishing–spam boundary separately (Sec. V-B).`,
    `A robustness study against four common obfuscation tricks and a lightweight normalisation defence (Sec. V-C), and an analysis of which detectors the fused model relies on (Sec. V-D).`,
    `An open implementation in which every number in this paper is generated from the experiment output files [18].`,
  ]),

  H1("Related Work"),
  H2("SMS spam and smishing detection"),
  P(`Early SMS filtering introduced the SMS Spam Collection and showed that token-based classifiers such as Naive Bayes work well on short texts [5], [6]. Mishra and Soni separated smishing from spam, released a labelled ham/spam/smishing dataset [3], and proposed detectors that combine content analysis with URL, source-code and APK checks [2], [4]. Their evaluations, like most in this area, report results from fixed splits, and the systems explain individual decisions only partially. Content-based filtering of phishing *email* has been surveyed extensively [7]; many of its features carry over to SMS.`),
  H2("Transformers and LLMs"),
  P(`Transformer encoders such as BERT and DistilBERT model context beyond keywords [9], [10], and LLMs can both generate and detect phishing text [12]. They improve accuracy on some text tasks but add memory, latency and, for hosted LLMs, per-message cost, which matters for filtering at carrier or handset scale. We therefore focus on a light, explainable pipeline and treat transformer layers as future work.`),
  H2("Obfuscation and explainability"),
  P(`Text classifiers can be evaded by small character-level edits such as substitutions and inserted separators [16]. Unicode homoglyphs, characters from other scripts that look like Latin letters, are a known spoofing vector [8], [17]. Post-hoc explainers such as LIME describe individual predictions of any model [15]; our detector instead builds its decision from named signals, so the explanation is part of the decision.`),

  H1("System Design"),
  ...Figure(path.join(L.ROOT, "papers", "figures", "fig_sms_email_pipeline.png"),
    `SMS engine of PhishSentry. An optional normalisation step undoes common obfuscation; heuristic detector bits and a Naive Bayes score are fused by logistic regression; the verdict is returned with its evidence.`),
  H2("Heuristic detectors"),
  P(`Six detectors encode cues that security-awareness guidance teaches users to notice: *urgency* (pressure to act quickly), *credential* (requests for OTP, PIN, password or account details), *financial* (money, prizes, refunds, bank actions), *URL* (links, including shortened ones), *sentiment* (fear or threat wording) and *pattern* (template phrases such as "dear customer" or "call [number] to claim"). Each detector *d*_{k} fires 0 or 1. Our earlier design also summarised them as a weighted score`),
  Eq("*S*_{h} = min(1, Σ_{k} *w*_{k} *d*_{k}),", 1),
  P(`with hand-set weights *w*_{k} between 0.10 and 0.25.`, { noIndent: true }),
  H2("Statistical layer"),
  P(`A Multinomial Naive Bayes classifier over TF-IDF unigrams and bigrams (smoothing α = 0.1) returns *S*_{nb} = *P*(malicious | message). It also provides the terms that contributed most to a positive decision, which we include in the explanation.`),
  H2("Fusion"),
  P(`The earlier PhishSentry design fused the layers with fixed weights and a rule override:`),
  Eq("*S* = α*S*_{h} + (1 − α)*S*_{nb},     *S*′ = max(*S*, *S*_{h}) if *S*_{h} ≥ θ.", 2),
  P(`We replace (2) with stacked generalisation [13]: a logistic-regression meta-classifier receives *S*_{h}, *S*_{nb} and the six detector bits and outputs the final probability`, { noIndent: true }),
  Eq("*P*(malicious) = σ(*b* + *v*_{h}*S*_{h} + *v*_{nb}*S*_{nb} + Σ_{k} *u*_{k} *d*_{k}).", 3),
  P(`Its coefficients *u*_{k} are a global explanation of how much each detector matters. For a fair comparison, α in (2), the meta-classifier and the decision threshold of every variant are fitted on a validation part of the training data only.`, { noIndent: true }),
  H2("Normalisation defence"),
  P(`Before scoring, an optional step maps Cyrillic and Greek look-alike letters to Latin [17], decodes digits and symbols that appear *inside* words (acc0unt → account, p@ypal → paypal), joins letters split by separators (v.e.r.i.f.y → verify), and restores defanged links (hxxp, [.]). Stand-alone numbers such as phone numbers, prices and times are left untouched.`),

  H1("Experimental Setup"),
  P(`**Data.** We use the public SMS phishing dataset of Mishra and Soni [3], which labels ${int(`${S}:n_raw`)} messages as ham, spam or smishing. Removing ${dups} exact duplicates (case- and whitespace-insensitive), which would otherwise leak between folds, leaves ${int(`${S}:n`)} messages: ${lc("ham")} ham, ${lc("spam")} spam and ${lc("smishing")} smishing. We study two tasks: **T1**, malicious (smishing or spam) versus ham, the setting of a carrier or handset filter; and **T2**, smishing versus all other messages, which isolates fraud attempts from commercial spam.`),
  P(`**Protocol.** Results use stratified 5-fold cross-validation repeated with ${int(`${S}:repeats`)} seeds (${get(`${S}:repeats`) ? 5 * get(`${S}:repeats`) : TBD("TBD")} train/test splits). Inside each training fold, 25% is held out to fit fusion weights, the meta-classifier and the F1-optimal threshold of every variant; the test fold is never used for tuning. We report precision (P), recall (R), F1 and false-positive rate (FPR) as mean ± standard deviation, and compare variants with the Nadeau–Bengio corrected resampled t-test, which accounts for the overlap between training sets [14]. The robustness study (Sec. V-C) uses ${int(`${R}:splits`)} splits; perturbations are applied only to malicious messages in the test fold. Experiments ran on ${get(`${S}:_machine.cpu`) ? `a Linux machine (${get(`${S}:_machine.cpu`)}, ${get(`${S}:_machine.logical_cpus`)} logical CPUs)` : TBD("TBD: CPU")} with scikit-learn [11].`),

  H1("Results"),
  H2("Malicious SMS detection (T1)"),
  ...TableBlock("SMS detection, malicious vs. ham (T1), %, mean ± std over 25 splits",
    ["Method", "P", "R", "F1", "FPR"],
    [["Heuristic only", "heuristic"], ["Naive Bayes only", "naive_bayes"],
     ["Fixed-weight fusion (2)", "ensemble"], ["**Stacked fusion (3)**", "stacked"]].map(([l, v]) =>
      [l, sum(M, v, "precision"), sum(M, v, "recall"), sum(M, v, "f1"), sum(M, v, "fpr")]),
    [4.4, 3.2, 3.2, 3.2, 3.2]),
  P(`Stacked fusion is the best variant on every metric (Table I). It improves F1 by ${diff(M, "stacked_vs_naive_bayes")} points over Naive Bayes (p = ${pv(M, "stacked_vs_naive_bayes")}) and by ${diff(M, "stacked_vs_ensemble")} points over fixed-weight fusion (p = ${pv(M, "stacked_vs_ensemble")}), and lowers the false-positive rate to ${mean(M, "stacked", "fpr")}% with less variance. Fixed-weight fusion is indistinguishable from Naive Bayes alone (${diff(M, "ensemble_vs_naive_bayes")} points, p = ${pv(M, "ensemble_vs_naive_bayes")}): on validation data the tuned weight α mostly ignores the heuristic score, and the rule override never changed a decision (${diff(M, "override_effect")} points). The heuristic score alone is weak (F1 ${mean(M, "heuristic", "f1")}%), but its individual bits are useful inputs to the meta-classifier (Sec. V-D).`),
  H2("Smishing versus spam (T2)"),
  ...TableBlock("Smishing vs. all other messages (T2), %, mean ± std over 25 splits",
    ["Method", "P", "R", "F1", "FPR"],
    [["Heuristic only", "heuristic"], ["Naive Bayes only", "naive_bayes"],
     ["Fixed-weight fusion (2)", "ensemble"], ["Stacked fusion (3)", "stacked"]].map(([l, v]) =>
      [l, sum(S, v, "precision"), sum(S, v, "recall"), sum(S, v, "f1"), sum(S, v, "fpr")]),
    [4.4, 3.2, 3.2, 3.2, 3.2]),
  P(`Separating smishing from spam is markedly harder (Table II). All learned variants reach about ${mean(S, "stacked", "f1", 1)}% F1 and differ by less than their standard deviation (stacked vs. Naive Bayes: ${diff(S, "stacked_vs_naive_bayes")} points, p = ${pv(S, "stacked_vs_naive_bayes")}). The error analysis explains why: ${spamShare}% of stacked fusion's false positives are spam messages, and only ${hamFprPct}% of personal (ham) messages are ever flagged. Many spam messages in the corpus use the same lures as smishing, such as premium-rate call-backs and "you have won" prizes, so the boundary between the two classes is partly a matter of labelling. For users this error is benign, because a flagged spam message is still unwanted. Reporting T1 and T2 separately makes this visible; a single merged score would hide it.`),
  H2("Robustness to obfuscation"),
  ...TableBlock("Recall (%) on T1 when malicious test messages are obfuscated",
    ["Obfuscation", "NB", "Stacked", "NB + norm.", "Stacked + norm."],
    [["None (clean)", "clean"], ["Leetspeak", "leetspeak"], ["Homoglyphs", "homoglyph"], ["Split letters", "split_letters"],
     ["Defanged links", "defanged_links"], ["**All combined**", "combined"]].map(([l, a]) =>
      [l, rr(a, "naive_bayes"), rr(a, "stacked"), rr(a, "naive_bayes+norm"), rr(a, "stacked+norm")]),
    [4.2, 2.4, 2.8, 3, 3.6]),
  P(`We rewrote malicious test messages with leetspeak (letters replaced by digits), Cyrillic homoglyphs, letters split by dots, and defanged links, each applied to a random subset of words, and all four combined (e.g., "ver1fy your 4ccount now at hxxp://sbi-kyc[.]com"). Table III shows the detectors degrade gracefully: the combined attack lowers recall by ${rdrop("combined", "naive_bayes")} points for Naive Bayes and ${rdrop("combined", "stacked")} points for stacked fusion, because most messages still contain unmodified lure words. With normalisation, recall under the combined attack is ${rr("combined", "stacked+norm")}%, against ${rr("clean", "stacked")}% on clean text, while the clean false-positive rate stays at ${num(`${R}:clean_fpr.stacked+norm.mean`, 2)}%. Attacks that rewrite every word, or paraphrase the message with an LLM, are not covered by this test.`),
  H2("Which detectors matter"),
  ...TableBlock("Detector analysis on T1: firing rate, stacking coefficient, and F1 change when the detector is removed",
    ["Detector", "Fires on malicious (%)", "Fires on ham (%)", "Coef. u_{k}", "ΔF1 (pts)"],
    DET.map((d) => [d, num(`${M}:detector_firing.${d}.positive_%`, 1), num(`${M}:detector_firing.${d}.negative_%`, 1), coef(`det_${d}`), abl(d)]),
    [3, 3, 2.6, 2.4, 2.4]),
  P(`Table IV shows that the fused model relies mainly on three detectors: *pattern*, *financial* and *URL* have the largest coefficients, and removing them costs ${abl("pattern")}, ${abl("financial")} and ${abl("url")} F1 points respectively. *Urgency*, *credential* and *sentiment* fire rarely in this corpus and their removal changes F1 by less than 0.1 points; they remain useful as explanations shown to users, but could be dropped from scoring. Naive Bayes carries the largest single weight (coefficient ${coef("naive_bayes")}).`),
  H2("Explanations and latency"),
  P(`Every verdict lists the detectors that fired, the per-layer scores and the most indicative terms. For example, the message "${(get(`${M}:examples.0.text`) || "").replace(/[^\x20-\x7E]/g, "").slice(0, 70)}…" receives probability ${num(`${M}:examples.0.score`, 2)}; the explanation reports the *${(get(`${M}:examples.0.detectors_fired`) || []).join(", ")}* detector and the terms "${(get(`${M}:examples.0.nb_terms`) || []).join('", "')}". The full pipeline scores a message in ${lat} ms median (${lat95} ms at the 95th percentile) on one CPU core, fast enough for gateway-level filtering.`),

  H1("Limitations and Ethics"),
  P(`The corpus is English, partly dated, and contains few lures now common in India, such as UPI, KYC, courier and electricity-bill messages; results may not transfer to multilingual traffic. Our obfuscation test perturbs a subset of words and does not cover LLM paraphrasing. We did not evaluate transformer layers, which may separate smishing from spam better. The dataset is public; no personal messages were collected.`),

  H1("Conclusion"),
  P(`We evaluated the SMS engine of PhishSentry with a protocol designed to avoid optimistic results: de-duplicated data, repeated cross-validation, thresholds tuned only on validation data, and a corrected significance test. Stacking interpretable detector bits with a Naive Bayes score detects malicious SMS with ${mean(M, "stacked", "f1")}% F1 and ${mean(M, "stacked", "fpr")}% FPR, significantly better than its strongest single layer, while fixed-weight voting and rule overrides add nothing. Residual errors lie almost entirely on the smishing–spam boundary, not on personal messages, and simple normalisation counters common obfuscation. Future work will add multilingual Indian smishing data, a fine-tuned transformer layer, and joint evaluation with PhishSentry's email and web engines.`),

  H1("References", false),
  ...References([
    `M. Khonji, Y. Iraqi, and A. Jones, "Phishing detection: A literature survey," *IEEE Commun. Surveys Tuts.*, vol. 15, no. 4, pp. 2091–2121, 2013, doi: 10.1109/SURV.2013.032213.00009.`,
    `S. Mishra and D. Soni, "Smishing Detector: A security model to detect smishing through SMS content analysis and URL behavior analysis," *Future Gener. Comput. Syst.*, 2020, doi: 10.1016/j.future.2020.03.021.`,
    `S. Mishra and D. Soni, "SMS phishing dataset for machine learning and pattern recognition," Mendeley Data, V1, 2022, doi: 10.17632/f45bkkt8pr.1.`,
    `S. Mishra and D. Soni, "DSmishSMS—A system to detect smishing SMS," *Neural Comput. Appl.*, 2023, doi: 10.1007/s00521-021-06305-y.`,
    `T. A. Almeida, J. M. G. Hidalgo, and A. Yamakami, "Contributions to the study of SMS spam filtering: New collection and results," in *Proc. ACM DocEng*, 2011, pp. 259–262.`,
    `G. V. Cormack, J. M. G. Hidalgo, and E. P. Sanz, "Feature engineering for mobile (SMS) spam filtering," in *Proc. ACM SIGIR*, 2007, pp. 871–872.`,
    `A. Almomani, B. B. Gupta, S. Atawneh, A. Meulenberg, and E. Almomani, "A survey of phishing email filtering techniques," *IEEE Commun. Surveys Tuts.*, vol. 15, no. 4, pp. 2070–2090, 2013.`,
    `Unicode Consortium, "Unicode Security Considerations," Unicode Technical Report #36.`,
    `J. Devlin, M.-W. Chang, K. Lee, and K. Toutanova, "BERT: Pre-training of deep bidirectional transformers for language understanding," in *Proc. NAACL-HLT*, 2019, pp. 4171–4186.`,
    `V. Sanh, L. Debut, J. Chaumond, and T. Wolf, "DistilBERT, a distilled version of BERT: Smaller, faster, cheaper and lighter," arXiv:1910.01108, 2019.`,
    `F. Pedregosa *et al.*, "Scikit-learn: Machine learning in Python," *J. Mach. Learn. Res.*, vol. 12, pp. 2825–2830, 2011.`,
    `F. Heiding, B. Schneier, A. Vishwanath, J. Bernstein, and P. S. Park, "Devising and detecting phishing emails using large language models," *IEEE Access*, vol. 12, pp. 42131–42146, 2024, doi: 10.1109/ACCESS.2024.3375882.`,
    `D. H. Wolpert, "Stacked generalization," *Neural Networks*, vol. 5, no. 2, pp. 241–259, 1992.`,
    `C. Nadeau and Y. Bengio, "Inference for the generalization error," *Mach. Learn.*, vol. 52, no. 3, pp. 239–281, 2003.`,
    `M. T. Ribeiro, S. Singh, and C. Guestrin, "‘Why should I trust you?’: Explaining the predictions of any classifier," in *Proc. ACM SIGKDD*, 2016, pp. 1135–1144.`,
    `J. Li, S. Ji, T. Du, B. Li, and T. Wang, "TextBugger: Generating adversarial text against real-world applications," in *Proc. NDSS*, 2019.`,
    `Unicode Consortium, "Unicode Security Mechanisms," Unicode Technical Standard #39.`,
    `${get("_github:url") || TBD("TBD: GitHub URL of phishsentry-research")}`,
  ]),
];

const authors = require("./authors.json");
fs.mkdirSync(path.join(L.ROOT, "papers", "out"), { recursive: true });
L.build({ title: "Explainable Learned Fusion for Robust SMS Phishing Detection: A Statistically Validated Study of Smishing Filters",
  authors, body, out: path.join(L.ROOT, "papers", "out", "PaperA_VCC2027_PhishSentry.docx") });
