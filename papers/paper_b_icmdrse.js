// Paper B - ICMDRSE-2027 (website engine). Numbers come from results/e3_web.json,
// e4_aggregation.json and e5_llm_override.json; until those exist they show as [TBD].
// Build:  node papers/paper_b_icmdrse.js  ->  papers/out/PaperB_ICMDRSE2027_PhishSentry.docx
const path = require("path"); const fs = require("fs");
const L = require("./lib/ieee");
const { P, H1, H2, Bullets, Numbered, Eq, TableBlock, Figure, Abstract, Keywords, References, num, int, get, has, TBD } = L;

const W = "e3_web", A4 = "e4_aggregation", L5 = "e5_llm_override";
const pc = (spec, d = 2) => num(spec, d, 100);           // fraction -> %
const m = (variant, k, d = 2) => pc(`${W}:${variant}.${k}`, d);
const e5 = (mode, k, d = 2) => pc(`${L5}:${mode}.${k}`, d);
const abl = (n) => get(`${W}:ablation.${n}.delta_f1`);
const fmtDelta = (v) => (typeof v === "number" ? (v >= 0 ? "+" : "") + (v * 100).toFixed(2) : TBD("TBD"));
const best = (() => {
  const a = get(`${W}:ablation`); if (!a) return null;
  return Object.entries(a).sort((x, y) => x[1].delta_f1 - y[1].delta_f1)[0];
})();
const sensFig = path.join(L.ROOT, "papers", "figures", "fig_sensitivity.png");

const body = [
  Abstract(
    `Phishing pages now live for hours, imitate brands pixel by pixel and are increasingly written with the help of large language models, so blacklists and single classifiers miss many of them. We present the web engine of PhishSentry, which renders each URL in a sandboxed browser, runs eight explainable rule analyzers, aggregates their signals with a diminishing-returns trust score, and lets a vision-capable LLM revise that score. We collected ${int(`${W}:n`)} live pages (${int(`${W}:n_phish`)} phishing from OpenPhish, ${int(`${W}:n_legit`)} legitimate from the Tranco list) and froze each one as a snapshot so every experiment is repeatable. On held-out pages the rule engine alone reaches ${m("phishsentry", "f1")}% F1 at ${m("phishsentry", "fpr")}% false-positive rate, versus ${m("additive_baseline", "f1")}% for plain additive scoring and ${m("url_random_forest", "f1")}% for a URL-feature Random Forest. Bounded LLM revision reaches ${e5("bounded", "f1")}% F1; letting the LLM replace the score outright reaches ${e5("replace", "f1")}%. We also measure how often the LLM corrects or breaks a decision, its run-to-run consistency, its robustness to injected instructions, and its cost per page.`),
  Keywords("phishing detection, explainable AI, large language models, vision-language models, prompt injection, web security"),

  H1("Introduction"),
  P(`Phishing websites remain the most common way to steal credentials and payment data [1]. Most phishing domains are active for only a short time before they are reported [8], so blacklists such as Google Safe Browsing protect users only after a page has already been seen and reported [9]. Learning-based detectors trained on URL or HTML features adapt better [4], [10], but they are opaque, and attackers change exactly those surface features. Visual detectors compare a page's appearance with known brands [6], [7], and recent work uses large language models (LLMs) to judge a whole page in context [11].`),
  P(`LLM-based detection raises three practical questions that are rarely measured together: does the LLM actually improve on a strong explainable baseline, or does it just replace it; is its verdict stable across runs; and can text planted on the page steer it [13]? We study these questions with PhishSentry, a multi-channel detector whose SMS engine is described in a companion paper [12]. This paper covers its web engine. Our contributions are:`),
  ...Numbered([
    `An explainable web engine: eight rule analyzers whose signals are aggregated with a diminishing-returns, exponential-decay trust score, tuned on validation data and checked for sensitivity (Sec. III, V-B).`,
    `A controlled comparison of three ways to combine that score with a vision LLM—off, replace and bounded revision—including decisions corrected versus broken, consistency over repeated calls, prompt-injection robustness and cost (Sec. V-C).`,
    `An ablation that quantifies each analyzer's contribution, and a comparison with additive scoring, a URL-feature classifier and blacklist lookup at collection time (Sec. V-A).`,
    `A snapshot-based collection protocol and open code, so all results can be reproduced after the phishing pages go offline [14].`,
  ]),

  H1("Related Work"),
  P(`**Heuristic and feature-based detection.** CANTINA scored pages with TF-IDF terms and search-engine lookups [2]; CANTINA+ added structural HTML features and a learned classifier [3]. Many later systems learn from URL lexical features [4], [10]. **Visual detection.** PhishZoo compared page appearance and logos with trusted sites [6]; Phishpedia identifies the brand logo with deep learning and checks it against the domain [7]. **LLM-based detection.** ChatPhishDetector crawls a site and asks an LLM to identify impersonated brands and social-engineering cues, reporting high accuracy without training [11]; LLMs also generate convincing phishing text [15]. **Prompt injection.** LLMs that read untrusted content can be steered by instructions hidden in it [13], a direct risk for any detector that shows attacker-controlled pages to an LLM. **Explainability.** Model-agnostic explainers such as LIME and SHAP explain individual predictions after the fact [16], [17]; PhishSentry instead builds its verdict from named signals, so the explanation is the decision itself.`),

  H1("System Design"),
  ...Figure(path.join(L.ROOT, "papers", "figures", "fig_web_pipeline.png"),
    `Web engine of PhishSentry. The sandbox renders the page once; rule analyzers emit weighted signals; the aggregation engine turns them into a trust score; the vision LLM may revise it under one of three override modes.`),
  H2("Sandboxed acquisition"),
  P(`Each URL is opened in headless Chromium through Playwright with downloads disabled. After the load event and a short delay for client-side scripts, the engine stores the final URL after redirects, the rendered DOM, a 1280×800 screenshot, the TLS certificate status, the domain's registration age and, when available, the Safe Browsing verdict at that moment. Analysing this frozen snapshot rather than the live URL makes every result reproducible.`),
  H2("Rule analyzers"),
  P(`Eight analyzers emit named signals with weights (Table I). Each signal is also an explanation shown to the user.`),
  ...TableBlock("Rule analyzers and example signals (weight)",
    ["Analyzer", "Example signals"],
    [["URL lexical", "IP host (0.20), punycode (0.15), '@' in URL (0.10), long URL (0.05)"],
     ["Typosquatting", "edit distance 1–2 to a brand (0.25), brand inside domain (0.20)"],
     ["Domain age", "< 30 days (0.20), < 180 days (0.05)"],
     ["TLS", "invalid or expired certificate (0.20), no HTTPS (0.10)"],
     ["Forms", "form posts to another domain (0.25), mailto form (0.20)"],
     ["Scripts", "hidden iframe (0.15), obfuscated script (0.10)"],
     ["Links", "mostly empty links (0.10), mostly external links (0.10)"],
     ["Content", "brand in title but not in domain (0.20), no legal pages (0.05)"]],
    [2, 6]),
  H2("Risk aggregation"),
  P(`Signals with weight *w*_{i} ≥ *c* are critical, the rest minor. Many weak signals should not outweigh one strong one, so minor risk grows with diminishing returns:`),
  Eq("*R*_{c} = Σ_{w_i ≥ c} *w*_{i},    *R*_{s} = *k*·(Σ_{w_i < c} *w*_{i})^{*e*},", 1),
  Eq("*T* = 100 · *d*^{100(R_c + R_s)},   0 ≤ *T* ≤ 100,", 2),
  P(`where *T* is the trust score and *d* < 1 a decay rate. Pages with *T* ≥ 75 are safe, 45 ≤ *T* < 75 suspicious, and *T* < 45 high risk; we treat suspicious and high risk as phishing. The constants (*c*, *k*, *e*, *d*) were originally set by hand (0.15, 0.7, 0.5, 0.95); here we tune them by grid search on a validation split ${get(`${W}:tuned_params`) ? `(selected: ${["critical_min", "scale", "exponent", "decay"].map((k) => get(`${W}:tuned_params.${k}`)).join(", ")})` : TBD("TBD: tuned values")} and report their sensitivity.`, { noIndent: true }),
  H2("Vision-LLM revision"),
  P(`The LLM receives the screenshot, the final URL and the list of fired signals, and returns JSON with a phishing verdict, the impersonated brand and a predicted trust score. The system prompt states that page content is untrusted data and must not be obeyed. We run it at temperature 0 and cache every response. We compare three modes: **off** (rules only); **replace**, the original PhishSentry design, where the LLM's score replaces *T*; and **bounded**, our proposal, where the LLM may move *T* by at most ±30 points, so a single model error cannot override strong rule evidence. A phishing or impersonation verdict also switches (2) to a faster decay (*d* = 0.90) and lowers the suspicious cut-off to 40.`),

  H1("Experimental Setup"),
  P(`**Data.** Over ${TBD("TBD: N days, start–end dates")} we sampled phishing URLs from the OpenPhish community feed and legitimate sites from ranks 1–100,000 of the Tranco list [18], so the legitimate set is not limited to famous brands. After removing pages that failed to load we kept ${int(`${W}:n_phish`)} phishing and ${int(`${W}:n_legit`)} legitimate snapshots. **Split.** A stratified 30% validation split is used only to tune the aggregation constants and to train the Random Forest baseline; all numbers are reported on the remaining ${int(`${W}:n_test`)} test pages. **Baselines.** (i) Additive scoring, *T* = 100 − 100·Σ*w*_{i}; (ii) a Random Forest on 15 URL lexical features [4]; (iii) the Safe Browsing verdict recorded at collection time, which shows how many fresh phishing pages a blacklist had not yet listed. **LLM.** ${get(`${L5}:model`) || TBD("TBD: model snapshot")}, prompt version ${get(`${L5}:prompt_version`) || TBD("TBD")}, ${TBD("TBD: number of runs")} runs per page for consistency; ${int(`${L5}:prompt_injection.pages`)} phishing pages copied with a hidden instruction claiming the page is verified, for the injection test. **Metrics.** Precision, recall, F1, false-positive rate (FPR), ROC-AUC, latency and API cost.`),

  H1("Results"),
  H2("Detection and baselines"),
  ...TableBlock("Detection on held-out pages, %",
    ["Method", "P", "R", "F1", "FPR"],
    [["Blacklist at collection", "blacklist_at_collection"], ["URL Random Forest", "url_random_forest"], ["Additive scoring", "additive_baseline"],
     ["Rules, hand-set constants", "phishsentry_default_constants"], ["**Rules, tuned (ours)**", "phishsentry"]].map(([l, v]) =>
      [l, m(v, "precision"), m(v, "recall"), m(v, "f1"), m(v, "fpr")]),
    [5, 3, 3, 3, 3]),
  P(`Table II compares the rule engine with the baselines. ${has(W) ? `Tuned diminishing-returns aggregation reaches ${m("phishsentry", "f1")}% F1 against ${m("additive_baseline", "f1")}% for additive scoring at the same cut-off, and its false-positive rate is ${m("phishsentry", "fpr")}% versus ${m("additive_baseline", "fpr")}%. ${get(`${W}:blacklist_at_collection`) ? `The blacklist caught only ${m("blacklist_at_collection", "recall")}% of phishing pages at the time we collected them, which illustrates the zero-day gap.` : ""}` : TBD("TBD: interpret Table II after running E3 - say which method wins and by how much; if a baseline wins, say so")}`),
  ...TableBlock("Ablation: F1 change when one analyzer is removed (points)",
    ["Analyzer removed", "ΔF1", "FPR (%)"],
    ["url", "typosquat", "domain", "ssl", "forms", "scripts", "links", "content"].map((n) =>
      [n, fmtDelta(abl(n)), pc(`${W}:ablation.${n}.fpr`)]), [4, 3, 3]),
  P(best ? `Removing the *${best[0]}* analyzer costs the most (${fmtDelta(best[1].delta_f1)} points F1). ${TBD("TBD: one or two sentences on which analyzers matter and which could be dropped")}` : TBD("TBD: interpret Table III after running E3"), { noIndent: false }),
  H2("Aggregation constants"),
  ...(fs.existsSync(sensFig) ? Figure(sensFig, "F1 on test pages when one aggregation constant is moved between 80% and 120% of its tuned value.")
    : [P(TBD("TBD: sensitivity figure appears here after E3/E4"), { noIndent: true })]),
  P(has(A4) ? `${TBD("TBD: describe Fig. 3 - how much F1 changes when each constant moves ±20%; a flat curve means the result does not hinge on a lucky constant")}` : TBD("TBD: run E3/E4"), { noIndent: true }),
  H2("Does the LLM help?"),
  ...TableBlock("Combining the rule score with the vision LLM",
    ["Mode", "F1 (%)", "FPR (%)", "Flips", "Corrected", "Broken"],
    [["Off (rules only)", "off"], ["Replace (original)", "replace"], ["**Bounded ±30 (ours)**", "bounded"]].map(([l, k]) =>
      [l, e5(k, "f1"), e5(k, "fpr"), k === "off" ? "–" : int(`${L5}:flips_${k}.total`),
       k === "off" ? "–" : int(`${L5}:flips_${k}.corrected`), k === "off" ? "–" : int(`${L5}:flips_${k}.broke`)]),
    [4.5, 2, 2, 1.5, 2, 1.8]),
  P(has(L5) ? `${TBD("TBD: interpret Table IV - does replace or bounded beat rules only; how many decisions did the LLM break")} Across repeated calls, the LLM's verdict was identical for ${num(`${L5}:consistency_all_runs_agree_%`, 1)}% of pages. Of ${int(`${L5}:prompt_injection.pages`)} phishing pages with an injected instruction, the LLM was fooled on ${int(`${L5}:prompt_injection.llm_fooled`)}. Under bounded revision, such an error can raise the trust score by at most 30 points, so pages with strong rule evidence stay flagged. The LLM adds ${num(`${L5}:latency_llm.median_ms`, 0)} ms median latency and about US$${num(`${L5}:cost_usd_per_page`, 4)} per page, against ${num(`${W}:latency_heuristic.median_ms`, 1)} ms for the rule engine.`
    : TBD("TBD: run E5 (needs OPENAI_API_KEY) and interpret Table IV, consistency, injection and cost here")),

  H1("Discussion and Limitations"),
  P(`OpenPhish pages are confirmed phishing, which may make them easier than pages that evade every feed; legitimate pages are drawn from popular sites. Domain-age lookups fail for some registries. The LLM is a commercial API whose behaviour can change between snapshots; we fix and report the snapshot, cache every answer, and publish the cache. We did not interact with phishing pages beyond loading them, submitted no data, and collected pages inside an isolated virtual machine.`),

  H1("Conclusion"),
  P(`${has(W) && has(L5) ? TBD("TBD: two-sentence summary with the headline numbers from Tables II and IV") : TBD("TBD: conclusion with headline numbers once E3-E5 are run")} PhishSentry's web engine shows that an explainable rule layer can serve as the backbone of LLM-assisted phishing detection, with the LLM used to revise rather than replace a decision. Future work covers multilingual Indian phishing pages, an open-weights vision model run locally, and evaluation on campaigns that span web, SMS and email together [12].`),

  H1("References", false),
  ...References([
    `M. Khonji, Y. Iraqi, and A. Jones, "Phishing detection: A literature survey," *IEEE Commun. Surveys Tuts.*, vol. 15, no. 4, pp. 2091–2121, 2013.`,
    `Y. Zhang, J. I. Hong, and L. F. Cranor, "CANTINA: A content-based approach to detecting phishing web sites," in *Proc. WWW*, 2007, pp. 639–648.`,
    `G. Xiang, J. Hong, C. P. Rose, and L. Cranor, "CANTINA+: A feature-rich machine learning framework for detecting phishing web sites," *ACM Trans. Inf. Syst. Secur.*, vol. 14, no. 2, Art. 21, 2011.`,
    `O. K. Sahingoz, E. Buber, O. Demir, and B. Diri, "Machine learning based phishing detection from URLs," *Expert Syst. Appl.*, vol. 117, pp. 345–357, 2019.`,
    `A. K. Jain and B. B. Gupta, "Towards detection of phishing websites on client-side using machine learning based approach," *Telecommun. Syst.*, vol. 68, pp. 687–700, 2018.`,
    `S. Afroz and R. Greenstadt, "PhishZoo: Detecting phishing websites by looking at them," in *Proc. IEEE ICSC*, 2011, pp. 368–375.`,
    `Y. Lin *et al.*, "Phishpedia: A hybrid deep learning based approach to visually identify phishing webpages," in *Proc. USENIX Security Symp.*, 2021.`,
    `D. K. McGrath and M. Gupta, "Behind phishing: An examination of phisher modi operandi," in *Proc. USENIX LEET*, 2008.`,
    `Google, "Safe Browsing," Google for Developers. [Online]. Available: https://developers.google.com/safe-browsing`,
    `Y. Yang, G. Zhao, and P. Zeng, "Phishing website detection based on multidimensional features driven by deep learning," *IEEE Access*, vol. 7, pp. 15196–15209, 2019.`,
    `T. Koide, H. Nakano, and D. Chiba, "ChatPhishDetector: Detecting phishing sites using large language models," *IEEE Access*, vol. 12, pp. 154381–154400, 2024, doi: 10.1109/ACCESS.2024.3483905.`,
    `N. Korade, S. Dudhanale, S. Deogaonkar, A. Deokar, and S. Dodikindiwad, "Explainable learned fusion for robust SMS phishing detection: A statistically validated study of smishing filters," under review, 2026.`,
    `K. Greshake *et al.*, "Not what you've signed up for: Compromising real-world LLM-integrated applications with indirect prompt injection," in *Proc. ACM AISec*, 2023.`,
    `${TBD("TBD: GitHub URL of phishsentry-research")}`,
    `F. Heiding, B. Schneier, A. Vishwanath, J. Bernstein, and P. S. Park, "Devising and detecting phishing emails using large language models," *IEEE Access*, vol. 12, pp. 42131–42146, 2024.`,
    `M. T. Ribeiro, S. Singh, and C. Guestrin, "‘Why should I trust you?’: Explaining the predictions of any classifier," in *Proc. ACM SIGKDD*, 2016, pp. 1135–1144.`,
    `S. M. Lundberg and S.-I. Lee, "A unified approach to interpreting model predictions," in *Proc. NeurIPS*, 2017, pp. 4765–4774.`,
    `V. Le Pochat, T. Van Goethem, S. Tajalizadegan, M. Korczyński, and W. Joosen, "Tranco: A research-oriented top sites ranking hardened against manipulation," in *Proc. NDSS*, 2019.`,
  ]),
];

const authors = require("./authors.json");
fs.mkdirSync(path.join(L.ROOT, "papers", "out"), { recursive: true });
L.build({ title: "Should a Vision LLM Revise or Replace? Explainable Website Phishing Detection with LLM-Assisted Trust Scoring",
  authors, body, out: path.join(L.ROOT, "papers", "out", "PaperB_ICMDRSE2027_PhishSentry.docx") });
