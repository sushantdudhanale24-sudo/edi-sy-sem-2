import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
plt.rcParams["font.family"] = "Liberation Serif"; plt.rcParams["mathtext.fontset"] = "stix"
fig, ax = plt.subplots(figsize=(3.5, 3.9), dpi=400)
ax.set_xlim(0, 104); ax.set_ylim(0, 112); ax.axis("off")
FS = 6.5
def box(x, y, w, h, t, fc="#ffffff"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.4,rounding_size=1.2", fc=fc, ec="#333333", lw=0.6))
    ax.text(x + w/2, y + h/2, t, ha="center", va="center", fontsize=FS, linespacing=1.12)
def arr(x1, y1, x2, y2):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1), arrowprops=dict(arrowstyle="-|>", lw=0.6, color="#333333", mutation_scale=5))
G, B, Y = "#eef3f8", "#f6f1e7", "#eef6ee"
box(1, 97, 30, 11, "URL", fc=G)
box(38, 97, 61, 11, "Headless Chromium sandbox:\nrender, DOM, screenshot, TLS, WHOIS")
arr(31.5, 102.5, 37.5, 102.5)
ax.text(1, 89, "Rule analyzers (signals with weights)", fontsize=6.8, weight="bold")
names = ["URL lexical", "Typosquatting", "Domain age", "TLS / SSL", "Forms", "Scripts / iframes", "Links", "Content / legal"]
for i, n in enumerate(names):
    x = 1 + (i % 4) * 25; y = 75 - (i // 4) * 11
    box(x, y, 22.5, 8, n)
arr(75, 96.5, 75, 84.5)
box(1, 41, 56, 15, "Aggregation: critical vs minor\nsignals, diminishing returns,\ntrust $T = 100\\,d^{100R_t}$", fc=B)
box(62, 41, 37, 15, "Vision LLM on\nscreenshot + signals\n(cached, temp 0)", fc=Y)
arr(50, 63.5, 29, 56.5); ax.plot([99.6, 102.5, 102.5], [102.5, 102.5, 60], color="#333333", lw=0.6); arr(102.5, 60, 92, 56.6)
ax.text(103.3, 80, "screenshot", rotation=90, fontsize=5.6, va="center")
arr(57.5, 48.5, 61.5, 48.5)
box(12, 18, 76, 15, "Override rule: off  |  replace (original)  |\nbounded ±30 pts (proposed); AI flag\n→ faster decay, lower suspicious cut-off", fc=B)
arr(29, 40.5, 40, 33.5); arr(80.5, 40.5, 65, 33.5)
box(12, 1, 76, 11, "Safe / Suspicious / High risk + explanation\n(signals fired, LLM reasons)")
arr(50, 17.5, 50, 12.5)
plt.savefig("fig_web_pipeline.png", bbox_inches="tight", pad_inches=0.02)
