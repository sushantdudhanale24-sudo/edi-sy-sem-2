# Fig. 1 of Paper A: SMS pipeline (file name kept for the build script)
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
plt.rcParams["font.family"] = "Liberation Serif"; plt.rcParams["mathtext.fontset"] = "stix"
fig, ax = plt.subplots(figsize=(3.5, 2.45), dpi=400)
ax.set_xlim(0, 100); ax.set_ylim(0, 70); ax.axis("off")
FS = 6.6
def box(x, y, w, h, t, fc="#ffffff"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.4,rounding_size=1.2", fc=fc, ec="#333333", lw=0.6))
    ax.text(x + w/2, y + h/2, t, ha="center", va="center", fontsize=FS, linespacing=1.12)
def arr(x1, y1, x2, y2):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1), arrowprops=dict(arrowstyle="-|>", lw=0.6, color="#333333", mutation_scale=5))
G, B = "#eef3f8", "#f6f1e7"
box(1, 47, 15, 16, "Incoming\nSMS", fc=G)
box(21, 47, 20, 16, "Normalise\n(homoglyphs,\nleet, splits)")
box(47, 56, 25, 10, "6 heuristic\ndetectors (bits)")
box(47, 41, 25, 10, "TF-IDF + Naive\nBayes → $S_{nb}$")
box(78, 43, 21, 21, "Stacked\nfusion:\nlogistic\nregression", fc=B)
arr(16.5, 55, 20.5, 55); arr(41.5, 57, 46.5, 61); arr(41.5, 53, 46.5, 46)
arr(72.5, 61, 77.5, 57); arr(72.5, 46, 77.5, 50)
box(10, 6, 80, 22, "Verdict + explanation:\nphishing probability, detectors that fired,\nNaive Bayes terms that pushed the score up,\nper-layer scores")
arr(88.5, 42.5, 76, 28.5)
ax.text(31, 43.5, "optional defence", ha="center", fontsize=5.4, style="italic", color="#555555")
plt.savefig("fig_sms_email_pipeline.png", bbox_inches="tight", pad_inches=0.02)
