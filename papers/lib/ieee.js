// IEEE two-column conference layout for docx-js, plus a results lookup that
// never invents numbers: anything missing from results/*.json renders as a
// yellow-highlighted [TBD: ...] so it is impossible to miss before submission.
const fs = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, ImageRun, Table, TableRow, TableCell,
  AlignmentType, WidthType, BorderStyle, SectionType, TabStopType, ShadingType,
} = require("docx");

const ROOT = path.resolve(__dirname, "..", "..");
const RES = process.env.PHISHSENTRY_RESULTS_DIR || path.join(ROOT, "results");
const FONT = "Times New Roman";
const COL_W = 5040;            // 3.5 in column in DXA
const PT = (n) => n * 2;       // half-points

// ------------------------------------------------------------------ results
const cache = {};
function load(name) {
  if (!(name in cache)) {
    const p = path.join(RES, name + ".json");
    cache[name] = fs.existsSync(p) ? JSON.parse(fs.readFileSync(p, "utf8")) : null;
  }
  return cache[name];
}
function get(spec) {               // "file:a.b.c"
  const [file, key] = spec.split(":");
  let v = load(file);
  if (v == null) return undefined;
  for (const k of key.split(".")) { if (v == null) return undefined; v = v[k]; }
  return v;
}
const TBD = (label) => `«${label}»`;
const MISSING = new Set();
const TBD_TEXT = [];
const miss = (spec) => { MISSING.add(spec.split(":")[0] + "  (" + (spec.split(":")[1] || "") + ")"); return TBD("TBD"); };
// value formatters ------------------------------------------------------------
function num(spec, digits = 2, scale = 1) {
  const v = get(spec);
  return typeof v === "number" ? (v * scale).toFixed(digits) : miss(spec);
}
function int(spec) {
  const v = get(spec);
  return typeof v === "number" ? Math.round(v).toLocaleString("en-US") : miss(spec);
}
function pm(spec, digits = 2) {   // mean ± std object
  const v = get(spec);
  return v && typeof v.mean === "number" ? `${v.mean.toFixed(digits)} ± ${v.std.toFixed(digits)}`   : miss(spec);
}
function pval(spec) {
  const v = get(spec);
  if (typeof v !== "number") return miss(spec);
  return v < 0.001 ? "< 0.001" : v.toFixed(3);
}
function has(file) { return load(file) != null; }

// ------------------------------------------------------------------ inline markup
// **bold**  *italic*  _{sub}  ^{sup}  «TBD» (highlighted)
function runs(text, base = {}) {
  const out = [];
  const re = /(\*\*[^*]+\*\*|\*[^*]+\*|_\{[^}]+\}|\^\{[^}]+\}|«[^»]+»)/g;
  let last = 0, m;
  const push = (t, extra = {}) => t && out.push(new TextRun({ text: t, font: FONT, size: base.size || PT(10), bold: base.bold, italics: base.italics, ...extra }));
  while ((m = re.exec(text))) {
    push(text.slice(last, m.index));
    const t = m[0];
    if (t.startsWith("**")) push(t.slice(2, -2), { bold: true });
    else if (t.startsWith("_{")) push(t.slice(2, -1), { subScript: true });
    else if (t.startsWith("^{")) push(t.slice(2, -1), { superScript: true });
    else if (t.startsWith("«")) { TBD_TEXT.push(t.slice(1, -1)); push("[" + t.slice(1, -1) + "]", { highlight: "yellow", bold: true }); }
    else push(t.slice(1, -1), { italics: true });
    last = m.index + t.length;
  }
  push(text.slice(last));
  return out;
}

// ------------------------------------------------------------------ blocks
const P = (text, o = {}) => new Paragraph({
  children: runs(text, o), alignment: o.align || AlignmentType.JUSTIFIED,
  indent: o.noIndent ? undefined : { firstLine: 202 }, spacing: { after: o.after ?? 0, before: o.before ?? 0, line: 240 },
});
let h1n = 0, h2n = 0;
const ROMAN = ["I", "II", "III", "IV", "V", "VI", "VII", "VIII", "IX", "X", "XI", "XII"];
function H1(text, numbered = true) {
  if (numbered) { h1n += 1; h2n = 0; }
  const label = numbered ? `${ROMAN[h1n - 1]}. ${text}` : text;
  return new Paragraph({ children: [new TextRun({ text: label, font: FONT, size: PT(10), smallCaps: true })],
    alignment: AlignmentType.CENTER, spacing: { before: 160, after: 80 }, keepNext: true });
}
function H2(text) {
  h2n += 1;
  return new Paragraph({ children: [new TextRun({ text: `${String.fromCharCode(64 + h2n)}. ${text}`, font: FONT, size: PT(10), italics: true })],
    spacing: { before: 80, after: 40 }, keepNext: true });
}
function Bullets(items) {
  return items.map((t) => new Paragraph({ children: runs("• " + t), alignment: AlignmentType.JUSTIFIED,
    indent: { left: 240, hanging: 160 }, spacing: { after: 0 } }));
}
function Numbered(items) {
  return items.map((t, i) => new Paragraph({ children: runs(`${i + 1}) ${t}`), alignment: AlignmentType.JUSTIFIED,
    indent: { left: 240, hanging: 240 }, spacing: { after: 0 } }));
}
function Eq(text, n) {
  return new Paragraph({ children: [new TextRun({ text: "\t", font: FONT }), ...runs(text), new TextRun({ text: `\t(${n})`, font: FONT, size: PT(10) })],
    tabStops: [{ type: TabStopType.CENTER, position: COL_W / 2 }, { type: TabStopType.RIGHT, position: COL_W }],
    spacing: { before: 60, after: 60 } });
}
let tabN = 0, figN = 0;
function TableBlock(caption, header, rows, widths) {
  tabN += 1;
  const total = widths.reduce((a, b) => a + b, 0);
  const W = widths.map((w) => Math.round((w / total) * COL_W));
  W[W.length - 1] += COL_W - W.reduce((a, b) => a + b, 0);
  const b0 = { style: BorderStyle.NONE, size: 0, color: "FFFFFF" };
  const line = { style: BorderStyle.SINGLE, size: 4, color: "000000" };
  const cell = (t, i, isHead, isLast, isFirstBody) => new TableCell({
    width: { size: W[i], type: WidthType.DXA },
    margins: { top: 20, bottom: 20, left: 50, right: 50 },
    borders: { left: b0, right: b0, top: isHead ? line : (isFirstBody ? line : b0), bottom: isLast ? line : b0 },
    children: [new Paragraph({ alignment: i === 0 ? AlignmentType.LEFT : AlignmentType.CENTER,
      children: runs(String(t), { size: PT(8), bold: isHead }) })],
  });
  const all = [header, ...rows];
  return [
    new Paragraph({ children: [new TextRun({ text: `TABLE ${ROMAN[tabN - 1]}`, font: FONT, size: PT(8), smallCaps: true })],
      alignment: AlignmentType.CENTER, spacing: { before: 120 }, keepNext: true }),
    new Paragraph({ children: runs(caption, { size: PT(8), }), alignment: AlignmentType.CENTER, spacing: { after: 60 }, keepNext: true }),
    new Table({ width: { size: COL_W, type: WidthType.DXA }, columnWidths: W,
      rows: all.map((r, ri) => new TableRow({ cantSplit: true,
        children: r.map((t, i) => cell(t, i, ri === 0, ri === all.length - 1, ri === 1)) })) }),
    new Paragraph({ children: [], spacing: { after: 80 } }),
  ];
}
function Figure(file, caption, widthIn = 3.4) {
  figN += 1;
  const buf = fs.readFileSync(file);
  const w = buf.readUInt32BE(16), h = buf.readUInt32BE(20);   // PNG header
  const px = Math.round(widthIn * 96);
  return [
    new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 120 }, keepNext: true,
      children: [new ImageRun({ type: "png", data: buf, transformation: { width: px, height: Math.round(px * h / w) } })] }),
    new Paragraph({ children: runs(`Fig. ${figN}.  ${caption}`, { size: PT(8) }), alignment: AlignmentType.JUSTIFIED,
      spacing: { before: 40, after: 120 } }),
  ];
}
function Abstract(text) {
  return new Paragraph({ alignment: AlignmentType.JUSTIFIED, spacing: { after: 60 },
    children: [new TextRun({ text: "Abstract", font: FONT, size: PT(9), bold: true, italics: true }),
      new TextRun({ text: "—", font: FONT, size: PT(9), bold: true }), ...runs(text, { size: PT(9), bold: true })] });
}
function Keywords(text) {
  return new Paragraph({ alignment: AlignmentType.JUSTIFIED, spacing: { after: 120 },
    children: [new TextRun({ text: "Index Terms", font: FONT, size: PT(9), bold: true, italics: true }),
      new TextRun({ text: "—" + text, font: FONT, size: PT(9), bold: true })] });
}
function References(list) {
  return list.map((r, i) => new Paragraph({ alignment: AlignmentType.JUSTIFIED, spacing: { after: 20 },
    tabStops: [{ type: TabStopType.LEFT, position: 300 }], indent: { left: 300, hanging: 300 },
    children: runs(`[${i + 1}]\t${r}`, { size: PT(8) }) }));
}

// ------------------------------------------------------------------ document
function build({ title, authors, body, out }) {
  const noB = { style: BorderStyle.NONE, size: 0, color: "FFFFFF" };
  const rowsOf = (arr, n) => { const r = []; for (let i = 0; i < arr.length; i += n) r.push(arr.slice(i, i + n)); return r; };
  // simpler: rebuild cells per row with fixed widths
  const per = Math.min(3, authors.length), cw = Math.floor(10440 / per);
  const mkCell = (a) => new TableCell({ width: { size: cw, type: WidthType.DXA }, borders: { top: noB, bottom: noB, left: noB, right: noB },
    margins: { bottom: 120 },
    children: [a.name, ...a.lines].map((t, i) => new Paragraph({ alignment: AlignmentType.CENTER,
      children: [new TextRun({ text: t, font: FONT, size: i === 0 ? PT(11) : PT(9), italics: i > 0 && i < a.lines.length })] })) });
  const authorGrid = new Table({ width: { size: cw * per, type: WidthType.DXA }, columnWidths: Array(per).fill(cw),
    alignment: AlignmentType.CENTER,
    rows: rowsOf(authors, per).map((g) => new TableRow({ children: g.map(mkCell) })) });

  const page = { size: { width: 12240, height: 15840 }, margin: { top: 1080, bottom: 1440, left: 900, right: 900 } };
  const doc = new Document({
    styles: { default: { document: { run: { font: FONT, size: PT(10) } } } },
    sections: [
      { properties: { page }, children: [
        new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 160 },
          children: [new TextRun({ text: title, font: FONT, size: PT(24) })] }),
        authorGrid, new Paragraph({ children: [], spacing: { after: 80 } })] },
      { properties: { page, type: SectionType.CONTINUOUS, column: { count: 2, space: 360 } }, children: body },
    ],
  });
  return Packer.toBuffer(doc).then((b) => {
    fs.writeFileSync(out, b); console.log("wrote", out);
    const files = [...new Set([...MISSING].map((m) => m.split("  ")[0]))];
    const rep = out.replace(/\.docx$/, "_MISSING_RESULTS.txt");
    const notes = [...new Set(TBD_TEXT.filter((t) => t !== "TBD"))];
    fs.writeFileSync(rep, `Highlighted [TBD] items in the paper: ${TBD_TEXT.length}\n\n` +
      (files.length ? "Result files not found yet:\n" + files.map((f) => "  results/" + f + ".json").join("\n") + "\n\n" : "All numeric result lookups found.\n\n") +
      (notes.length ? "Text to write or run:\n" + notes.map((n) => "  - " + n).join("\n") + "\n" : ""));
    console.log(`  ${TBD_TEXT.length} [TBD] highlights; missing result files: ${files.join(", ") || "none"}`);
  });
}

module.exports = { P, H1, H2, Bullets, Numbered, Eq, TableBlock, Figure, Abstract, Keywords, References, build,
  num, int, pm, pval, get, has, TBD, ROOT };
