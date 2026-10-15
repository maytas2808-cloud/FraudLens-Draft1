"use strict";
// Renders the disguised-scam stress test (scripts/stress_test.py) on the Evaluation page.
(() => {
  const box = document.getElementById("robustness");
  if (!box) return;
  const pct = (x) => (x == null ? "—" : `${(x * 100).toFixed(1)}%`);
  const make = (tag, text, cls) => {
    const n = document.createElement(tag);
    if (text !== undefined) n.textContent = text;
    if (cls) n.className = cls;
    return n;
  };

  function bar(label, value) {
    const row = make("div", undefined, "bar-row");
    const track = make("div", undefined, "bar");
    const fill = make("i", undefined, value < 0.9 ? "warn" : undefined);
    track.appendChild(fill);
    row.append(make("span", label), track, make("b", pct(value)));
    requestAnimationFrame(() => requestAnimationFrame(() => { fill.style.width = `${Math.max(0.5, value * 100)}%`; }));
    return row;
  }

  function table(headers, rows, numericFrom) {
    const t = make("table");
    const hr = make("tr");
    headers.forEach((h, i) => hr.appendChild(make("th", h, i >= numericFrom ? "num" : undefined)));
    t.appendChild(make("thead")).appendChild(hr);
    const tb = t.appendChild(make("tbody"));
    for (const r of rows) {
      const tr = tb.appendChild(make("tr"));
      r.forEach((c, i) => tr.appendChild(make("td", String(c), i >= numericFrom ? "num" : undefined)));
    }
    const wrap = make("div", undefined, "table-wrap");
    wrap.appendChild(t);
    return wrap;
  }

  function render(r) {
    const o = r.overall;
    const lead = make("p", `${r.description} Generated ${new Date(r.generated_at).toLocaleString()}.`, "muted");
    const headline = make("p");
    headline.append(make("strong", `${pct(o.detection_rate)} of ${o.n} disguised scams were still caught`),
      document.createTextNode(` (undisguised: ${pct(r.baseline_detection_rate)}).`));
    const bars = make("div", undefined, "bars");
    for (const t of r.transforms) bars.appendChild(bar(t.name, t.detection_rate));
    const rows = r.transforms.map((t) => [
      t.name, `${t.caught} / ${t.n}`, pct(t.detection_rate), pct(t.baseline_rate),
      t.legit_n != null ? `${t.legit_false_positives} / ${t.legit_n} (undisguised ${r.legit_baseline_false_positives})` : "—",
    ]);
    const misses = r.transforms.flatMap((t) => t.misses.map((m) => [t.id, m.id, m.category, m.score, m.text]));
    box.replaceChildren(lead, headline, bars,
      table(["Disguise", "Caught", "Detection", "Same items undisguised", "Legit false positives"], rows, 1),
      make("h3", "Disguised scams that slipped through (sample)"),
      misses.length ? table(["Disguise", "ID", "Category", "Score", "Disguised text"], misses.slice(0, 15), 3) : make("p", "None.", "muted"));
  }

  fetch("/api/robustness")
    .then((res) => (res.ok ? res.json() : Promise.reject(new Error("Robustness report not generated yet. Run scripts/stress_test.py."))))
    .then(render)
    .catch((e) => box.replaceChildren(make("p", e.message, "muted")));
})();
