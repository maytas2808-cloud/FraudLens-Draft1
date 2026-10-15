"use strict";
// Adds an "Inspect website" button to every link card in the results.
(() => {
  const make = (tag, cls, text) => {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  };

  function finding(f) {
    let cls = "indicator";
    if (f.weight < 0) cls += " safe";
    else if (f.weight >= 20) cls += " strong";
    const li = make("li", cls);
    const head = make("div", "indicator-head");
    head.append(make("span", "", f.label), make("span", "points", `${f.weight > 0 ? "+" : ""}${f.weight} pts`));
    li.append(head, make("p", "", f.explanation));
    for (const ev of f.evidence || []) if (ev) li.appendChild(make("code", "evidence", ev));
    return li;
  }

  function render(box, r) {
    box.replaceChildren();
    const head = make("div", "site-head");
    head.append(make("strong", "", "Website inspection"));
    const badge = r.level === "unknown" ? make("span", "badge", "NOT REACHABLE") : make("span", `badge ${r.level}`, `${r.level.toUpperCase()} · ${r.score}`);
    head.appendChild(badge);
    box.append(head, make("p", "site-summary", r.summary));
    const facts = [];
    if (r.final_url && r.final_url !== r.url) facts.push(`Landed on: ${r.final_url}`);
    if (r.page && r.page.title) facts.push(`Page title: ${r.page.title}`);
    if (r.page) facts.push(`Forms on page: ${r.page.forms}`);
    if (r.redirects && r.redirects.length > 1) facts.push(`Redirects: ${r.redirects.length - 1}`);
    facts.push(`Checked in ${r.elapsed_ms} ms`);
    const ul = make("ul", "facts");
    for (const f of facts) ul.appendChild(make("li", "", f));
    box.appendChild(ul);
    if (r.findings.length) {
      const list = make("ul", "indicators");
      for (const f of r.findings) list.appendChild(finding(f));
      box.appendChild(list);
    }
    box.appendChild(make("p", "small muted", "Only the page's HTML was downloaded on our server. No scripts ran and nothing was stored."));
  }

  async function inspect(url, button, box) {
    button.disabled = true;
    button.textContent = "Inspecting…";
    box.hidden = false;
    box.replaceChildren(make("p", "muted small", "Opening the page safely on our server…"));
    try {
      const res = await fetch("/api/inspect-site", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Website inspection failed.");
      render(box, data);
      button.textContent = "Inspect again";
    } catch (ex) {
      box.replaceChildren(make("p", "form-error", ex.message || "Network error."));
      button.textContent = "Inspect website";
    } finally {
      button.disabled = false;
    }
  }

  function enhance(card) {
    if (card.dataset.siteReady) return;
    const urlNode = card.querySelector(".url-text");
    if (!urlNode) return;
    card.dataset.siteReady = "1";
    const row = make("div", "site-row");
    const button = make("button", "btn-ghost site-btn", "Inspect website");
    button.type = "button";
    const hint = make("span", "small muted", "Looks inside the page for fake login forms and brand copies.");
    row.append(button, hint);
    const box = make("div", "site-result");
    box.hidden = true;
    box.setAttribute("aria-live", "polite");
    button.addEventListener("click", () => inspect(urlNode.textContent.trim(), button, box));
    card.append(row, box);
  }

  const urls = document.getElementById("urls");
  if (!urls) return;
  new MutationObserver(() => urls.querySelectorAll(".url-card").forEach(enhance)).observe(urls, { childList: true });
})();
