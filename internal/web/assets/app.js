"use strict";

// qphpscanner web UI. All scan-derived text is inserted with textContent to
// avoid injecting attacker-controlled response data into the DOM.

const $ = (id) => document.getElementById(id);

const form = $("scan-form");
const statusEl = $("status");
const scanBtn = $("scan-btn");
const summaryEl = $("summary");
const resultsEl = $("results");
const downloadsEl = $("downloads");

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  await runScan();
});

async function runScan() {
  const targets = $("targets").value;
  if (!targets.trim()) {
    setStatus("Enter at least one target.", true);
    return;
  }

  const body = {
    targets_text: targets,
    ports: $("ports").value.trim(),
    mode: $("mode").value,
    tls: $("tls").value,
    timeout_seconds: parseInt($("timeout").value, 10) || 10,
    concurrency: parseInt($("concurrency").value, 10) || 50,
    follow_redirects: $("follow").checked,
    security_txt: $("securitytxt").checked,
    insecure: $("insecure").checked,
    include_closed: $("includeclosed").checked,
  };

  scanBtn.disabled = true;
  setStatus("Scanning…");
  resultsEl.replaceChildren();
  summaryEl.replaceChildren();
  downloadsEl.classList.add("hidden");

  try {
    const resp = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await resp.json();
    if (!resp.ok || !data.ok) {
      throw new Error(data.error || ("HTTP " + resp.status));
    }
    render(data.result);
    const n = data.result.summary.hosts_scanned;
    setStatus(`Done in ${data.result.meta.duration_ms} ms · ${n} host(s).`);
    downloadsEl.classList.remove("hidden");
  } catch (err) {
    setStatus("Error: " + err.message, true);
  } finally {
    scanBtn.disabled = false;
  }
}

function setStatus(msg, isError) {
  statusEl.textContent = msg;
  statusEl.classList.toggle("error", !!isError);
}

function render(result) {
  renderSummary(result.summary, result.meta);
  const targets = result.targets || [];
  if (targets.length === 0) {
    const p = el("p", "empty", "No open services found.");
    resultsEl.appendChild(p);
    return;
  }
  for (const t of targets) {
    resultsEl.appendChild(renderHost(t));
  }
}

function renderSummary(s, meta) {
  const stats = [
    ["Hosts", s.hosts_scanned],
    ["Open ports", s.open_ports],
    ["HTTP", s.http_services],
    ["PHP confirmed", s.php_confirmed],
    ["PHP likely", s.php_likely],
    ["Vuln leads", s.vulnerabilities],
    ["security.txt", s.security_txt],
  ];
  for (const [label, n] of stats) {
    const box = el("div", "stat");
    box.appendChild(el("div", "n", String(n)));
    box.appendChild(el("div", "l", label));
    summaryEl.appendChild(box);
  }
}

function renderHost(t) {
  const group = el("div", "host-group");
  group.appendChild(el("h3", null, t.host));
  for (const svc of t.services || []) {
    group.appendChild(renderService(svc));
  }
  return group;
}

function renderService(svc) {
  const verdict = svc.php ? svc.php.verdict : "none";
  const card = el("div", "svc v-" + verdict);

  const head = el("div", "svc-head");
  head.appendChild(el("span", "svc-url", svc.url || (svc.host + ":" + svc.port)));
  if (svc.php) {
    const b = el("span", "badge " + verdict, "PHP: " + verdict + " (" + svc.php.confidence + ")");
    head.appendChild(b);
  } else if (!svc.port_open) {
    head.appendChild(el("span", "badge none", "closed"));
  }
  card.appendChild(head);

  const kv = el("dl", "kv");
  const add = (k, v) => {
    if (v === undefined || v === null || v === "") return;
    kv.appendChild(el("dt", null, k));
    kv.appendChild(el("dd", null, String(v)));
  };

  if (!svc.port_open) {
    add("Port", "closed/filtered");
    if (svc.error) add("Error", svc.error);
    card.appendChild(kv);
    return card;
  }

  const h = svc.http;
  if (h) {
    add("Status", h.status + (h.proto ? " " + h.proto : ""));
    add("Server", h.server);
    add("X-Powered-By", h.powered_by);
    add("Title", h.title);
    if (h.tls) add("TLS", h.tls.version + " (" + h.tls.cipher_suite + ")");
    if (h.final_url) add("Redirected to", h.final_url);
  } else {
    add("HTTP", "no response");
    if (svc.error) add("Error", svc.error);
  }

  const php = svc.php;
  if (php) {
    if (php.variant) add("Variant", php.variant);
    if (php.version) add("Version", php.version + (php.version_source ? " (via " + php.version_source + ")" : ""));
    if (php.eol_detail) {
      kv.appendChild(el("dt", null, "Lifecycle"));
      const dd = el("dd", null, php.eol_detail);
      if (php.end_of_life) { dd.classList.add("warn"); dd.textContent = "END OF LIFE — " + php.eol_detail; }
      kv.appendChild(dd);
    }
    if (php.phpinfo_exposed) {
      kv.appendChild(el("dt", null, "phpinfo()"));
      const dd = el("dd", "warn", "exposed at " + php.phpinfo_url);
      kv.appendChild(dd);
    }
  }
  card.appendChild(kv);

  if (php) {
    if (php.frameworks && php.frameworks.length) card.appendChild(chips("Frameworks", php.frameworks));
    if (php.extensions && php.extensions.length) card.appendChild(chips("Extensions", php.extensions));
    if (php.modules && php.modules.length) card.appendChild(chips("Server modules", php.modules));

    if (php.vulnerabilities && php.vulnerabilities.length) {
      card.appendChild(renderVulns(php.vulnerabilities));
    }
    if (php.evidence && php.evidence.length) {
      card.appendChild(renderEvidence(php.evidence));
    }
  }

  if (svc.security_txt && svc.security_txt.present) {
    card.appendChild(renderSecurityTxt(svc.security_txt));
  }

  return card;
}

function chips(label, items) {
  const wrap = el("div");
  wrap.appendChild(el("div", "l", label));
  const row = el("div", "chips");
  for (const it of items) row.appendChild(el("span", "chip", it));
  wrap.appendChild(row);
  return wrap;
}

function renderVulns(vulns) {
  const d = el("details");
  d.open = true;
  d.appendChild(el("summary", null, `Vulnerability leads (${vulns.length})`));
  const ul = el("ul", "vulnlist");
  for (const v of vulns) {
    const li = el("li");
    li.appendChild(el("span", "sev " + (v.severity || "low"), (v.severity || "").toUpperCase()));
    li.appendChild(document.createTextNode(v.id + " — " + v.title));
    li.appendChild(el("div", "note", "affects " + v.affected_versions + " · " + v.match_basis));
    ul.appendChild(li);
  }
  d.appendChild(ul);
  d.appendChild(el("p", "note", "Correlated from the detected version only — verify against the live service."));
  return d;
}

function renderEvidence(evidence) {
  const d = el("details");
  d.appendChild(el("summary", null, `Evidence (${evidence.length})`));
  const ul = el("ul", "evlist");
  for (const ev of evidence) {
    const li = el("li");
    li.appendChild(el("span", "ev-weight", String(ev.weight)));
    li.appendChild(document.createTextNode(" " + ev.signal + " — " + ev.detail + (ev.data ? " [" + ev.data + "]" : "")));
    ul.appendChild(li);
  }
  d.appendChild(ul);
  return d;
}

function renderSecurityTxt(st) {
  const box = el("div", "sectxt");
  box.appendChild(el("h4", null, "security.txt" + (st.signed ? " (PGP-signed)" : "")));
  const kv = el("dl", "kv");
  const add = (k, v) => {
    if (!v || (Array.isArray(v) && !v.length)) return;
    kv.appendChild(el("dt", null, k));
    kv.appendChild(el("dd", null, Array.isArray(v) ? v.join(", ") : String(v)));
  };
  add("URL", st.url);
  add("Contact", st.contact);
  if (st.expires) {
    kv.appendChild(el("dt", null, "Expires"));
    const dd = el("dd", null, st.expires + (st.expired ? " (EXPIRED)" : ""));
    if (st.expired) dd.classList.add("warn");
    kv.appendChild(dd);
  }
  add("Policy", st.policy);
  add("Encryption", st.encryption);
  add("Languages", st.preferred_languages);
  add("Acknowledgments", st.acknowledgments);
  add("Hiring", st.hiring);
  box.appendChild(kv);
  return box;
}

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = text;
  return n;
}
