const runButton = document.getElementById("run-scan");
const findingsRoot = document.getElementById("findings");
const errorBox = document.getElementById("error");
const stateLabel = document.getElementById("scan-state");
const jsonButton = document.getElementById("download-json");
const mdButton = document.getElementById("download-md");
const specFile = document.getElementById("spec-file");
let lastResult = null;

function renderIcons(root = document) {
  if (!window.lucide) return;
  window.lucide.createIcons({
    root,
    attrs: { "stroke-width": 1.7 },
  });
}

document.getElementById("base-url").textContent = location.origin;

specFile.addEventListener("change", () => {
  document.getElementById("spec-name").textContent = specFile.files[0]?.name || "openapi.yaml";
});

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

function icon(name, className = "") {
  const node = element("i", className);
  node.setAttribute("data-lucide", name);
  node.setAttribute("aria-hidden", "true");
  return node;
}

function download(name, content, type) {
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([content], { type }));
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

function buildCommand(finding) {
  const request = finding.request || {};
  const method = request.method || finding.method || "GET";
  const url = request.url || "";
  const parts = [`curl -X ${method}`, `"${url}"`];
  for (const [name, value] of Object.entries(request.headers || {})) {
    parts.push(`-H "${name}: ${value}"`);
  }
  if (request.json) {
    parts.push('-H "Content-Type: application/json"');
    parts.push(`-d '${JSON.stringify(request.json)}'`);
  }
  return parts.join(" ");
}

function detailGroup(label, value, className = "") {
  const group = element("div", className);
  group.append(element("span", "", label), element("p", "", value));
  return group;
}

function renderFinding(finding) {
  const article = element("article", "finding");
  const top = element("div", "finding-top");
  const title = element("div", "finding-title");
  title.append(
    element("span", `badge ${finding.severity.toLowerCase()}`, finding.severity),
    element("strong", "", finding.title),
    element("span", "verified technical-label", "CONFIRMED")
  );
  title.lastElementChild.prepend(icon("badge-check"));
  top.append(title, element("span", "score", `${finding.score}/10`));
  article.append(top, element("div", "endpoint", `${finding.method} ${finding.endpoint}`));
  article.append(element("p", "", finding.evidence));

  const details = element("details");
  details.append(element("summary", "", "Show evidence and test-only reproduction"));
  const grid = element("div", "finding-detail");
  grid.append(
    detailGroup("EXPECTED", finding.expected_result, "expected"),
    detailGroup("OBSERVED", finding.actual_result, "observed"),
    detailGroup("REMEDIATION", finding.remediation, "remediation")
  );
  details.append(grid);

  const command = buildCommand(finding);
  const repro = element("div", "repro");
  const head = element("div", "repro-head");
  head.append(element("span", "repro-label", "TEST-ONLY REPRODUCTION REQUEST"));
  const copy = element("button", "copy-button");
  copy.type = "button";
  copy.append(icon("copy"), element("span", "", "Copy request"));
  copy.addEventListener("click", async () => {
    await navigator.clipboard.writeText(command);
    copy.replaceChildren(icon("check"), element("span", "", "Copied"));
    renderIcons(copy);
    setTimeout(() => {
      copy.replaceChildren(icon("copy"), element("span", "", "Copy request"));
      renderIcons(copy);
    }, 1500);
  });
  head.append(copy);
  repro.append(head, element("pre", "", command));
  details.append(repro);
  article.append(details);
  renderIcons(article);
  return article;
}

function setScanState(text, className = "") {
  stateLabel.textContent = text;
  stateLabel.className = `scan-state ${className}`.trim();
}

function render(report) {
  for (const severity of ["Critical", "High", "Medium", "Low"]) {
    document.getElementById(`count-${severity.toLowerCase()}`).textContent = report.summary[severity] || 0;
  }
  const count = report.findings.length;
  document.getElementById("finding-total").textContent = `${count} CONFIRMED`;
  findingsRoot.replaceChildren(...report.findings.map(renderFinding));
  if (!count) {
    const empty = element("div", "empty-state");
    empty.append(icon("circle-check", "empty-mark"));
    const copy = element("div");
    copy.append(
      element("strong", "", "No confirmed findings."),
      element("p", "", "The sandbox checks completed without an ownership violation.")
    );
    empty.append(copy);
    findingsRoot.append(empty);
  }
  renderIcons(findingsRoot);
  setScanState("SCAN COMPLETE", "done");
  jsonButton.disabled = false;
  mdButton.disabled = false;
}

runButton.addEventListener("click", async () => {
  runButton.disabled = true;
  runButton.setAttribute("aria-busy", "true");
  runButton.querySelector(".button-label-long").textContent = "Testing object ownership…";
  runButton.querySelector(".button-label-short").textContent = "Testing…";
  setScanState("TESTING OBJECT OWNERSHIP…", "running");
  errorBox.hidden = true;
  try {
    const body = specFile.files[0] ? { spec: await specFile.files[0].text() } : {};
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.detail || `Scan failed: HTTP ${response.status}`);
    lastResult = payload;
    render(payload.report);
  } catch (error) {
    setScanState("SCAN FAILED", "failed");
    errorBox.textContent = error.message;
    errorBox.hidden = false;
  } finally {
    runButton.disabled = false;
    runButton.removeAttribute("aria-busy");
    runButton.querySelector(".button-label-long").textContent = "Run authorized scan";
    runButton.querySelector(".button-label-short").textContent = "Run scan";
  }
});

jsonButton.addEventListener("click", () => {
  if (lastResult) download("sentinel_report.json", JSON.stringify(lastResult.report, null, 2), "application/json");
});

mdButton.addEventListener("click", () => {
  if (lastResult) download("sentinel_report.md", lastResult.markdown, "text/markdown");
});

renderIcons();
