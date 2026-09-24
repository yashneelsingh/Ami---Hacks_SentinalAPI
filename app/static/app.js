const runButton = document.getElementById("run-scan");
const findingsRoot = document.getElementById("findings");
const errorBox = document.getElementById("error");
const stateLabel = document.getElementById("scan-state");
const jsonButton = document.getElementById("download-json");
const mdButton = document.getElementById("download-md");
const specFile = document.getElementById("spec-file");
const baseUrlInput = document.getElementById("base-url-input");
let lastResult = null;

const ICON_MARKUP = {
  "badge-check": '<path d="m9 12 2 2 4-4"></path><circle cx="12" cy="12" r="9"></circle>',
  check: '<path d="m5 12 4 4L19 6"></path>',
  "circle-check": '<path d="m8 12 2.5 2.5L16 9"></path><circle cx="12" cy="12" r="9"></circle>',
  copy: '<rect x="8" y="8" width="11" height="11" rx="1"></rect><path d="M16 8V5H5v11h3"></path>',
  download: '<path d="M12 3v12"></path><path d="m7 10 5 5 5-5"></path><path d="M5 21h14"></path>',
  "external-link": '<path d="M14 4h6v6"></path><path d="m20 4-9 9"></path><path d="M18 13v6H5V6h6"></path>',
  "file-up": '<path d="M14 2H6v20h12V6Z"></path><path d="M14 2v4h4"></path><path d="M12 17V10"></path><path d="m9 13 3-3 3 3"></path>',
  link: '<path d="M10 13a5 5 0 0 0 7.1.1l2-2a5 5 0 0 0-7.1-7.1l-1.1 1.1"></path><path d="M14 11a5 5 0 0 0-7.1-.1l-2 2A5 5 0 0 0 12 20l1.1-1.1"></path>',
  "scan-search": '<path d="M4 7V4h3"></path><path d="M17 4h3v3"></path><path d="M20 17v3h-3"></path><path d="M7 20H4v-3"></path><circle cx="11" cy="11" r="4"></circle><path d="m14 14 4 4"></path>',
};

function renderIcons(root = document) {
  const nodes = [];
  if (root.matches?.("[data-lucide]")) nodes.push(root);
  nodes.push(...root.querySelectorAll("[data-lucide]"));
  for (const node of nodes) {
    const name = node.dataset.lucide;
    const markup = ICON_MARKUP[name];
    if (!markup) continue;
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "1.7");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    svg.setAttribute("aria-hidden", "true");
    svg.className.baseVal = node.className;
    svg.innerHTML = markup;
    node.replaceWith(svg);
  }
}

baseUrlInput.value = location.origin;

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

function downloadReport(format) {
  const link = document.createElement("a");
  link.href = `/api/reports/sentinel_report.${format}`;
  link.download = `sentinel_report.${format}`;
  link.hidden = true;
  document.body.append(link);
  link.click();
  link.remove();
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
    const baseUrl = baseUrlInput.value.trim();
    if (!baseUrl) {
      baseUrlInput.focus();
      throw new Error("Enter a local API base URL before running the scan.");
    }
    const body = { base_url: baseUrl };
    if (specFile.files[0]) body.spec = await specFile.files[0].text();
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
  if (lastResult) downloadReport("json");
});

mdButton.addEventListener("click", () => {
  if (lastResult) downloadReport("md");
});

renderIcons();
