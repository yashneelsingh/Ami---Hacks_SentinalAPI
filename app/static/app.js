const runButton = document.getElementById("run-scan");
const specFile = document.getElementById("spec-file");
const baseUrlInput = document.getElementById("base-url-input");
const stateLabel = document.getElementById("scan-state");
const errorBox = document.getElementById("error");
const findingsRoot = document.getElementById("findings");
const jsonButton = document.getElementById("download-json");
const mdButton = document.getElementById("download-md");
let lastResult = null;

baseUrlInput.value = location.origin;

function el(tag, className = "", content) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (content !== undefined) node.textContent = String(content);
  return node;
}

function setText(id, value) {
  document.getElementById(id).textContent = String(value);
}

function updateTarget() {
  const value = baseUrlInput.value.trim();
  try {
    setText("header-target", new URL(value).host);
  } catch {
    setText("header-target", "Target not set");
  }
}

function updateSpec() {
  const name = specFile.files[0]?.name || "openapi.yaml";
  setText("spec-name", name);
  setText("spec-source", specFile.files[0] ? "Using the selected local file" : "Using the checked-in demo specification");
}

baseUrlInput.addEventListener("input", () => { updateTarget(); invalidateResult(); });
specFile.addEventListener("change", () => { updateSpec(); invalidateResult(); });
updateTarget();

function setScanState(label, className = "") {
  stateLabel.textContent = label;
  stateLabel.className = `scan-state ${className}`.trim();
}

function renderEndpointTable(endpoints) {
  const rows = document.getElementById("endpoint-rows");
  rows.replaceChildren();
  setText("endpoint-total", `${endpoints.length} tested`);
  if (!endpoints.length) {
    const row = el("tr");
    const cell = el("td", "table-empty", "No endpoints were tested. Review the scan status and selected specification.");
    cell.colSpan = 5;
    row.append(cell);
    rows.append(row);
    return;
  }
  for (const endpoint of endpoints) {
    const row = el("tr");
    const cells = [
      ["Method & endpoint", `${endpoint.method} ${endpoint.endpoint}`],
      ["User A object", endpoint.owner_a_id ?? "Unavailable"],
      ["User B object", endpoint.owner_b_id ?? "Unavailable"],
      ["Cross-user HTTP", endpoint.cross_user_status == null ? "Unavailable" : `HTTP ${endpoint.cross_user_status}`],
    ];
    for (const [label, value] of cells) {
      const cell = el("td", "", value);
      cell.dataset.label = label;
      row.append(cell);
    }
    const outcomeCell = el("td");
    outcomeCell.dataset.label = "Outcome";
    outcomeCell.append(el("span", `outcome ${endpoint.outcome || "inconclusive"}`, endpoint.outcome || "inconclusive"));
    row.append(outcomeCell);
    rows.append(row);
  }
}

function renderComparison(report) {
  const root = document.getElementById("comparison-content");
  const status = document.getElementById("comparison-status");
  root.replaceChildren();
  const endpoint = (report.tested_endpoints || [])[0];
  if (!endpoint) {
    status.textContent = "No check completed";
    status.className = "comparison-status inconclusive";
    root.append(el("div", "comparison-empty", "No ownership comparison was completed. Review the scan status and specification."));
    return;
  }
  status.textContent = endpoint.outcome === "fail" ? "Ownership failed" : endpoint.outcome === "pass" ? "Ownership enforced" : endpoint.outcome;
  status.className = `comparison-status ${endpoint.outcome}`;
  const flow = el("div", "comparison-flow");
  const steps = [
    ["USER A BASELINE", endpoint.owner_a_id, "A's own object ID"],
    ["USER B BASELINE", endpoint.owner_b_id, "B's own object ID"],
    ["A REQUESTS B'S OBJECT", endpoint.cross_user_status == null ? "No response" : `HTTP ${endpoint.cross_user_status}`, `Object ID ${endpoint.owner_b_id ?? "unavailable"}`],
  ];
  steps.forEach(([label, value, detail], index) => {
    const step = el("div", `comparison-step${index === 2 ? " cross" : ""}`);
    step.append(el("span", "", label), el("strong", "", value ?? "Unavailable"), el("p", "", detail));
    flow.append(step);
  });
  const conclusion = el("div", "comparison-conclusion");
  conclusion.append(
    el("strong", "", endpoint.outcome === "fail" ? "Confirmed ownership violation" : endpoint.outcome === "pass" ? "Cross-user access blocked" : "Result needs review"),
    el("p", "", endpoint.reason || "The comparison did not provide a conclusive reason.")
  );
  root.append(flow, conclusion);
}

function buildCommand(finding) {
  const request = finding.request || {};
  const parts = [`curl -X ${request.method || finding.method || "GET"}`, `"${request.url || ""}"`];
  for (const [name, value] of Object.entries(request.headers || {})) {
    const safeValue = name.toLowerCase() === "authorization" ? "Bearer <TEST_USER_TOKEN>" : value;
    parts.push(`-H "${name}: ${safeValue}"`);
  }
  return parts.join(" ");
}

function detail(label, value) {
  const group = el("div");
  group.append(el("span", "", label), el("p", "", value || "Not available"));
  return group;
}

function renderFinding(finding) {
  const article = el("article", "finding");
  const top = el("div", "finding-top");
  const title = el("div", "finding-title");
  title.append(el("span", `badge ${finding.severity.toLowerCase()}`, finding.severity), el("strong", "", finding.title), el("span", "verified", "Confirmed"));
  top.append(title, el("span", "score", `${finding.score}/10`));
  article.append(top, el("div", "endpoint", `${finding.method} ${finding.endpoint}`), el("p", "", finding.evidence));
  const details = el("details");
  details.append(el("summary", "", "View evidence and safe reproduction"));
  const grid = el("div", "finding-detail");
  grid.append(
    detail("EXPECTED", finding.expected_result),
    detail("OBSERVED", finding.actual_result),
    detail("WHY IT MATTERS", finding.category === "BOLA" ? "An authenticated user could receive an object owned by another user." : "The API returned fields that should not be included in a normal user response."),
    detail("FIX", finding.remediation)
  );
  details.append(grid);
  const command = buildCommand(finding);
  const repro = el("div", "repro");
  const head = el("div", "repro-head");
  head.append(el("span", "repro-label", "TEST-ONLY REPRODUCTION REQUEST"));
  const copy = el("button", "copy-button", "Copy request");
  copy.type = "button";
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(command);
      copy.textContent = "Copied";
    } catch {
      copy.textContent = "Copy unavailable";
    }
    setTimeout(() => { copy.textContent = "Copy request"; }, 1800);
  });
  head.append(copy);
  repro.append(head, el("pre", "", command));
  details.append(repro);
  article.append(details);
  return article;
}

function render(report) {
  const endpoints = report.tested_endpoints || [];
  const count = report.findings.length;
  renderEndpointTable(endpoints);
  renderComparison(report);
  findingsRoot.replaceChildren(...report.findings.map(renderFinding));
  if (!count) {
    const empty = el("div", "empty-state");
    empty.append(el("strong", "", report.result === "clean" ? "No confirmed findings in the completed checks." : "No confirmed findings; some checks were inconclusive."));
    empty.append(el("p", "", "Review the tested endpoint outcome above before interpreting this result."));
    findingsRoot.append(empty);
  }
  const label = report.result === "clean" ? "Completed clean" : report.result === "inconclusive" ? "Inconclusive" : "Completed with findings";
  setScanState(label, report.result === "findings" ? "findings" : report.result);
  setText("finding-total", `${count} confirmed finding${count === 1 ? "" : "s"}`);
  jsonButton.disabled = false;
  mdButton.disabled = false;
}

function clearPreviousReport() {
  lastResult = null;
  jsonButton.disabled = true;
  mdButton.disabled = true;
  setText("finding-total", "Awaiting result");
  setText("endpoint-total", "Waiting for result");
  document.getElementById("comparison-status").textContent = "Awaiting response";
  document.getElementById("comparison-status").className = "comparison-status";
  document.getElementById("comparison-content").replaceChildren(el("div", "comparison-empty", "Testing the selected local API…"));
  document.getElementById("endpoint-rows").replaceChildren();
  findingsRoot.replaceChildren(el("div", "empty-state", "Waiting for scan results…"));
}

function invalidateResult() {
  if (!lastResult && stateLabel.textContent === "Ready to scan") return;
  clearPreviousReport();
  setScanState("Ready to scan");
  setText("finding-total", "Not yet scanned");
  setText("endpoint-total", "Not yet tested");
  document.getElementById("comparison-status").textContent = "Awaiting scan";
  document.getElementById("comparison-content").replaceChildren(el("div", "comparison-empty", "Run a scan to compare live responses."));
  const row = el("tr");
  const cell = el("td", "table-empty", "No endpoints tested yet. Run a scan to populate this table.");
  cell.colSpan = 5;
  row.append(cell);
  document.getElementById("endpoint-rows").append(row);
  findingsRoot.replaceChildren(el("div", "empty-state", "Run the local scan to inspect live evidence."));
  errorBox.hidden = true;
}

runButton.addEventListener("click", async () => {
  clearPreviousReport();
  runButton.disabled = true;
  runButton.setAttribute("aria-busy", "true");
  runButton.querySelector(".button-label-long").textContent = "Testing object ownership…";
  runButton.querySelector(".button-label-short").textContent = "Testing…";
  setScanState("Testing object ownership…", "running");
  errorBox.hidden = true;
  try {
    const baseUrl = baseUrlInput.value.trim();
    if (!baseUrl) {
      baseUrlInput.focus();
      throw new Error("Enter a local API base URL before running the scan.");
    }
    const body = { base_url: baseUrl };
    if (specFile.files[0]) body.spec = await specFile.files[0].text();
    const response = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.detail || `Scan failed: HTTP ${response.status}`);
    lastResult = payload;
    render(payload.report);
  } catch (error) {
    setScanState("Scan failed", "failed");
    setText("finding-total", "No report generated");
    setText("endpoint-total", "Not completed");
    document.getElementById("comparison-status").textContent = "No check completed";
    document.getElementById("comparison-status").className = "comparison-status error";
    document.getElementById("comparison-content").replaceChildren(el("div", "comparison-empty", "No ownership comparison completed. Correct the issue and run the scan again."));
    if (/target|origin|loopback/i.test(error.message)) baseUrlInput.focus();
    errorBox.textContent = error.message;
    errorBox.hidden = false;
  } finally {
    runButton.disabled = false;
    runButton.removeAttribute("aria-busy");
    runButton.querySelector(".button-label-long").textContent = "Run authorized scan";
    runButton.querySelector(".button-label-short").textContent = "Run scan";
  }
});

function downloadReport(format) {
  if (!lastResult) return;
  const link = document.createElement("a");
  link.href = `/api/reports/sentinel_report.${format}`;
  link.download = `sentinel_report.${format}`;
  link.hidden = true;
  document.body.append(link);
  link.click();
  link.remove();
}

jsonButton.addEventListener("click", () => downloadReport("json"));
mdButton.addEventListener("click", () => downloadReport("md"));
