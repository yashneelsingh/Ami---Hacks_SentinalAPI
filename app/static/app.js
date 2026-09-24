const runButton = document.getElementById("run-scan");
const findingsRoot = document.getElementById("findings");
const errorBox = document.getElementById("error");
const stateLabel = document.getElementById("scan-state");
const jsonButton = document.getElementById("download-json");
const mdButton = document.getElementById("download-md");
let lastResult = null;
const specFile = document.getElementById("spec-file");

specFile.addEventListener("change", () => {
  document.getElementById("spec-name").textContent = specFile.files[0]?.name || "openapi.yaml";
});

document.getElementById("base-url").textContent = location.origin;

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

function download(name, content, type) {
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([content], { type }));
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

function renderFinding(finding) {
  const article = element("article", "finding");
  const top = element("div", "finding-top");
  const title = element("div", "finding-title");
  title.append(element("span", `badge ${finding.severity.toLowerCase()}`, finding.severity));
  title.append(element("strong", "", finding.title));
  top.append(title, element("span", "score", `${finding.score}/10`));
  article.append(top, element("div", "endpoint", `${finding.method} ${finding.endpoint}`));
  article.append(element("p", "", finding.evidence));

  const details = element("details");
  details.append(element("summary", "", "Evidence and reproduction"));
  const grid = element("div", "finding-detail");
  for (const [label, value] of [["Expected", finding.expected_result], ["Observed", finding.actual_result], ["Remediation", finding.remediation]]) {
    const group = element("div");
    group.append(element("span", "", label), element("p", "", value));
    grid.append(group);
  }
  details.append(grid);

  const request = finding.request || {};
  const command = `curl -X ${request.method || finding.method} "${request.url || ""}" -H "Authorization: Bearer <TEST_USER_TOKEN>"`;
  const repro = element("div", "repro");
  const head = element("div", "repro-head");
  head.append(element("span", "", "Reproduction request"));
  const copy = element("button", "copy-button", "Copy");
  copy.type = "button";
  copy.addEventListener("click", async () => {
    await navigator.clipboard.writeText(command);
    copy.textContent = "Copied";
    setTimeout(() => { copy.textContent = "Copy"; }, 1500);
  });
  head.append(copy);
  repro.append(head, element("pre", "", command));
  details.append(repro);
  article.append(details);
  return article;
}

function render(report) {
  for (const severity of ["Critical", "High", "Medium", "Low"]) {
    document.getElementById(`count-${severity.toLowerCase()}`).textContent = report.summary[severity] || 0;
  }
  document.getElementById("finding-total").textContent = report.findings.length;
  findingsRoot.replaceChildren(...report.findings.map(renderFinding));
  if (!report.findings.length) findingsRoot.append(element("div", "empty-state", "No confirmed findings."));
  stateLabel.textContent = "Scan complete";
  stateLabel.classList.add("done");
  jsonButton.disabled = false;
  mdButton.disabled = false;
}

runButton.addEventListener("click", async () => {
  runButton.disabled = true;
  runButton.textContent = "Scanning…";
  stateLabel.textContent = "Running";
  stateLabel.classList.remove("done");
  errorBox.hidden = true;
  try {
    const body = specFile.files[0] ? { spec: await specFile.files[0].text() } : {};
    const response = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.detail || `Scan failed: HTTP ${response.status}`);
    lastResult = payload;
    render(payload.report);
  } catch (error) {
    stateLabel.textContent = "Scan failed";
    errorBox.textContent = error.message;
    errorBox.hidden = false;
  } finally {
    runButton.disabled = false;
    runButton.innerHTML = '<span aria-hidden="true">▶</span> Run scan';
  }
});

jsonButton.addEventListener("click", () => {
  if (lastResult) download("sentinel_report.json", JSON.stringify(lastResult.report, null, 2), "application/json");
});
mdButton.addEventListener("click", () => {
  if (lastResult) download("sentinel_report.md", lastResult.markdown, "text/markdown");
});
