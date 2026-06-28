const scanForm = document.querySelector("#scanForm");
const urlInput = document.querySelector("#urlInput");
const quickTests = document.querySelectorAll("[data-url]");
const meter = document.querySelector("#meter");
const scoreValue = document.querySelector("#score");
const verdict = document.querySelector("#verdict");
const summary = document.querySelector("#summary");
const reputationBadge = document.querySelector("#reputationBadge");
const domainValue = document.querySelector("#domainValue");
const protocolValue = document.querySelector("#protocolValue");
const categoryValue = document.querySelector("#categoryValue");
const signalCount = document.querySelector("#signalCount");
const signalsList = document.querySelector("#signals");
const historyList = document.querySelector("#historyList");
const clearHistory = document.querySelector("#clearHistory");
const downloadReport = document.querySelector("#downloadReport");

let scanHistory = JSON.parse(localStorage.getItem("phishGuardHistory") || "[]");
let currentResult = null;

const trustedDomains = new Set([
  "google.com",
  "microsoft.com",
  "apple.com",
  "amazon.com",
  "paypal.com",
  "github.com",
  "openai.com",
  "facebook.com",
  "instagram.com",
  "linkedin.com",
  "wikipedia.org",
  "youtube.com"
]);

const brandTargets = [
  "paypal",
  "google",
  "microsoft",
  "apple",
  "amazon",
  "facebook",
  "instagram",
  "netflix",
  "bank",
  "secure",
  "account"
];

const suspiciousTlds = new Set(["zip", "mov", "tk", "ml", "ga", "cf", "gq", "ru", "cn", "top", "xyz"]);

function normalizeUrl(value) {
  const trimmed = value.trim();
  if (!trimmed) {
    throw new Error("Please enter a website URL.");
  }

  const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  return new URL(candidate);
}

function getDomainParts(hostname) {
  const cleanHost = hostname.replace(/^www\./, "").toLowerCase();
  const labels = cleanHost.split(".").filter(Boolean);
  const tld = labels.at(-1) || "";
  const rootDomain = labels.length >= 2 ? labels.slice(-2).join(".") : cleanHost;

  return { cleanHost, labels, rootDomain, tld };
}

function hasIpAddress(hostname) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || /^\[[a-f0-9:]+\]$/i.test(hostname);
}

function addSignal(signals, weight, title, detail) {
  signals.push({ weight, title, detail });
}

function analyzeUrl(input) {
  const parsed = normalizeUrl(input);
  const { cleanHost, labels, rootDomain, tld } = getDomainParts(parsed.hostname);
  const fullUrl = parsed.href.toLowerCase();
  const path = `${parsed.pathname}${parsed.search}`.toLowerCase();
  const signals = [];

  if (parsed.protocol !== "https:") {
    addSignal(signals, 18, "Insecure protocol", "The URL does not use HTTPS encryption.");
  }

  if (hasIpAddress(cleanHost)) {
    addSignal(signals, 22, "IP address domain", "Legitimate public sites rarely use raw IP addresses for sign-in pages.");
  }

  if (cleanHost.includes("-")) {
    addSignal(signals, 8, "Hyphenated domain", "Attackers often use hyphens to imitate trusted services.");
  }

  if (labels.length > 3) {
    addSignal(signals, 10, "Deep subdomain chain", "Multiple subdomains can hide the real registered domain.");
  }

  if (cleanHost.length > 35) {
    addSignal(signals, 8, "Long domain name", "Very long domains are harder to verify at a glance.");
  }

  if (fullUrl.length > 90) {
    addSignal(signals, 8, "Long URL", "Long links may be designed to bury suspicious parts of the address.");
  }

  if (suspiciousTlds.has(tld)) {
    addSignal(signals, 12, "High-risk domain ending", `The .${tld} ending is commonly abused in low-reputation campaigns.`);
  }

  if (/@/.test(parsed.href)) {
    addSignal(signals, 18, "At-symbol redirect trick", "Text before @ can mislead users about the actual destination.");
  }

  if (/(login|verify|update|secure|account|password|signin|wallet|confirm)/i.test(path)) {
    addSignal(signals, 10, "Sensitive action wording", "The path asks for account-style actions often seen in credential theft.");
  }

  const imitatesBrand = brandTargets.some((brand) => cleanHost.includes(brand) && !rootDomain.includes(`${brand}.`));
  if (imitatesBrand) {
    addSignal(signals, 20, "Brand impersonation pattern", "The domain contains a trusted brand word without being that brand's domain.");
  }

  if (/\d/.test(cleanHost) && /[a-z]/.test(cleanHost)) {
    addSignal(signals, 6, "Mixed letters and numbers", "Number substitutions can make fake domains look familiar.");
  }

  const trusted = trustedDomains.has(rootDomain);
  let score = signals.reduce((total, signal) => total + signal.weight, 0);

  if (trusted && parsed.protocol === "https:" && !hasIpAddress(cleanHost)) {
    score = Math.max(0, score - 25);
  }

  score = Math.min(100, Math.max(0, score));

  let category = "Low Risk";
  if (score >= 70) {
    category = "Likely Phishing";
  } else if (score >= 35) {
    category = "Suspicious";
  } else if (trusted) {
    category = "Trusted";
  }

  return {
    score,
    category,
    domain: cleanHost,
    protocol: parsed.protocol.replace(":", "").toUpperCase(),
    url: parsed.href,
    scannedAt: new Date().toLocaleString(),
    signals,
    trusted
  };
}

function getVerdictClass(score) {
  if (score >= 70) return "danger";
  if (score >= 35) return "suspicious";
  return "safe";
}

function renderSignals(signals) {
  signalsList.innerHTML = "";

  if (signals.length === 0) {
    const empty = document.createElement("li");
    empty.className = "empty";
    empty.textContent = "No major phishing indicators were found.";
    signalsList.append(empty);
    return;
  }

  signals
    .sort((a, b) => b.weight - a.weight)
    .forEach((signal) => {
      const item = document.createElement("li");
      item.innerHTML = `<span aria-hidden="true">!</span><div><b>${signal.title}</b><br>${signal.detail}</div>`;
      signalsList.append(item);
    });
}

function renderHistory() {
  historyList.innerHTML = "";

  if (scanHistory.length === 0) {
    const empty = document.createElement("li");
    empty.className = "empty";
    empty.textContent = "Completed scans will appear here.";
    historyList.append(empty);
    return;
  }

  scanHistory.forEach((entry) => {
    const item = document.createElement("li");
    item.innerHTML = `
      <button type="button" data-history-url="${entry.url}">
        <span>${entry.domain}</span>
        <small>${entry.category} - ${entry.score}/100 - ${entry.scannedAt}</small>
      </button>
    `;
    historyList.append(item);
  });
}

function saveToHistory(result) {
  scanHistory = [result, ...scanHistory.filter((entry) => entry.url !== result.url)].slice(0, 6);
  localStorage.setItem("phishGuardHistory", JSON.stringify(scanHistory));
  renderHistory();
}

function renderResult(result) {
  const circumference = 364;
  const offset = circumference - (result.score / 100) * circumference;
  const verdictClass = getVerdictClass(result.score);

  currentResult = result;
  downloadReport.disabled = false;
  meter.style.strokeDashoffset = String(offset);
  meter.style.stroke = `var(--${verdictClass === "danger" ? "danger" : verdictClass === "suspicious" ? "warning" : "safe"})`;
  scoreValue.textContent = result.score;
  verdict.className = `verdict ${verdictClass}`;
  verdict.textContent = result.category;
  reputationBadge.textContent = result.trusted ? "Known domain" : result.category;
  domainValue.textContent = result.domain;
  protocolValue.textContent = result.protocol;
  categoryValue.textContent = result.category;
  signalCount.textContent = `${result.signals.length} found`;
  summary.textContent =
    result.score >= 70
      ? "This URL shows strong phishing indicators. Avoid entering passwords, payment details, or OTPs."
      : result.score >= 35
        ? "This URL has suspicious traits. Verify the domain carefully before sharing any information."
        : "This URL appears low risk based on visible URL signals, but always verify unexpected links.";

  renderSignals(result.signals);
  saveToHistory(result);
}

function runScan(value) {
  try {
    renderResult(analyzeUrl(value));
  } catch (error) {
    currentResult = null;
    downloadReport.disabled = true;
    verdict.className = "verdict danger";
    verdict.textContent = "Invalid URL";
    summary.textContent = error.message;
  }
}

function downloadCurrentReport() {
  if (!currentResult) return;

  const signalLines = currentResult.signals.length
    ? currentResult.signals.map((signal) => `- ${signal.title}: ${signal.detail}`).join("\n")
    : "- No major phishing indicators were found.";

  const report = `PhishGuard URL Scan Report\n\nURL: ${currentResult.url}\nDomain: ${currentResult.domain}\nProtocol: ${currentResult.protocol}\nCategory: ${currentResult.category}\nRisk Score: ${currentResult.score}/100\nScanned At: ${currentResult.scannedAt}\n\nDetection Signals:\n${signalLines}\n`;
  const blob = new Blob([report], { type: "text/plain" });
  const link = document.createElement("a");

  link.href = URL.createObjectURL(blob);
  link.download = `phishguard-report-${currentResult.domain.replace(/[^a-z0-9]/gi, "-")}.txt`;
  link.click();
  URL.revokeObjectURL(link.href);
}

scanForm.addEventListener("submit", (event) => {
  event.preventDefault();
  runScan(urlInput.value);
});

quickTests.forEach((button) => {
  button.addEventListener("click", () => {
    urlInput.value = button.dataset.url;
    runScan(button.dataset.url);
  });
});

historyList.addEventListener("click", (event) => {
  const button = event.target.closest("[data-history-url]");
  if (!button) return;

  urlInput.value = button.dataset.historyUrl;
  runScan(button.dataset.historyUrl);
});

clearHistory.addEventListener("click", () => {
  scanHistory = [];
  localStorage.removeItem("phishGuardHistory");
  renderHistory();
});

downloadReport.addEventListener("click", downloadCurrentReport);
renderHistory();
const demoButton = document.querySelector(".mode-switch button:last-child");

demoButton.addEventListener("click", () => {
    alert("Demo Button Clicked");

    const result = analyzeUrl("http://paypal-login.verify-user-security.ru/login");
    console.log(result);

    renderResult(result);
});