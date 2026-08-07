import React, { useState, useRef, useEffect, useMemo, useCallback } from "react";

/* ==========================================================================
   L.A.Y.E.R.S — Layered Analysis & Yield of Extension Risk Signals
   A forensic static-analysis instrument for Chrome/Chromium extensions.
   100% local: nothing is uploaded. CRX/ZIP parsed in-browser.
   ========================================================================== */


const PERM_DB = {
  "<all_urls>": { risk: "crit", cap: "READ_ALL_PAGES", desc: "Read and modify content on every website, and intercept all page traffic." },
  "debugger": { risk: "crit", cap: "INJECT_CODE", desc: "Attach Chrome's debugger to any tab — intercept traffic and run arbitrary JS." },
  "nativeMessaging": { risk: "crit", cap: "NATIVE", desc: "Talk to a native desktop app — bridge to OS-level command execution and the filesystem." },
  "proxy": { risk: "crit", cap: "CONTROL_PROXY", desc: "Redirect all browser traffic through an attacker-chosen proxy." },
  "webRequestBlocking": { risk: "crit", cap: "INTERCEPT_NETWORK", desc: "Synchronously modify or block requests — strip HTTPS, inject or redirect content." },
  "webRequest": { risk: "high", cap: "INTERCEPT_NETWORK", desc: "Observe every request including auth headers, cookies and bodies." },
  "declarativeNetRequest": { risk: "high", cap: "INTERCEPT_NETWORK", desc: "Block or redirect network requests via rules." },
  "cookies": { risk: "high", cap: "ACCESS_COOKIES", desc: "Read all cookies across domains — session and auth token theft." },
  "history": { risk: "high", cap: "ACCESS_HISTORY", desc: "Read and modify full browsing history." },
  "identity": { risk: "high", cap: "ACCESS_COOKIES", desc: "Obtain the user's Google OAuth tokens." },
  "scripting": { risk: "high", cap: "INJECT_CODE", desc: "Inject and run scripts in page context — capture forms, passwords, DOM." },
  "contentSettings": { risk: "high", desc: "Change per-site security settings (JS, cookies, plugins)." },
  "clipboardRead": { risk: "high", cap: "READ_CLIPBOARD", desc: "Read the clipboard — may capture passwords, keys, 2FA codes." },
  "geolocation": { risk: "high", desc: "Access precise physical location." },
  "management": { risk: "high", desc: "Disable or uninstall other extensions, including security tools." },
  "pageCapture": { risk: "high", cap: "CAPTURE_SCREEN", desc: "Save full pages including sensitive content." },
  "privacy": { risk: "high", desc: "Alter Chrome privacy / tracking-protection settings." },
  "browsingData": { risk: "high", desc: "Delete cookies, cache, history and saved passwords." },
  "tabs": { risk: "med", desc: "Read tab URLs and titles — reveals browsing activity." },
  "clipboardWrite": { risk: "med", desc: "Write to the clipboard — can swap pasted content." },
  "downloads": { risk: "med", desc: "Trigger downloads to the user's machine." },
  "bookmarks": { risk: "med", desc: "Read/write all bookmarks." },
  "webNavigation": { risk: "med", desc: "Track every navigation event in real time." },
  "topSites": { risk: "med", desc: "Read most-visited sites." },
  "sessions": { risk: "med", desc: "Read recently closed tabs and session data." },
  "background": { risk: "med", desc: "Persist in the background." },
  "notifications": { risk: "low", desc: "Show desktop notifications — possible phishing surface." },
  "activeTab": { risk: "low", desc: "Temporary access to the current tab on user action." },
  "storage": { risk: "low", desc: "Store extension data." },
  "alarms": { risk: "low", desc: "Schedule code execution." },
  "contextMenus": { risk: "low", desc: "Add right-click menu items." },
};

/* --------------------------------------------------------------- capabilities */
const CAP_DEFS = {
  READ_ALL_PAGES:   { name: "Read All Pages", sev: "crit", icon: "M2 6h16M2 10h16M2 14h10" },
  INJECT_CODE:      { name: "Inject Code", sev: "crit", icon: "M6 5l-4 5 4 5M14 5l4 5-4 5M11 3l-2 14" },
  INTERCEPT_NETWORK:{ name: "Intercept Network", sev: "crit", icon: "M10 2v16M2 10h16M4 4l12 12M16 4L4 16" },
  EXECUTE_DYNAMIC:  { name: "Execute Dynamic Code", sev: "crit", icon: "M4 4h12v12H4zM7 8l2 2-2 2M11 12h2" },
  EXFILTRATE:       { name: "Exfiltrate Data", sev: "high", icon: "M10 3v9M6 8l4 4 4-4M4 15h12" },
  ACCESS_COOKIES:   { name: "Access Cookies", sev: "high", icon: "M10 2a8 8 0 108 8 4 4 0 01-4-4 4 4 0 01-4-4zM7 9v.01M12 12v.01M9 13v.01" },
  ACCESS_HISTORY:   { name: "Read History", sev: "high", icon: "M10 5v5l3 2M10 2a8 8 0 108 8" },
  NATIVE:           { name: "Native Host", sev: "crit", icon: "M3 4h14v9H3zM7 17h6M10 13v4" },
  CAPTURE_SCREEN:   { name: "Capture Screen", sev: "high", icon: "M3 5h14v10H3zM7 5V3h6v2" },
  READ_CLIPBOARD:   { name: "Read Clipboard", sev: "high", icon: "M6 4h8v13H6zM8 4V2h4v2" },
  CONTROL_PROXY:    { name: "Control Proxy", sev: "crit", icon: "M10 2v4M10 14v4M2 10h4M14 10h4M5 5l3 3M12 12l3 3" },
  OBFUSCATED:       { name: "Obfuscated Code", sev: "high", icon: "M4 8h12v8H4zM7 8V5a3 3 0 016 0v3" },
};
const CAP_WEIGHT = {
  READ_ALL_PAGES: 9, INJECT_CODE: 7, INTERCEPT_NETWORK: 9, EXECUTE_DYNAMIC: 8,
  EXFILTRATE: 6, ACCESS_COOKIES: 6, ACCESS_HISTORY: 5, NATIVE: 10,
  CAPTURE_SCREEN: 6, READ_CLIPBOARD: 5, CONTROL_PROXY: 10, OBFUSCATED: 5,
};

/* -------------------------------------------------------------- combo recipes */
const COMBOS = [
  { id: "exfil_engine", need: ["READ_ALL_PAGES", "EXFILTRATE"], sev: "crit", weight: 18,
    name: "Mass Page-Content Exfiltration",
    desc: "Can read content from every site and send it to an external server — the shape of spyware and data brokers.",
    flow: ["Read any page", "External POST"] },
  { id: "mitm", need: ["INTERCEPT_NETWORK", "EXFILTRATE"], sev: "crit", weight: 18,
    name: "Traffic Interception + Exfiltration",
    desc: "Sees requests/responses and can ship them off-box — full man-in-the-browser potential.",
    flow: ["Intercept traffic", "External POST"] },
  { id: "rce_channel", need: ["EXECUTE_DYNAMIC", "EXFILTRATE"], sev: "crit", weight: 16,
    name: "Remote Code Execution Channel",
    desc: "Fetches remote content and executes it dynamically — the payload can change after review.",
    flow: ["Fetch remote", "eval / Function"] },
  { id: "cookie_theft", need: ["ACCESS_COOKIES", "EXFILTRATE"], sev: "crit", weight: 15,
    name: "Session / Cookie Theft",
    desc: "Reads auth cookies and can transmit them — account takeover without a password.",
    flow: ["Read cookies", "External POST"] },
  { id: "native_bridge", need: ["NATIVE", "READ_ALL_PAGES"], sev: "crit", weight: 16,
    name: "Web-to-Native Bridge",
    desc: "Bridges untrusted page data into a native host that can run OS commands.",
    flow: ["Read any page", "Native messaging"] },
  { id: "external_inject", need: ["INJECT_CODE", "EXECUTE_DYNAMIC"], sev: "high", weight: 10,
    name: "Dynamic Injection Surface",
    desc: "Injects scripts and runs dynamic code — high risk if either input is attacker-influenced.",
    flow: ["Inject script", "Dynamic exec"] },
  { id: "clip_exfil", need: ["READ_CLIPBOARD", "EXFILTRATE"], sev: "high", weight: 11,
    name: "Clipboard Harvesting",
    desc: "Reads the clipboard and can send it out — captures pasted secrets, seed phrases, 2FA.",
    flow: ["Read clipboard", "External POST"] },
];

/* --------------------------------------------------------------------- engine */
const SEV_ORDER = { crit: 0, high: 1, med: 2, low: 3, info: 4 };
const PEN = { crit: 20, high: 10, med: 4, low: 1, info: 0 };
const CAP_PEN_CAP = 34, COMBO_PEN_CAP = 40, SECRET_PEN_EACH = 12, SECRET_PEN_CAP = 30;

function calcEntropy(s) {
  const f = {}; for (const c of s) f[c] = (f[c] || 0) + 1;
  const l = s.length;
  return -Object.values(f).reduce((a, v) => { const p = v / l; return a + p * Math.log2(p); }, 0);
}

const LIB_HINT = /(?:^|\/)(?:node_modules|vendor|libs?|third[_-]?party|bower_components)\//i;
const LIB_NAME = /(?:jquery|angular|react(?:-dom)?|vue|lodash|underscore|moment|bootstrap|polyfill|axios|d3|three|zepto|backbone|ember|preact|rxjs|core-js|regenerator|webpack|babel|tslib)/i;
const LIB_BANNER = /(?:jQuery (?:Foundation|JavaScript Library)|React(?:DOM)?\s+v?\d|Lodash|MIT License.*(?:jQuery|React|Vue)|@license)/i;

function classifyFile(name, src) {
  if (LIB_HINT.test(name) || LIB_NAME.test(name)) return "vendor";
  if (src && LIB_BANNER.test(src.slice(0, 400))) return "vendor";
  if (name.toLowerCase().endsWith(".min.js")) return "minified";
  if (src) {
    const lines = src.split("\n");
    const maxLine = lines.reduce((m, l) => Math.max(m, l.length), 0);
    if (maxLine > 3000 && lines.length < src.length / 400) return "minified";
  }
  return "first";
}
const confFor = (cls) => (cls === "vendor" ? "low" : cls === "minified" ? "medium" : "high");
const clsFactor = (cls) => (cls === "vendor" ? 0.2 : cls === "minified" ? 0.55 : 1);

/* JS sink rules */
const JS_RULES = [
  { sev: "crit", title: "eval()", re: /\beval\s*\(/g, sink: "EXECUTE_DYNAMIC", desc: "Executes strings as code. Attacker-controlled input here means RCE." },
  { sev: "crit", title: "new Function()", re: /new\s+Function\s*\(/g, sink: "EXECUTE_DYNAMIC", desc: "Equivalent to eval() — runs dynamic strings as code." },
  { sev: "crit", title: "Remote fetch → eval", re: /fetch\s*\([\s\S]{0,240}?eval\s*\(/g, sink: "EXECUTE_DYNAMIC", desc: "Fetches content and eval()s it — classic remote code execution channel." },
  { sev: "crit", title: "Dynamic <script> injection", re: /createElement\s*\(\s*['"`]script['"`]\s*\)/g, sink: "INJECT_CODE", desc: "Creates script elements at runtime — can load attacker-controlled code." },
  { sev: "high", title: "innerHTML assignment", re: /\.innerHTML\s*\+?=(?!\s*['"`]\s*['"`])/g, sink: "DOM", desc: "innerHTML with dynamic data is an XSS sink." },
  { sev: "high", title: "outerHTML assignment", re: /\.outerHTML\s*=/g, sink: "DOM", desc: "Same XSS risk as innerHTML." },
  { sev: "high", title: "document.write()", re: /document\.write(?:ln)?\s*\(/g, sink: "DOM", desc: "XSS vector with untrusted content." },
  { sev: "high", title: "setTimeout/Interval with string", re: /set(?:Timeout|Interval)\s*\(\s*['"`]/g, sink: "EXECUTE_DYNAMIC", desc: "String argument is eval-like dynamic execution." },
  { sev: "high", title: "tabs.executeScript()", re: /chrome\.tabs\.executeScript\s*\(/g, sink: "INJECT_CODE", desc: "Runs a script in a tab — dangerous if content is dynamic." },
  { sev: "high", title: "scripting.executeScript()", re: /chrome\.scripting\.executeScript\s*\(/g, sink: "INJECT_CODE", desc: "Injects and executes scripts into page context." },
  { sev: "high", title: "postMessage to '*'", re: /postMessage\s*\([^)]*,\s*['"]\*['"]/g, desc: "Sends data to any origin — hostile frames can receive it." },
  { sev: "high", title: "cookies.getAll()", re: /chrome\.cookies\.getAll\s*\(/g, cap: "ACCESS_COOKIES", desc: "Reads all cookies — session hijack risk." },
  { sev: "high", title: "history.search()", re: /chrome\.history\.search\s*\(/g, cap: "ACCESS_HISTORY", desc: "Reads browsing history." },
  { sev: "high", title: "identity.getAuthToken()", re: /chrome\.identity\.getAuthToken\s*\(/g, cap: "ACCESS_COOKIES", desc: "Retrieves the signed-in user's OAuth token." },
  { sev: "med", title: "String.fromCharCode() chains", re: /(?:String\.fromCharCode\s*\([^)]*\)\s*\+?\s*){3,}/g, desc: "Repeated char-code construction — common obfuscation." },
  { sev: "med", title: "insertAdjacentHTML()", re: /insertAdjacentHTML\s*\(/g, sink: "DOM", desc: "Parses HTML — XSS if untrusted." },
  { sev: "med", title: "message listener", re: /addEventListener\s*\(\s*['"`]message['"`]/g, source: true, desc: "Verify it checks event.origin before trusting the payload." },
  { sev: "med", title: "fetch() to external URL", re: /fetch\s*\(\s*[`'"]https?:\/\/[^`'"]+/g, cap: "EXFILTRATE", desc: "Sends/receives data to an external endpoint — verify the destination." },
  { sev: "med", title: "sendBeacon()", re: /navigator\.sendBeacon\s*\(/g, cap: "EXFILTRATE", desc: "Fire-and-forget POST, commonly used for silent exfiltration." },
  { sev: "med", title: "XMLHttpRequest", re: /new\s+XMLHttpRequest\s*\(/g, cap: "EXFILTRATE", source: true, desc: "Review what is sent and where." },
  { sev: "med", title: "WebSocket", re: /new\s+WebSocket\s*\(\s*['"`]wss?:\/\//g, cap: "EXFILTRATE", desc: "Real-time channel — review endpoint and payload." },
  { sev: "med", title: "atob() decode", re: /\batob\s*\(/g, desc: "Base64 decode — often hides strings from static scanners." },
  { sev: "low", title: "unescape()", re: /\bunescape\s*\(/g, desc: "Deprecated; used to hide encoded payloads." },
];

/* privacy / fingerprint */
const PRIV_RULES = [
  { re: /document\.cookie/g, sev: "high", cap: "ACCESS_COOKIES", title: "document.cookie access", desc: "Direct cookie read — session/auth exposure." },
  { re: /canvas\.toDataURL|getImageData/g, sev: "high", title: "Canvas fingerprinting", desc: "Renders and reads pixels to build a device fingerprint." },
  { re: /(?:Offline)?AudioContext\s*\(/g, sev: "high", title: "Audio fingerprinting", desc: "Generates a unique audio signature to track the user." },
  { re: /RTCPeerConnection/g, sev: "high", title: "WebRTC IP leak", desc: "Can reveal real IP even behind a VPN." },
  { re: /chrome\.tabs\.captureVisibleTab/g, sev: "crit", cap: "CAPTURE_SCREEN", title: "Screen capture", desc: "Screenshots the active tab — any sensitive page." },
  { re: /navigator\.(?:plugins|mimeTypes)/g, sev: "med", title: "Plugin fingerprinting", desc: "Reads plugin list for device fingerprinting." },
  { re: /navigator\.(?:hardwareConcurrency|deviceMemory)/g, sev: "med", title: "Hardware fingerprinting", desc: "Reads hardware specs for fingerprinting." },
  { re: /localStorage\.(?:get|set)Item/g, sev: "low", title: "localStorage access", desc: "Reads/writes site localStorage." },
  { re: /screen\.(?:width|height|colorDepth|pixelDepth)/g, sev: "low", title: "Screen fingerprinting", desc: "Reads screen metrics — fingerprinting vector." },
];

/* secrets */
const PLACEHOLDER = /^(?:x{4,}|0{4,}|1234|abcd|test|demo|example|sample|your[_-]?|placeholder|dummy|changeme|<[^>]*>|\$\{)/i;
const SECRET_PATTERNS = [
  { re: /AIza[0-9A-Za-z\-_]{35}/g, title: "Google API Key", sev: "crit" },
  { re: /ya29\.[0-9A-Za-z\-_]{40,}/g, title: "Google OAuth Token", sev: "crit" },
  { re: /sk-(?:proj-)?[A-Za-z0-9]{32,}/g, title: "OpenAI API Key", sev: "crit" },
  { re: /sk-ant-api[0-9]{2}-[A-Za-z0-9\-_]{80,}/g, title: "Anthropic API Key", sev: "crit" },
  { re: /(?:AKIA|ASIA)[0-9A-Z]{16}/g, title: "AWS Access Key ID", sev: "crit" },
  { re: /gh[pousr]_[A-Za-z0-9]{36,}/g, title: "GitHub Token", sev: "crit" },
  { re: /glpat-[A-Za-z0-9\-_]{20,}/g, title: "GitLab Token", sev: "crit" },
  { re: /sk_live_[A-Za-z0-9]{24,}/g, title: "Stripe Live Secret", sev: "crit" },
  { re: /pk_live_[A-Za-z0-9]{24,}/g, title: "Stripe Live Public", sev: "high" },
  { re: /sk_test_[A-Za-z0-9]{24,}/g, title: "Stripe Test Key", sev: "med" },
  { re: /xox[baprs]-[0-9A-Za-z\-]{10,}/g, title: "Slack Token", sev: "crit" },
  { re: /SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}/g, title: "SendGrid Key", sev: "crit" },
  { re: /AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}/g, title: "Firebase FCM Key", sev: "crit" },
  { re: /mongodb(?:\+srv)?:\/\/[^\s'"<>]{8,}/gi, title: "MongoDB URI", sev: "crit" },
  { re: /(?:mysql|postgres(?:ql)?|redis):\/\/[^\s'"<>]{8,}/gi, title: "DB Connection String", sev: "crit" },
  { re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, title: "Private Key", sev: "crit", nocap: true },
  { re: /eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}/g, title: "JWT Token", sev: "high" },
  // generic — require capture group + entropy gate
  { re: /(?:api[_\-.]?key|apikey)\s*[:=]\s*['"`]([A-Za-z0-9\-_]{20,})/gi, title: "Generic API Key", sev: "high", gate: true },
  { re: /(?:secret[_\-.]?key|client[_\-.]?secret)\s*[:=]\s*['"`]([A-Za-z0-9\-_]{16,})/gi, title: "Client / Secret Key", sev: "crit", gate: true },
  { re: /(?:password|passwd|pwd)\s*[:=]\s*['"`]([^'"`\s]{8,})/gi, title: "Hardcoded Password", sev: "crit", gate: true },
  { re: /(?:auth[_\-.]?token|bearer[_\-.]?token)\s*[:=]\s*['"`]([A-Za-z0-9\-_.]{20,})/gi, title: "Auth Token", sev: "high", gate: true },
];
function redact(s) { if (!s) return ""; if (s.length <= 8) return "••••"; return s.slice(0, 4) + "•".repeat(Math.min(s.length - 8, 14)) + s.slice(-4); }

/* main scan */
function runScan(files) {
  const F = [];
  let id = 0;
  const add = (o) => F.push({ id: id++, count: 1, conf: "high", ...o });

  // classify
  const cls = {};
  for (const [n, s] of Object.entries(files)) cls[n] = s === "[binary]" ? "binary" : classifyFile(n, s);

  const caps = new Map(); // id -> {source, sev}
  const markCap = (capId, source) => {
    if (!caps.has(capId)) caps.set(capId, { source, sev: CAP_DEFS[capId]?.sev || "med" });
  };

  /* ---- manifest ---- */
  const mKey = Object.keys(files).find((k) => k === "manifest.json" || k.toLowerCase().endsWith("/manifest.json"));
  let manifest = null;
  if (!mKey) add({ cat: "manifest", sev: "crit", title: "manifest.json not found", file: "—", desc: "No manifest — not a valid extension package." });
  else {
    try { manifest = JSON.parse(files[mKey]); }
    catch (e) { add({ cat: "manifest", sev: "crit", title: "Invalid manifest.json", file: mKey, desc: "Parse error: " + e.message }); }
  }

  if (manifest) {
    const MF = mKey;
    const perms = [...(manifest.permissions || []), ...(manifest.optional_permissions || []), ...(manifest.host_permissions || [])];
    perms.forEach((p) => {
      const info = PERM_DB[p];
      if (info?.cap) markCap(info.cap, "manifest");
      if (info && (info.risk === "crit" || info.risk === "high"))
        add({ cat: "manifest", sev: info.risk, title: "Permission: " + p, file: MF, desc: info.desc, snippet: `"${p}"` });
    });
    if (manifest.manifest_version < 3)
      add({ cat: "manifest", sev: "high", title: "Manifest V2 (deprecated)", file: MF, desc: "MV2 allows blocking webRequest and remote code — being removed from Chrome.", snippet: "manifest_version: " + manifest.manifest_version });

    // CSP (MV2 string OR MV3 object)
    const csp = manifest.content_security_policy;
    const cspStr = typeof csp === "string" ? csp : JSON.stringify(csp || "");
    if (cspStr.includes("unsafe-eval")) { add({ cat: "manifest", sev: "crit", title: "CSP allows unsafe-eval", file: MF, desc: "unsafe-eval re-enables dynamic code execution.", snippet: cspStr.slice(0, 160) }); markCap("EXECUTE_DYNAMIC", "manifest"); }
    if (cspStr.includes("unsafe-inline")) add({ cat: "manifest", sev: "high", title: "CSP allows unsafe-inline", file: MF, desc: "unsafe-inline defeats CSP protection for inline scripts.", snippet: cspStr.slice(0, 160) });
    if (!csp && manifest.manifest_version < 3) add({ cat: "manifest", sev: "med", title: "No Content Security Policy", file: MF, desc: "Falls back to permissive defaults." });

    if (manifest.update_url && String(manifest.update_url).startsWith("http:"))
      add({ cat: "manifest", sev: "crit", title: "HTTP update URL — MITM risk", file: MF, desc: "Updates over HTTP can be intercepted and replaced.", snippet: manifest.update_url });

    // web_accessible_resources (MV3 array-of-objects / MV2 array-of-strings)
    (manifest.web_accessible_resources || []).forEach((w, i) => {
      if (typeof w === "object") {
        const m = w.matches || [];
        if (m.includes("<all_urls>") || m.some((u) => u === "*://*/*"))
          add({ cat: "manifest", sev: "high", title: "WAR exposed to all origins", file: `${MF} [WAR#${i}]`, desc: `Resources [${(w.resources || []).join(", ")}] reachable from any site — fingerprinting/probing surface.`, snippet: JSON.stringify(w).slice(0, 160) });
        if (w.use_dynamic_url === false && (w.resources || []).length)
          add({ cat: "manifest", sev: "low", title: "WAR without dynamic URL", file: `${MF} [WAR#${i}]`, desc: "Static resource URLs make the extension easier to fingerprint." });
      }
    });

    (manifest.content_scripts || []).forEach((s, i) => {
      const m = s.matches || [];
      if (m.includes("<all_urls>") || m.some((u) => u === "*://*/*")) {
        markCap("READ_ALL_PAGES", "manifest");
        add({ cat: "manifest", sev: "high", title: "Content script on all URLs", file: `${MF} [cs#${i}]`, desc: `Scripts [${(s.js || []).join(", ")}] run on every site at ${s.run_at || "document_idle"}${s.all_frames ? ", all frames" : ""}.`, snippet: JSON.stringify(m).slice(0, 120) });
      }
      if (s.run_at === "document_start")
        add({ cat: "manifest", sev: "med", title: "Content script at document_start", file: `${MF} [cs#${i}]`, desc: "Runs before the DOM exists — can hook early page events." });
    });

    const ec = manifest.externally_connectable;
    if (ec) {
      const m = ec.matches || [];
      const broad = m.includes("<all_urls>") || m.some((u) => /\*:\/\/\*/.test(u) || u === "*://*/*");
      add({ cat: "manifest", sev: broad ? "high" : "med", title: broad ? "externally_connectable open to all sites" : "externally_connectable defined", file: MF, desc: broad ? "Any website can send messages to this extension — remote-controllable attack surface." : "Specific sites can message this extension; confirm the allowlist.", snippet: JSON.stringify(ec).slice(0, 160) });
    }
    if ((manifest.permissions || []).includes("nativeMessaging"))
      markCap("NATIVE", "manifest");
  }

  /* ---- JS ---- */
  const jsFiles = Object.keys(files).filter((f) => /\.(m?js|ts)$/i.test(f) && files[f] !== "[binary]");
  jsFiles.forEach((fname) => {
    const src = files[fname];
    if (!src) return;
    const c = cls[fname];
    const conf = confFor(c);
    const lines = src.split("\n");
    const hasNet = /fetch\s*\(|XMLHttpRequest|sendBeacon|new\s+WebSocket|sendMessage/.test(src);
    const hasSource = /addEventListener\s*\(\s*['"`]message['"`]|location\.(?:href|search|hash)|document\.URL|\.responseText|params\.get|new\s+URLSearchParams/.test(src);

    JS_RULES.forEach((rule) => {
      const re = new RegExp(rule.re.source, rule.re.flags);
      let m, hits = 0, first = null;
      while ((m = re.exec(src)) !== null && hits < 3) {
        const ln = src.slice(0, m.index).split("\n").length;
        if (first === null) first = { ln, line: (lines[ln - 1] || "").trim() };
        hits++;
      }
      if (!hits) return;
      if (rule.cap) markCap(rule.cap, "code");
      if (rule.sink === "INJECT_CODE") markCap("INJECT_CODE", "code");
      if (rule.sink === "EXECUTE_DYNAMIC") markCap("EXECUTE_DYNAMIC", "code");

      // taint correlation: dangerous sink + a source in same file → elevate
      let sev = rule.sev, extra = "";
      if ((rule.sink === "EXECUTE_DYNAMIC" || rule.sink === "DOM" || rule.sink === "INJECT_CODE") && hasSource && c === "first") {
        sev = rule.sink === "DOM" ? "high" : "crit";
        extra = " A likely data source (message/URL/response) is present in the same file — treat as a real source→sink path, not a stray match.";
      }
      add({ cat: "js", sev, conf, cls: c, title: rule.title, file: `${fname}:${first.ln}`, desc: rule.desc + extra, snippet: first.line });
    });

    // obfuscation
    if (c === "first" && src.length > 800 && calcEntropy(src) > 5.25) {
      markCap("OBFUSCATED", "code");
      add({ cat: "js", sev: "high", conf: "high", cls: c, title: "High-entropy first-party code", file: fname, desc: "Unusually high Shannon entropy in non-library code — a strong obfuscation/packing signal.", snippet: src.slice(0, 130) });
    }

    // keylogger
    if (/addEventListener\s*\(\s*['"`]key(?:down|up|press)['"`]/.test(src)) {
      const sev = hasNet ? "crit" : "med";
      if (hasNet) markCap("EXFILTRATE", "code");
      add({ cat: "privacy", sev, conf, cls: c, title: hasNet ? "Keylogger pattern" : "Keyboard listener", file: fname, desc: hasNet ? "Keystroke capture combined with network calls — the keylogger signature." : "Captures keystrokes; verify scope." });
    }
    if (hasNet && c === "first") markCap("EXFILTRATE", "code");
  });

  /* ---- HTML ---- */
  Object.keys(files).filter((f) => /\.html?$/i.test(f) && files[f] !== "[binary]").forEach((fname) => {
    const src = files[fname];
    const test = (re, sev, title, desc) => { const m = src.match(re); if (m) add({ cat: "html", sev, title, file: fname, desc, snippet: (m[0] || "").slice(0, 130) }); };
    test(/<script[^>]*src\s*=\s*['"]https?:\/\/[^'"]+/i, "crit", "Remote script source", "Loads JS from an external URL — the server/CDN can change it after review.");
    test(/<script(?![^>]*\bsrc\b)[^>]*>\s*\S/i, "high", "Inline script", "Inline JS conflicts with strict CSP.");
    test(/<iframe[^>]*src\s*=\s*['"]https?:\/\/[^'"]+/i, "high", "External iframe", "Loads external content — clickjacking/phishing surface.");
    test(/<form[^>]*action\s*=\s*['"]https?:\/\/[^'"]+/i, "crit", "Form posts to external URL", "User input may be exfiltrated to another domain.");
    test(/on\w+\s*=\s*["'][^"']+["']/i, "high", "Inline event handler", "Inline handlers violate CSP and can run untrusted code.");
    test(/<meta[^>]*http-equiv\s*=\s*['"]refresh['"]/i, "med", "Meta refresh redirect", "Can redirect users to a phishing page.");
  });

  /* ---- network ---- */
  const urlMap = new Map();
  const URL_RE = /(['"`])((?:https?|wss?):\/\/[a-z0-9\-._~:/?#[\]@!$&'()*+,;=%]+)\1/gi;
  Object.entries(files).forEach(([fname, src]) => {
    if (src === "[binary]") return;
    let m; const re = new RegExp(URL_RE.source, URL_RE.flags);
    while ((m = re.exec(src)) !== null) {
      const u = m[2];
      if (!urlMap.has(u)) urlMap.set(u, new Set());
      urlMap.get(u).add(fname);
    }
  });
  if (manifest) {
    const addU = (u, s) => { if (!urlMap.has(u)) urlMap.set(u, new Set()); urlMap.get(u).add(s); };
    (manifest.host_permissions || []).forEach((u) => addU(u, mKey));
    (manifest.content_scripts || []).forEach((cs, i) => (cs.matches || []).forEach((u) => addU(u, `${mKey}[cs#${i}]`)));
    if (manifest.update_url) addU(manifest.update_url, mKey);
  }
  const urls = [...urlMap.entries()].map(([url, s]) => ({ url, files: [...s] }));
  urls.forEach(({ url, files: uf }) => {
    if (url.startsWith("http:") && !/localhost|127\.0\.0\.1/.test(url))
      add({ cat: "network", sev: "high", title: "Insecure HTTP endpoint", file: uf[0], desc: "HTTP traffic is open to MITM and injection.", snippet: url });
    if (/\/\/(?:\d{1,3}\.){3}\d{1,3}(?:[:/]|$)/.test(url))
      add({ cat: "network", sev: "med", title: "Hardcoded IP address", file: uf[0], desc: "Raw IPs bypass DNS reputation and hint at hidden infrastructure.", snippet: url });
  });

  /* ---- privacy rules across files ---- */
  Object.entries(files).forEach(([fname, src]) => {
    if (src === "[binary]") return;
    const c = cls[fname], conf = confFor(c);
    PRIV_RULES.forEach((rule) => {
      const re = new RegExp(rule.re.source, "g");
      const m = re.exec(src);
      if (m) {
        if (rule.cap) markCap(rule.cap, "code");
        add({ cat: "privacy", sev: rule.sev, conf, cls: c, title: rule.title, file: fname, desc: rule.desc, snippet: (m[0] || "").slice(0, 100) });
      }
    });
  });

  /* ---- secrets ---- */
  const seenSecret = new Set();
  Object.entries(files).forEach(([fname, src]) => {
    if (src === "[binary]") return;
    const c = cls[fname];
    SECRET_PATTERNS.forEach((rule) => {
      const re = new RegExp(rule.re.source, rule.re.flags.includes("g") ? rule.re.flags : rule.re.flags + "g");
      let m;
      while ((m = re.exec(src)) !== null) {
        const val = rule.gate ? m[1] : m[0];
        if (!val) continue;
        if (rule.gate) {
          if (PLACEHOLDER.test(val)) continue;
          if (!rule.nocap && calcEntropy(val) < 3.2) continue;
        }
        const key = rule.title + "::" + val.slice(0, 24);
        if (seenSecret.has(key)) continue;
        seenSecret.add(key);
        // vendor placeholder secrets are almost always sample config
        const sev = c === "vendor" && rule.sev === "crit" ? "med" : rule.sev;
        add({ cat: "secrets", sev, conf: confFor(c), cls: c, title: rule.title, file: fname, desc: `Possible hardcoded ${rule.title}. Anyone with the extension file can extract it. Confirm it is not a placeholder before treating as live.`, snippet: redact(val) });
      }
    });
  });

  /* ---- capabilities + combos ---- */
  const capabilities = [...caps.entries()].map(([id, v]) => ({ id, ...CAP_DEFS[id], source: v.source }));
  const capSet = new Set(caps.keys());
  const combos = COMBOS.filter((cb) => cb.need.every((n) => capSet.has(n)));
  combos.forEach((cb) =>
    add({ cat: "combo", sev: cb.sev, title: "Attack chain: " + cb.name, file: "capability model", desc: cb.desc + " Chain: " + cb.flow.join(" → ") + "." })
  );

  /* ---- dedupe ---- */
  const map = new Map();
  F.forEach((f) => {
    const base = String(f.file).split(":")[0];
    const key = `${f.cat}::${f.title}::${base}`;
    if (map.has(key)) { const e = map.get(key); e.count++; if (SEV_ORDER[f.sev] < SEV_ORDER[e.sev]) e.sev = f.sev; }
    else map.set(key, { ...f });
  });
  const findings = [...map.values()];

  /* ---- score ---- */
  const bd = [];
  let score = 100;
  // capabilities
  let capPenalty = 0;
  capabilities.forEach((c) => { const w = CAP_WEIGHT[c.id] || 0; const f = c.source === "manifest" ? 1 : 0.85; capPenalty += w * f; });
  capPenalty = Math.min(capPenalty, 34);
  if (capPenalty) bd.push({ label: "Declared + observed capabilities", pts: -Math.round(capPenalty) });
  score -= capPenalty;
  // combos (the big signal)
  let comboPenalty = combos.reduce((s, c) => s + c.weight, 0);
  comboPenalty = Math.min(comboPenalty, 40);
  if (comboPenalty) bd.push({ label: `${combos.length} dangerous capability combination${combos.length > 1 ? "s" : ""}`, pts: -Math.round(comboPenalty) });
  score -= comboPenalty;
  // secrets
  const liveSecrets = findings.filter((f) => f.cat === "secrets" && (f.sev === "crit" || f.sev === "high") && f.conf !== "low");
  const secretPen = Math.min(liveSecrets.length * 12, 30);
  if (secretPen) bd.push({ label: `${liveSecrets.length} probable hardcoded secret${liveSecrets.length > 1 ? "s" : ""}`, pts: -secretPen });
  score -= secretPen;
  // other findings, per-category caps, confidence + class weighted
  const CAT_CAP = { js: 16, html: 8, privacy: 12, network: 8, manifest: 20 };
  const confW = { high: 1, medium: 0.6, low: 0.25 };
  Object.entries(CAT_CAP).forEach(([cat, cap]) => {
    let p = 0;
    findings.filter((f) => f.cat === cat).forEach((f) => { p += PEN[f.sev] * (confW[f.conf] || 1) * clsFactor(f.cls || "first"); });
    p = Math.min(p, cap);
    if (p >= 1) { bd.push({ label: `${cat} findings`, pts: -Math.round(p) }); score -= p; }
  });
  score = Math.max(0, Math.min(100, Math.round(score)));

  return {
    files, cls, manifest, mKey, findings, urls, capabilities, combos, score, breakdown: bd,
    name: manifest?.name || "Unknown extension", version: manifest?.version || "?",
  };
}

/* ---------------------------------------------------------- CRX / ZIP loader */
function loadJSZip() {
  return new Promise((res, rej) => {
    if (window.JSZip) return res(window.JSZip);
    const s = document.createElement("script");
    s.src = "https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js";
    s.onload = () => res(window.JSZip);
    s.onerror = () => rej(new Error("Could not load the ZIP engine. Check your network connection."));
    document.head.appendChild(s);
  });
}
async function extractFiles(file, onStep) {
  const JSZip = await loadJSZip();
  const buf = await file.arrayBuffer();
  let zipData = buf;
  const sig = new Uint8Array(buf, 0, 4);
  if (sig[0] === 0x43 && sig[1] === 0x72 && sig[2] === 0x78 && sig[3] === 0x21) {
    onStep("Parsing CRX header…");
    const v = new DataView(buf), ver = v.getUint32(4, true);
    let off = 16;
    if (ver === 3) off = 12 + v.getUint32(8, true);
    else if (ver === 2) off = 16 + v.getUint32(8, true) + v.getUint32(12, true);
    zipData = buf.slice(off);
  }
  onStep("Unpacking archive…");
  const zip = await JSZip.loadAsync(zipData);
  const names = Object.keys(zip.files).filter((n) => !zip.files[n].dir);
  const out = {};
  for (let i = 0; i < names.length; i++) {
    const n = names[i];
    if (i % 6 === 0) onStep(`Reading files… ${i + 1}/${names.length}`);
    if (/\.(m?js|ts|html?|json|css)$/i.test(n)) { try { out[n] = await zip.files[n].async("string"); } catch { out[n] = ""; } }
    else out[n] = "[binary]";
  }
  return out;
}


/* ============================================================ presentation */
const SEV_COLOR = { crit: "var(--crit)", high: "var(--high)", med: "var(--med)", low: "var(--low)", info: "var(--info)" };
const scoreColor = (s) => (s <= 30 ? "var(--crit)" : s <= 55 ? "var(--high)" : s <= 75 ? "var(--med)" : "var(--low)");
const scoreLabel = (s) => (s <= 30 ? "Critical Exposure" : s <= 55 ? "High Exposure" : s <= 75 ? "Elevated Exposure" : "Low Exposure");
const verdictClass = (s) => (s <= 30 ? "v-crit" : s <= 55 ? "v-high" : s <= 75 ? "v-med" : "v-low");
const verdictText = (s) =>
  s <= 30 ? "Do not install. This extension has the capabilities and code patterns of malware."
  : s <= 55 ? "Install only with strong justification. Serious capabilities and risky patterns are present — review every finding."
  : s <= 75 ? "Review before installing. Some elevated capabilities warrant a closer look."
  : "No major red flags. The capabilities look proportionate — still skim the findings for context.";

const Badge = ({ s }) => <span className={`bdg b-${s}`}>{s}</span>;

const CSS = `
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

.lyr{--ink:#080b14;--ink2:#0b0f1a;--panel:#0e1421;--panel2:#131b2b;--panel3:#1a2438;--line:#1e293e;--line2:#2b3a56;
  --txt:#eaf0fb;--dim:#8496b4;--dim2:#54648a;
  --trace:#3fe0cc;--trace-d:#1c8377;--amber:#ffb454;--violet:#8b7cff;
  --crit:#ff5a76;--high:#ff9142;--med:#ffcf4a;--low:#3fe0cc;--info:#8b7cff;
  color:var(--txt);font-family:'Inter',system-ui,sans-serif;background:var(--ink);min-height:100vh;position:relative;overflow-x:hidden;-webkit-font-smoothing:antialiased}
.lyr *{box-sizing:border-box;margin:0;padding:0}
.lyr button:focus-visible,.lyr input:focus-visible,.lyr [tabindex]:focus-visible{outline:2px solid var(--trace);outline-offset:2px}

.amb{position:fixed;inset:0;z-index:0;pointer-events:none;overflow:hidden}
.orb{position:absolute;border-radius:50%;filter:blur(80px);opacity:.14;animation:drift 26s ease-in-out infinite}
.orb.a{width:520px;height:520px;background:var(--violet);top:-160px;right:-120px}
.orb.b{width:460px;height:460px;background:var(--trace);bottom:-180px;left:-140px;animation-delay:-9s}
.orb.c{width:300px;height:300px;background:var(--amber);top:40%;left:55%;opacity:.06;animation-delay:-16s}
@keyframes drift{0%,100%{transform:translate(0,0) scale(1)}33%{transform:translate(40px,30px) scale(1.08)}66%{transform:translate(-30px,20px) scale(.95)}}
.amb .grid{position:absolute;inset:0;opacity:.5;
  background-image:linear-gradient(rgba(140,150,180,.05) 1px,transparent 1px),linear-gradient(90deg,rgba(140,150,180,.05) 1px,transparent 1px);
  background-size:46px 46px;mask-image:radial-gradient(circle at 50% -10%,#000,transparent 75%)}

.mono{font-family:'JetBrains Mono',monospace}
.disp{font-family:'Space Grotesk',sans-serif}

.top{position:sticky;top:0;z-index:60;height:62px;display:flex;align-items:center;gap:14px;padding:0 22px;
  background:linear-gradient(180deg,rgba(8,11,20,.9),rgba(8,11,20,.6));backdrop-filter:blur(20px);border-bottom:1px solid var(--line)}
.top .mark{width:36px;height:36px;flex:none}
.top .ring{transform-origin:18px 18px;animation:spin 11s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.brand{display:flex;flex-direction:column;line-height:1.05}
.brand b{font-family:'Space Grotesk';font-weight:700;font-size:15px;letter-spacing:.24em}
.brand span{font-size:9px;color:var(--dim2);letter-spacing:.18em;text-transform:uppercase;margin-top:3px}
.local{margin-left:auto;display:flex;align-items:center;gap:8px;font-size:11px;color:var(--dim);border:1px solid var(--line);background:var(--panel);padding:7px 13px;border-radius:999px}
.dot{width:6px;height:6px;border-radius:50%;background:var(--trace);box-shadow:0 0 0 0 rgba(63,224,204,.5);animation:beat 2.6s infinite}
@keyframes beat{0%{box-shadow:0 0 0 0 rgba(63,224,204,.5)}70%{box-shadow:0 0 0 8px rgba(63,224,204,0)}100%{box-shadow:0 0 0 0 rgba(63,224,204,0)}}

.shell{display:grid;grid-template-columns:222px 1fr;position:relative;z-index:1}
.side{border-right:1px solid var(--line);min-height:calc(100vh - 62px);position:sticky;top:62px;height:calc(100vh - 62px);overflow-y:auto;padding:16px 12px;background:linear-gradient(180deg,rgba(14,20,33,.55),transparent 60%)}
.side::-webkit-scrollbar{width:4px}.side::-webkit-scrollbar-thumb{background:var(--line2);border-radius:3px}
.slab{font-size:9px;letter-spacing:.16em;text-transform:uppercase;color:var(--dim2);font-weight:700;padding:0 8px;margin:16px 0 6px}
.nav{position:relative;display:flex;align-items:center;gap:11px;padding:9px 11px;border-radius:10px;cursor:pointer;font-size:12.5px;color:var(--dim);font-weight:500;transition:.16s;margin-bottom:1px}
.nav:hover{color:var(--txt);background:var(--panel)}
.nav.on{color:var(--txt);background:linear-gradient(90deg,rgba(63,224,204,.1),rgba(139,124,255,.05))}
.nav.on::before{content:'';position:absolute;left:-12px;top:8px;bottom:8px;width:3px;border-radius:0 3px 3px 0;background:linear-gradient(180deg,var(--trace),var(--violet))}
.nav .ic{width:16px;height:16px;flex:none;stroke:currentColor;fill:none;stroke-width:1.7}
.nav.on .ic{stroke:var(--trace)}
.nav .n{margin-left:auto;font-size:10px;font-weight:700;padding:1px 7px;border-radius:8px;background:var(--panel3);color:var(--dim)}
.nav.on .n{background:rgba(63,224,204,.14);color:var(--trace)}

.main{padding:26px 28px 80px;min-height:calc(100vh - 62px)}
.view{animation:viewIn .45s cubic-bezier(.2,.7,.2,1) both}
@keyframes viewIn{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}

.h1{font-family:'Space Grotesk';font-size:23px;font-weight:700;letter-spacing:-.01em;display:flex;align-items:baseline;gap:11px;margin-bottom:18px}
.h1 em{font-style:normal;font-size:12px;color:var(--dim);font-weight:500}
.h1 .bar{width:4px;height:23px;border-radius:3px;background:linear-gradient(180deg,var(--trace),var(--violet));align-self:center}
.lead{font-size:13px;color:var(--dim);line-height:1.75;max-width:660px;margin:-8px 0 20px}
.lead em{font-style:normal;color:var(--txt);font-weight:600}

.dz{border:1.5px dashed var(--line2);border-radius:20px;padding:70px 40px;text-align:center;cursor:pointer;
  background:radial-gradient(700px 320px at 50% -30%,rgba(139,124,255,.07),transparent),var(--panel);transition:.24s;position:relative;overflow:hidden}
.dz:hover,.dz.drag{border-color:var(--trace);border-style:solid;box-shadow:0 0 0 4px rgba(63,224,204,.07),0 40px 90px -40px rgba(0,0,0,.8)}
.dz .sweep{position:absolute;left:0;right:0;top:-2px;height:2px;background:linear-gradient(90deg,transparent,var(--trace),transparent);opacity:0}
.dz:hover .sweep,.dz.drag .sweep{opacity:.9;animation:sweepv 2.4s linear infinite}
@keyframes sweepv{0%{top:-2px}100%{top:100%}}
.dz .glyph{width:80px;height:80px;margin:0 auto 22px;border-radius:22px;display:grid;place-items:center;background:rgba(63,224,204,.06);border:1px solid rgba(63,224,204,.22);animation:bob 4s ease-in-out infinite}
@keyframes bob{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}
.dz .glyph svg{width:36px;height:36px;stroke:var(--trace);fill:none;stroke-width:1.5}
.dz h2{font-family:'Space Grotesk';font-size:22px;font-weight:600;margin-bottom:10px}
.dz p{color:var(--dim);font-size:13px;line-height:1.75;max-width:460px;margin:0 auto}

.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px;margin-top:18px}
.fcard{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px;animation:rise .4s both}
.fcard .t{font-family:'Space Grotesk';font-size:12.5px;font-weight:600;display:flex;align-items:center;gap:9px;margin-bottom:7px}
.fcard .d{font-size:11.5px;color:var(--dim);line-height:1.65}
.pip{width:7px;height:7px;border-radius:2px;box-shadow:0 0 8px currentColor}

.btn{font-family:'Inter';font-weight:600;font-size:12.5px;border:none;border-radius:10px;padding:10px 18px;cursor:pointer;transition:.16s;letter-spacing:.01em}
.btn.p{background:linear-gradient(135deg,var(--trace),#28bda8);color:#04140f;box-shadow:0 8px 24px -10px rgba(63,224,204,.7)}
.btn.p:hover{transform:translateY(-1px);box-shadow:0 12px 30px -10px rgba(63,224,204,.8)}
.btn.g{background:var(--panel2);color:var(--txt);border:1px solid var(--line2)}
.btn.g:hover{border-color:var(--trace);color:var(--trace)}
.btn.sm{padding:8px 14px;font-size:11.5px}

.panel{background:linear-gradient(180deg,var(--panel),var(--ink2));border:1px solid var(--line);border-radius:16px;padding:20px;margin-bottom:15px;animation:rise .42s both}
@keyframes rise{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
.phead{display:flex;align-items:center;justify-content:space-between;margin-bottom:15px;gap:12px}
.ptitle{font-size:10.5px;font-weight:700;letter-spacing:.11em;text-transform:uppercase;color:var(--dim);display:flex;align-items:center;gap:10px}
.ptitle .l{width:18px;height:2px;border-radius:2px;background:linear-gradient(90deg,var(--trace),var(--violet))}
.psub{font-size:11px;color:var(--dim2)}

.verdict{border-radius:14px;padding:15px 19px;margin-bottom:15px;font-weight:600;font-size:14px;display:flex;align-items:center;gap:13px;border:1px solid;animation:rise .36s both}
.verdict svg{width:21px;height:21px;flex:none;stroke:currentColor;fill:none;stroke-width:2}
.v-crit{background:rgba(255,90,118,.08);border-color:rgba(255,90,118,.28);color:var(--crit)}
.v-high{background:rgba(255,145,66,.08);border-color:rgba(255,145,66,.28);color:var(--high)}
.v-med{background:rgba(255,207,74,.08);border-color:rgba(255,207,74,.28);color:var(--med)}
.v-low{background:rgba(63,224,204,.08);border-color:rgba(63,224,204,.28);color:var(--low)}

.hero{display:grid;grid-template-columns:290px 1fr;gap:15px;margin-bottom:15px}
@media(max-width:900px){.hero{grid-template-columns:1fr}.shell{grid-template-columns:1fr}.side{display:none}}
.gaugewrap{background:linear-gradient(180deg,var(--panel),var(--ink2));border:1px solid var(--line);border-radius:16px;padding:22px;display:flex;flex-direction:column;align-items:center;position:relative;overflow:hidden;animation:rise .4s both}
.gaugewrap .halo{position:absolute;top:-38%;left:50%;transform:translateX(-50%);width:360px;height:360px;border-radius:50%;filter:blur(60px);opacity:.16;pointer-events:none}
.gnum{font-family:'Space Grotesk';font-weight:700;font-size:48px;line-height:1;font-variant-numeric:tabular-nums}
.gsub{font-size:9px;color:var(--dim2);letter-spacing:.04em;text-transform:uppercase;margin-top:3px;white-space:nowrap}
.glabel{font-family:'Space Grotesk';font-weight:600;font-size:16px;margin-top:16px;letter-spacing:.02em}
.gnote{font-size:11.5px;color:var(--dim);line-height:1.6;text-align:center;margin-top:9px}

.const{background:radial-gradient(500px 320px at 50% 40%,rgba(139,124,255,.05),transparent),linear-gradient(180deg,var(--panel),var(--ink2));border:1px solid var(--line);border-radius:16px;padding:18px;position:relative;overflow:hidden;animation:rise .45s both}
.const svg{display:block;width:100%;height:auto}
.node-lbl{font-family:'JetBrains Mono';font-size:10px;fill:var(--dim);letter-spacing:.01em}
.node-lbl.act{fill:var(--txt)}
.edge{stroke-linecap:round;fill:none}
.edge-flow{stroke-dasharray:5 9;animation:flow 1s linear infinite}
@keyframes flow{to{stroke-dashoffset:-14}}
.constkey{display:flex;gap:14px;flex-wrap:wrap;margin-top:6px;font-size:10.5px;color:var(--dim)}
.constkey i{display:inline-block;width:20px;height:2px;border-radius:2px;margin-right:6px;vertical-align:middle}

.chain{border:1px solid;border-radius:14px;padding:15px 17px;margin-bottom:11px;background:linear-gradient(120deg,var(--panel2),var(--panel));animation:rise .35s both;position:relative;overflow:hidden}
.chain::after{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:currentColor;opacity:.6}
.chain.c-crit{border-color:rgba(255,90,118,.3);color:var(--crit)}
.chain.c-high{border-color:rgba(255,145,66,.3);color:var(--high)}
.chain-h{display:flex;align-items:center;gap:10px;font-family:'Space Grotesk';font-weight:600;font-size:14.5px;margin-bottom:6px}
.chain-d{font-size:12px;color:var(--dim);line-height:1.65;margin-bottom:12px}
.flow{display:flex;align-items:center;gap:7px;flex-wrap:wrap}
.fnode{font-size:10.5px;font-weight:600;padding:6px 11px;border-radius:9px;background:var(--panel3);border:1px solid var(--line2);white-space:nowrap;color:var(--txt)}
.farrow{font-size:14px;animation:pulse 1.6s infinite}
@keyframes pulse{0%,100%{opacity:.3}50%{opacity:1}}

.stats{display:grid;grid-template-columns:repeat(auto-fill,minmax(108px,1fr));gap:11px;margin-bottom:15px}
.stat{background:linear-gradient(180deg,var(--panel),var(--ink2));border:1px solid var(--line);border-radius:13px;padding:15px 16px;transition:.2s;animation:rise .35s both}
.stat:hover{transform:translateY(-2px);border-color:var(--line2)}
.stat .v{font-family:'Space Grotesk';font-weight:700;font-size:28px;line-height:1;font-variant-numeric:tabular-nums}
.stat .k{font-size:9.5px;color:var(--dim2);text-transform:uppercase;letter-spacing:.08em;font-weight:600;margin-top:6px}
.stat .track{height:3px;border-radius:2px;background:var(--panel3);margin-top:10px;overflow:hidden}
.stat .track i{display:block;height:100%;border-radius:2px;transition:width 1.1s cubic-bezier(.2,.7,.2,1)}

.find{display:flex;gap:13px;padding:13px 15px;border-radius:12px;margin-bottom:8px;background:var(--panel2);border:1px solid var(--line);border-left-width:3px;cursor:pointer;transition:.15s;animation:rise .25s both}
.find:hover{background:var(--panel3);transform:translateX(3px)}
.find.crit{border-left-color:var(--crit)}.find.high{border-left-color:var(--high)}.find.med{border-left-color:var(--med)}.find.low{border-left-color:var(--low)}.find.info{border-left-color:var(--info)}
.fbody{flex:1;min-width:0}
.ftitle{font-size:13px;font-weight:600;display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:4px}
.ffile{font-size:11px;color:var(--dim2);margin-bottom:5px;word-break:break-all}
.fdesc{font-size:12px;color:var(--dim);line-height:1.6}
.fcode{background:var(--ink);border:1px solid var(--line);border-radius:8px;padding:9px 11px;font-size:11px;margin-top:9px;color:var(--trace);word-break:break-all;white-space:pre-wrap;max-height:0;overflow:hidden;transition:max-height .3s;font-family:'JetBrains Mono',monospace}
.find.open .fcode{max-height:170px;overflow:auto}
.fpen{font-size:10px;font-weight:700;color:var(--dim2);flex:none;align-self:flex-start;padding:3px 8px;background:var(--ink);border-radius:6px;border:1px solid var(--line)}

.bdg{display:inline-flex;align-items:center;padding:2px 8px;border-radius:5px;font-size:9px;font-weight:800;text-transform:uppercase;letter-spacing:.05em}
.b-crit{background:rgba(255,90,118,.15);color:var(--crit)}
.b-high{background:rgba(255,145,66,.15);color:var(--high)}
.b-med{background:rgba(255,207,74,.15);color:var(--med)}
.b-low{background:rgba(63,224,204,.15);color:var(--low)}
.b-info{background:rgba(139,124,255,.15);color:var(--info)}
.conf{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;padding:2px 7px;border-radius:5px;border:1px solid var(--line2);color:var(--dim)}
.dedupe{font-size:10px;font-weight:700;padding:2px 8px;border-radius:6px;background:var(--panel3);color:var(--dim)}
.tag{font-size:8.5px;font-weight:700;padding:2px 6px;border-radius:4px;text-transform:uppercase;letter-spacing:.04em}
.t-vendor{background:rgba(139,124,255,.14);color:var(--violet)}
.t-min{background:rgba(255,207,74,.14);color:var(--med)}

.search{position:relative;margin-bottom:13px}
.search svg{position:absolute;left:13px;top:50%;transform:translateY(-50%);width:15px;height:15px;stroke:var(--dim2);fill:none;stroke-width:2}
.search input{width:100%;padding:11px 13px 11px 38px;border:1px solid var(--line2);border-radius:11px;background:var(--panel);color:var(--txt);font-size:13px;font-family:'Inter';outline:none;transition:.15s}
.search input:focus{border-color:var(--trace);box-shadow:0 0 0 3px rgba(63,224,204,.1)}
.filters{display:flex;gap:8px;margin-bottom:13px;flex-wrap:wrap}
.fbtn{padding:7px 14px;border-radius:999px;border:1px solid var(--line);background:var(--panel);color:var(--dim);font-size:11.5px;font-weight:600;cursor:pointer;transition:.15s;font-family:'Inter'}
.fbtn:hover{color:var(--txt);border-color:var(--line2)}
.fbtn.on{border-color:rgba(63,224,204,.4);color:var(--trace);background:rgba(63,224,204,.08)}

.heat{display:flex;flex-wrap:wrap;gap:8px}
.ptile{padding:7px 12px;border-radius:9px;font-size:11px;font-weight:600;border:1px solid;cursor:default;transition:.15s;font-family:'JetBrains Mono'}
.ptile:hover{transform:translateY(-2px)}
.pt-crit{background:rgba(255,90,118,.08);border-color:rgba(255,90,118,.28);color:var(--crit)}
.pt-high{background:rgba(255,145,66,.08);border-color:rgba(255,145,66,.28);color:var(--high)}
.pt-med{background:rgba(255,207,74,.08);border-color:rgba(255,207,74,.28);color:var(--med)}
.pt-low{background:rgba(63,224,204,.08);border-color:rgba(63,224,204,.24);color:var(--low)}

.meta{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:11px}
.mi{background:var(--panel2);border:1px solid var(--line);border-radius:11px;padding:12px 14px}
.mi .k{font-size:9px;color:var(--dim2);text-transform:uppercase;letter-spacing:.07em;font-weight:700;margin-bottom:5px}
.mi .v{font-size:13px;font-weight:600;word-break:break-word}
.file{display:flex;align-items:center;gap:11px;padding:9px 13px;border-radius:10px;margin-bottom:5px;background:var(--panel2);border:1px solid var(--line);font-size:11.5px;font-family:'JetBrains Mono';transition:.12s}
.file:hover{background:var(--panel3);border-color:var(--line2)}
.ext{font-size:9px;font-weight:700;padding:2px 8px;border-radius:5px;text-transform:uppercase;flex:none;background:var(--panel3)}
.chip{display:inline-flex;align-items:center;gap:5px;padding:6px 11px;border-radius:8px;font-size:10.5px;font-family:'JetBrains Mono';background:var(--panel2);border:1px solid var(--line);margin:3px;word-break:break-all;transition:.12s}
.chip.d{border-color:rgba(255,90,118,.3);color:var(--crit)}
.chip.w{border-color:rgba(255,145,66,.3);color:var(--high)}
.pre{background:var(--ink);border:1px solid var(--line);border-radius:11px;padding:16px;font-family:'JetBrains Mono';font-size:11px;overflow:auto;color:var(--trace);max-height:460px;line-height:1.65}
.pre::-webkit-scrollbar{width:5px;height:5px}.pre::-webkit-scrollbar-thumb{background:var(--line2);border-radius:3px}

.load{text-align:center;padding:90px 20px}
.ldisk{width:78px;height:78px;margin:0 auto 24px;position:relative}
.larc{stroke:var(--trace);animation:spin .9s linear infinite;transform-origin:39px 39px}
.ldisk .core{position:absolute;inset:0;display:grid;place-items:center}
.ldisk .core b{font-family:'Space Grotesk';font-size:11px;letter-spacing:.2em;color:var(--trace)}
.ltitle{font-family:'Space Grotesk';font-size:17px;font-weight:600;margin-bottom:8px}
.lstep{font-size:12.5px;color:var(--dim);min-height:19px;margin-bottom:22px;font-family:'JetBrains Mono'}
.ltrack{width:360px;max-width:80vw;height:5px;background:var(--panel3);border-radius:3px;overflow:hidden;margin:0 auto}
.ltrack i{display:block;height:100%;background:linear-gradient(90deg,var(--trace),var(--violet));transition:width .35s}

.formula{background:var(--ink);border:1px solid var(--line);border-radius:12px;padding:18px;font-family:'JetBrains Mono';font-size:12.5px;line-height:2;color:var(--dim);margin-bottom:16px;white-space:pre-wrap}
.formula b{color:var(--trace);font-weight:600}
.formula .op{color:var(--amber)}
.lever{margin-bottom:16px}
.lever-h{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}
.lever-h .nm{font-family:'Space Grotesk';font-weight:600;font-size:13.5px}
.lever-h .cap{font-size:10.5px;color:var(--dim2);font-family:'JetBrains Mono'}
.lever-bar{height:9px;border-radius:5px;background:var(--panel3);overflow:hidden;position:relative}
.lever-bar i{display:block;height:100%;border-radius:5px;transform-origin:left;animation:grow 1.1s cubic-bezier(.2,.7,.2,1) both}
@keyframes grow{from{transform:scaleX(0)}to{transform:scaleX(1)}}
.lever-d{font-size:11.5px;color:var(--dim);line-height:1.65;margin-top:7px}
.band{display:grid;grid-template-columns:repeat(4,1fr);gap:0;border-radius:11px;overflow:hidden;border:1px solid var(--line);margin-top:6px}
.band div{padding:12px 10px;text-align:center;font-size:11px;font-weight:600}
.band .rng{font-family:'Space Grotesk';font-size:15px;display:block;margin-bottom:3px}

.wiki-nav{display:flex;gap:7px;flex-wrap:wrap;margin-bottom:16px}
.wchip{padding:7px 13px;border-radius:999px;border:1px solid var(--line);background:var(--panel);color:var(--dim);font-size:11.5px;font-weight:600;cursor:pointer;transition:.15s}
.wchip:hover{color:var(--txt);border-color:var(--line2)}
.wchip.on{border-color:rgba(139,124,255,.4);color:var(--violet);background:rgba(139,124,255,.08)}
.wrule{border:1px solid var(--line);border-left:3px solid var(--violet);border-radius:11px;padding:15px 17px;margin-bottom:11px;background:var(--panel2);animation:rise .3s both}
.wrule h4{font-family:'Space Grotesk';font-size:14px;font-weight:600;margin-bottom:7px;display:flex;align-items:center;gap:9px}
.wrule .do{font-size:9px;font-weight:800;text-transform:uppercase;letter-spacing:.05em;padding:2px 8px;border-radius:5px;background:rgba(63,224,204,.14);color:var(--trace)}
.wrule .do.dont{background:rgba(255,90,118,.14);color:var(--crit)}
.wrule p{font-size:12.5px;color:var(--dim);line-height:1.7;margin-bottom:8px}
.wrule .chk{font-size:11px;color:var(--dim2);border-top:1px dashed var(--line2);padding-top:8px;display:flex;align-items:center;gap:8px}
.wrule .chk b{color:var(--trace);font-weight:600}
.wcode{font-family:'JetBrains Mono';font-size:11px;background:var(--ink);border:1px solid var(--line);border-radius:7px;padding:8px 11px;color:var(--amber);margin:6px 0;white-space:pre-wrap;word-break:break-word}

.empty{text-align:center;padding:40px 20px;color:var(--dim2);font-size:13px}
input[type=file]{display:none}

@media(prefers-reduced-motion:reduce){
  .lyr *{animation-duration:.001ms!important;animation-iteration-count:1!important;transition-duration:.001ms!important}
  .orb{display:none}
}
`;

function useCountUp(target, on) {
  const [v, setV] = useState(0);
  useEffect(() => {
    if (!on) { setV(target); return; }
    let raf, start; const dur = 950;
    const step = (t) => { start = start || t; const p = Math.min(1, (t - start) / dur); setV(Math.round(target * (1 - Math.pow(1 - p, 3)))); if (p < 1) raf = requestAnimationFrame(step); };
    raf = requestAnimationFrame(step); return () => cancelAnimationFrame(raf);
  }, [target, on]);
  return v;
}

function Gauge({ score }) {
  const r = 54, c = 2 * Math.PI * r;
  const [mount, setMount] = useState(false);
  useEffect(() => { const t = setTimeout(() => setMount(true), 80); return () => clearTimeout(t); }, []);
  const num = useCountUp(score, mount);
  const col = scoreColor(score);
  const off = mount ? c * (1 - score / 100) : c;
  return (
    <div className="gaugewrap">
      <div className="halo" style={{ background: col }} />
      <div style={{ position: "relative", width: 160, height: 160 }}>
        <svg viewBox="0 0 150 150" width="160" height="160" style={{ transform: "rotate(-90deg)" }}>
          <circle cx="75" cy="75" r={r} fill="none" stroke="var(--panel3)" strokeWidth="11" />
          <circle cx="75" cy="75" r={r} fill="none" stroke={col} strokeWidth="11" strokeLinecap="round"
            strokeDasharray={c} strokeDashoffset={off} style={{ transition: "stroke-dashoffset 1.25s cubic-bezier(.2,.7,.2,1)", filter: `drop-shadow(0 0 7px ${col})` }} />
        </svg>
        <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
          <div className="gnum" style={{ color: col }}>{num}</div>
          <div className="gsub">Exposure&nbsp;/&nbsp;100</div>
        </div>
      </div>
      <div className="glabel" style={{ color: col, marginTop: 16 }}>{scoreLabel(score)}</div>
      <div className="gnote">{verdictText(score)}</div>
    </div>
  );
}

function Constellation({ capabilities, combos }) {
  const ids = Object.keys(CAP_DEFS);
  const active = new Set(capabilities.map((c) => c.id));
  const cx = 200, cy = 195, R = 120;
  const pos = {};
  ids.forEach((id, i) => { const a = (-90 + i * (360 / ids.length)) * Math.PI / 180; pos[id] = { x: cx + R * Math.cos(a), y: cy + R * Math.sin(a) }; });
  const [lit, setLit] = useState(0);
  useEffect(() => { setLit(0); const t = setInterval(() => setLit((n) => (n < ids.length ? n + 1 : n)), 65); return () => clearInterval(t); }, [capabilities]);
  const sevStroke = { crit: "var(--crit)", high: "var(--high)" };
  return (
    <div className="const">
      <div className="phead"><div className="ptitle"><span className="l" />Capability Constellation</div>
        <span className="psub">{active.size}/{ids.length} powers · {combos.length} chains</span></div>
      <svg viewBox="-170 -10 740 420" preserveAspectRatio="xMidYMid meet">
        <defs>
          <radialGradient id="cbg" cx="50%" cy="48%" r="55%"><stop offset="0%" stopColor="rgba(139,124,255,.1)" /><stop offset="100%" stopColor="transparent" /></radialGradient>
        </defs>
        <circle cx={cx} cy={cy} r={R} fill="url(#cbg)" stroke="var(--line)" strokeWidth="1" strokeDasharray="2 5" />
        {combos.map((cb, i) => {
          const a = pos[cb.need[0]], b = pos[cb.need[1]];
          if (!a || !b) return null;
          const show = lit >= ids.length;
          return (
            <g key={cb.id} style={{ opacity: show ? 1 : 0, transition: "opacity .5s", transitionDelay: i * 0.12 + "s" }}>
              <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} className="edge" stroke={sevStroke[cb.sev]} strokeWidth="2.5" opacity=".18" />
              <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} className="edge edge-flow" stroke={sevStroke[cb.sev]} strokeWidth="2" opacity=".9" style={{ filter: `drop-shadow(0 0 4px ${sevStroke[cb.sev]})` }} />
            </g>
          );
        })}
        {ids.map((id, i) => {
          const p = pos[id]; const on = active.has(id) && i < lit; const d = CAP_DEFS[id];
          const col = on ? SEV_COLOR[d.sev] : "var(--line2)";
          const outward = p.x >= cx;
          return (
            <g key={id} style={{ opacity: i < lit ? 1 : 0, transform: i < lit ? "scale(1)" : "scale(.5)", transformOrigin: `${p.x}px ${p.y}px`, transition: "opacity .4s, transform .4s" }}>
              {on && <circle cx={p.x} cy={p.y} r="16" fill={col} opacity=".14"><animate attributeName="r" values="14;18;14" dur="3s" repeatCount="indefinite" /></circle>}
              <circle cx={p.x} cy={p.y} r="11" fill={on ? "var(--panel)" : "var(--ink2)"} stroke={col} strokeWidth={on ? 2 : 1.2} style={{ filter: on ? `drop-shadow(0 0 5px ${col})` : "none" }} />
              <g transform={`translate(${p.x - 6},${p.y - 6}) scale(.6)`}><path d={d.icon} stroke={col} strokeWidth="2.4" fill="none" strokeLinecap="round" strokeLinejoin="round" /></g>
              <text x={p.x + (outward ? 16 : -16)} y={p.y + 3} textAnchor={outward ? "start" : "end"} className={`node-lbl ${on ? "act" : ""}`}>{d.name}</text>
            </g>
          );
        })}
      </svg>
      <div className="constkey">
        <span><i style={{ background: "var(--crit)" }} />critical chain</span>
        <span><i style={{ background: "var(--high)" }} />high chain</span>
        <span style={{ color: "var(--dim2)" }}>dimmed node = power not detected</span>
      </div>
    </div>
  );
}

function ComboList({ combos }) {
  if (!combos.length)
    return <div className="panel"><div className="phead"><div className="ptitle"><span className="l" />Attack Chains</div></div>
      <div className="empty">No dangerous capability combinations detected. Individual powers may still warrant review.</div></div>;
  return (
    <div className="panel">
      <div className="phead"><div className="ptitle"><span className="l" />Attack Chains</div><span className="psub">{combos.length} detected</span></div>
      {combos.map((cb, i) => (
        <div key={cb.id} className={`chain c-${cb.sev}`} style={{ animationDelay: i * .07 + "s" }}>
          <div className="chain-h"><Badge s={cb.sev} />{cb.name}</div>
          <div className="chain-d">{cb.desc}</div>
          <div className="flow">{cb.flow.map((n, j) => <React.Fragment key={j}><span className="fnode">{n}</span>{j < cb.flow.length - 1 && <span className="farrow" style={{ color: SEV_COLOR[cb.sev] }}>→</span>}</React.Fragment>)}</div>
        </div>
      ))}
    </div>
  );
}

function Finding({ f }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`find ${f.sev} ${open ? "open" : ""}`} onClick={() => setOpen((o) => !o)} tabIndex={0} onKeyDown={(e) => e.key === "Enter" && setOpen((o) => !o)}>
      <div className="fbody">
        <div className="ftitle"><Badge s={f.sev} />{f.title}
          {f.count > 1 && <span className="dedupe">×{f.count}</span>}
          {f.conf && f.conf !== "high" && <span className="conf">{f.conf} confidence</span>}
          {f.cls === "vendor" && <span className="tag t-vendor">vendor</span>}
          {f.cls === "minified" && <span className="tag t-min">minified</span>}</div>
        <div className="ffile mono">{f.file}</div>
        <div className="fdesc">{f.desc}</div>
        {f.snippet && <div className="fcode">{f.snippet}</div>}
      </div>
      <div className="fpen">−{PEN[f.sev] || 0}</div>
    </div>
  );
}

/* ---------------------------------------------------------------- Scoring tab */
function ScoringTab({ R }) {
  const levers = [
    { nm: "Dangerous combinations", cap: `cap ${COMBO_PEN_CAP} pts`, w: 40, col: "var(--crit)",
      d: "The heaviest lever. Every attack chain — a named threat built from two or more capabilities (exfiltration engine, MITM, cookie theft, RCE channel) — subtracts its own weight. This is deliberate: a malicious extension is defined by what its powers combine into, not by how many regex matches it produces." },
    { nm: "Capabilities", cap: `cap ${CAP_PEN_CAP} pts`, w: 34, col: "var(--high)",
      d: "Each distinct power the extension holds — read-all-pages, inject, intercept, exfiltrate, native host, and so on — carries a weight (native host and proxy control weigh most). Powers declared in the manifest count fully; powers only inferred from code are scaled to 85%, since code intent is less certain than a declared permission." },
    { nm: "Confirmed secrets", cap: `cap ${SECRET_PEN_CAP} pts`, w: 30, col: "var(--med)",
      d: `Each probable live credential (critical/high, and not inside a library file) subtracts ${SECRET_PEN_EACH} points. Placeholder-shaped values and low-entropy generic matches are filtered out before this stage, so sample config doesn't inflate the number.` },
    { nm: "Category findings", cap: "capped per category", w: 24, col: "var(--violet)",
      d: "Everything else — individual JS sinks, HTML issues, privacy signals, network problems, manifest misconfigurations — is summed with two multipliers, then capped per category so no single noisy file can dominate. Manifest caps at 20, privacy 12, JS 16, HTML and network 8 each." },
  ];
  return (
    <div className="view">
      <div className="h1"><span className="bar" /><span className="disp">How scoring works</span></div>
      <p className="lead">The exposure score answers one question: <em>how much damage could this extension do, and how confident are we?</em> It is not a count of findings. A tool with a hundred benign <span className="mono">innerHTML</span> matches in a bundled library should score better than a forty-line extension that quietly reads every page and POSTs it out. The model below is built to make that true.</p>

      <div className="panel">
        <div className="phead"><div className="ptitle"><span className="l" />The formula</div><span className="psub mono">lower = worse</span></div>
        <div className="formula">{
`score  =  100
        −  capabilities   (cap ${CAP_PEN_CAP} pts)
        −  combinations   (cap ${COMBO_PEN_CAP} pts)
        −  secrets        (cap ${SECRET_PEN_CAP} pts)
        −  Σ category      (each capped)

per finding:   penalty  ×  confidence  ×  code-class
confidence:    high ×1   ·  medium ×0.6  ·  low ×0.25
code-class:    first ×1  ·  minified ×0.55  ·  vendor ×0.2`
}</div>
      </div>

      <div className="panel">
        <div className="phead"><div className="ptitle"><span className="l" />The four levers</div><span className="psub">by maximum impact</span></div>
        {levers.map((lv, i) => (
          <div className="lever" key={lv.nm}>
            <div className="lever-h"><span className="nm">{lv.nm}</span><span className="cap">{lv.cap}</span></div>
            <div className="lever-bar"><i style={{ width: (lv.w / 40) * 100 + "%", background: lv.col, animationDelay: i * .12 + "s" }} /></div>
            <div className="lever-d">{lv.d}</div>
          </div>
        ))}
      </div>

      <div className="panel">
        <div className="phead"><div className="ptitle"><span className="l" />Why two multipliers</div></div>
        <p className="lead" style={{ margin: 0 }}>Static analysis on shipped extensions is noisy — real code is bundled, minified, and full of library internals that trip every regex. Two multipliers keep that noise from drowning the signal. <em>Confidence</em> reflects how sure the match is: a hit inside minified code is downgraded because line context is unreliable. <em>Code-class</em> reflects who wrote it — a sink inside <span className="mono">jquery.min.js</span> contributes at one-fifth weight, because you are auditing the author's intent, not React's internals. A dangerous pattern in first-party code counts fully.</p>
      </div>

      <div className="panel">
        <div className="phead"><div className="ptitle"><span className="l" />Score bands</div></div>
        <div className="band">
          {[["0–30", "Critical", "var(--crit)"], ["31–55", "High", "var(--high)"], ["56–75", "Elevated", "var(--med)"], ["76–100", "Low", "var(--low)"]].map(([r, l, c]) => (
            <div key={r} style={{ background: `linear-gradient(180deg, ${c}22, transparent)`, borderRight: "1px solid var(--line)", color: c }}>
              <span className="rng disp">{r}</span>{l}
            </div>
          ))}
        </div>
      </div>

      {R && (
        <div className="panel">
          <div className="phead"><div className="ptitle"><span className="l" />This scan, step by step</div><span className="psub mono">{R.name}</span></div>
          {R.breakdown.map((b, i) => (
            <div className="lever" key={i} style={{ marginBottom: 12 }}>
              <div className="lever-h"><span className="nm" style={{ fontSize: 12.5 }}>{b.label}</span><span className="cap" style={{ color: "var(--crit)" }}>{b.pts} pts{b.cap ? `  ·  cap ${b.cap}` : ""}</span></div>
              <div className="lever-bar"><i style={{ width: Math.min(100, (Math.abs(b.pts) / (b.cap || 40)) * 100) + "%", background: "var(--crit)", animationDelay: i * .08 + "s" }} /></div>
            </div>
          ))}
          <div style={{ display: "flex", justifyContent: "space-between", paddingTop: 12, borderTop: "1px solid var(--line)", fontWeight: 700, fontSize: 15 }}>
            <span>100 − penalties =</span><span className="disp" style={{ color: scoreColor(R.score) }}>{R.score} / 100</span>
          </div>
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------- Wiki tab */
const WIKI = {
  Manifest: [
    { do: "do", h: "Ship Manifest V3", p: "MV3 removes the blocking webRequest API and remote-hosted code, and runs background logic as an ephemeral service worker. MV2 is being removed from Chrome — new submissions must be V3. If you inherited an MV2 extension, migrating is a security upgrade, not just a compliance chore.", chk: "Flags manifest_version < 3 as high." },
    { do: "do", h: "Lock the extension ID", p: "For anything using native messaging or externally_connectable, pin the public key so another extension can't impersonate yours to a native host or a partner site.", chk: "Considered in the native-host capability assessment." },
  ],
  Permissions: [
    { do: "do", h: "Request the narrowest host match", p: "Ask for the specific origins you actually touch — https://app.example.com/* — never <all_urls> unless the product genuinely operates everywhere. Every extra origin is page content you can now read.", code: '"host_permissions": ["https://app.example.com/*"]', chk: "<all_urls> host access maps to the Read-All-Pages capability." },
    { do: "do", h: "Prefer activeTab over broad host access", p: "activeTab grants temporary access to the current tab only when the user invokes the extension. For click-to-act tools it replaces persistent host permissions entirely.", chk: "activeTab is rated low; broad host access is rated critical." },
    { do: "dont", h: "Don't collect powers you don't use", p: "cookies, history, debugger, proxy and nativeMessaging are the permissions reviewers and scanners weight most heavily. Each one you declare but don't need only raises your risk profile and your chances of a store rejection.", chk: "Every dangerous permission is surfaced and fed into the capability model." },
  ],
  CSP: [
    { do: "dont", h: "Never allow unsafe-eval or unsafe-inline", p: "unsafe-eval re-enables eval() and new Function(); unsafe-inline lets inline <script> run. Both undo the main protection CSP gives an extension. If you think you need eval, you almost always need a parser or a small state machine instead.", code: '"content_security_policy": {\n  "extension_pages": "script-src \'self\'; object-src \'self\'"\n}', chk: "unsafe-eval is critical (and flips on Execute-Dynamic); unsafe-inline is high." },
    { do: "do", h: "Keep all script in packaged files", p: "Move inline handlers and inline <script> blocks into bundled .js files referenced by src. This is what a strict CSP requires and it keeps the code reviewable.", chk: "Inline scripts and inline event handlers in HTML are flagged." },
  ],
  "Content scripts": [
    { do: "dont", h: "Don't put page data into HTML sinks", p: "Building DOM with innerHTML, outerHTML or document.write from anything the page controls — URL params, postMessage data, page text — is DOM XSS. Use textContent, or createElement plus setAttribute, or a sanitiser.", code: "el.textContent = note;   // safe\n// not: el.innerHTML = note", chk: "Sinks are elevated to critical when a data source shares the file (taint correlation)." },
    { do: "do", h: "Inject as late and as narrow as you can", p: "document_start and all_frames give you the widest, earliest reach into a page — great for a keylogger, rarely needed for a feature. Default to document_idle and the top frame unless you have a concrete reason.", chk: "document_start and all-URL content scripts are flagged." },
  ],
  Messaging: [
    { do: "do", h: "Validate the origin of every message", p: "A window message listener with no origin check will accept commands from any frame on the page. Check event.origin against an allowlist before trusting the data, and never feed message payloads into eval or innerHTML.", code: 'window.addEventListener("message", e => {\n  if (e.origin !== "https://trusted.example") return;\n  // ...\n});', chk: "Message listeners are flagged for review; payload→sink paths escalate." },
    { do: "dont", h: "Don't open externally_connectable to everyone", p: "matches: ['<all_urls>'] lets any website send messages to your extension — a remote control surface. List only the specific sites that legitimately talk to your extension.", chk: "Broad externally_connectable is flagged high." },
    { do: "dont", h: "Don't postMessage to a wildcard origin", p: "postMessage(data, '*') delivers to whatever frame is there, including a hostile one. Always pass the exact target origin.", chk: "postMessage to '*' is flagged high." },
  ],
  "Network & data": [
    { do: "do", h: "HTTPS everywhere, including update_url", p: "Any http:// endpoint — API, CDN, or the extension's own update URL — can be intercepted and rewritten on a hostile network. An HTTP update URL is a direct path to shipping attacker code to every user.", chk: "HTTP endpoints are high; an HTTP update_url is critical." },
    { do: "dont", h: "Don't load remote code", p: "Remote <script src>, fetching JS and eval-ing it, or pulling rules that become code — all mean the code that ships is not the code that runs. It's prohibited under MV3 and it's the classic supply-chain backdoor. Bundle everything you execute.", chk: "Remote script tags and fetch→eval are critical and light up the RCE chain." },
  ],
  "Storage & secrets": [
    { do: "dont", h: "Never hardcode credentials in the bundle", p: "Anyone can unzip a published extension and read every string. API keys, tokens, private keys and DB URIs in the source are effectively public. Put secrets behind your backend and hand out short-lived, scoped tokens instead.", chk: "20+ credential patterns, with placeholder filtering and entropy gating." },
    { do: "do", h: "Treat web-accessible resources as public", p: "Anything in web_accessible_resources can be loaded and inspected by any page you expose it to. Never place config with secrets there, keep the matches list tight, and set use_dynamic_url to blunt fingerprinting.", chk: "Over-broad WAR and static WAR URLs are flagged." },
  ],
  "Supply chain": [
    { do: "do", h: "Pin and review your dependencies", p: "Most extension compromises now arrive through a dependency or a sold/hijacked extension pushing a malicious update. Lock versions, review updates, and watch for maintainers who suddenly add network or eval calls.", chk: "Vendor code is classified and down-weighted, so first-party additions stand out." },
    { do: "do", h: "Minimise, don't obfuscate", p: "Minification is fine; obfuscation that hides intent will get you rejected and reads as malware to a reviewer. If your first-party code has unusually high entropy, expect scrutiny.", chk: "High-entropy first-party code raises the Obfuscated capability." },
  ],
};
function WikiTab() {
  const cats = Object.keys(WIKI);
  const [cat, setCat] = useState(cats[0]);
  return (
    <div className="view">
      <div className="h1"><span className="bar" /><span className="disp">Extension hardening wiki</span></div>
      <p className="lead">Field notes for building a Chrome extension that isn't a liability — the practices that keep you out of the red on this tool and out of trouble in review. Each item links back to what L.A.Y.E.R.S actually checks, so you can build to the scanner and know why.</p>
      <div className="wiki-nav">{cats.map((c) => <button key={c} className={`wchip ${cat === c ? "on" : ""}`} onClick={() => setCat(c)}>{c}</button>)}</div>
      {WIKI[cat].map((w, i) => (
        <div className="wrule" key={i} style={{ animationDelay: i * .05 + "s" }}>
          <h4><span className={`do ${w.do === "dont" ? "dont" : ""}`}>{w.do === "dont" ? "avoid" : "do"}</span>{w.h}</h4>
          <p>{w.p}</p>
          {w.code && <div className="wcode">{w.code}</div>}
          <div className="chk"><b>L.A.Y.E.R.S:</b>{w.chk}</div>
        </div>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------------ App */
const NAV_ANALYSIS = [
  { id: "overview", label: "Overview", ic: "M2 2h6v6H2zM12 2h6v6h-6zM2 12h6v6H2zM12 12h6v6h-6z" },
  { id: "findings", label: "Findings", ic: "M10 2L2 17h16zM10 8v3M10 14v.5" },
  { id: "manifest", label: "Manifest", ic: "M4 2h9l3 3v13H4zM4 6h8M4 9h8M4 12h5" },
  { id: "js", label: "JavaScript", ic: "M5 4L2 10l3 6M15 4l3 6-3 6M11 3l-2 14" },
  { id: "html", label: "HTML", ic: "M3 4l1 12 6 2 6-2 1-12z" },
  { id: "network", label: "Network", ic: "M10 2a8 8 0 100 16 8 8 0 000-16zM2 10h16M10 2c-2.5 2.5-3.5 5-3.5 8s1 5.5 3.5 8" },
  { id: "privacy", label: "Privacy", ic: "M10 2L3 5v5c0 4 3 7 7 8 4-1 7-4 7-8V5z" },
  { id: "secrets", label: "Secrets", ic: "M4 8h12v9H4zM6 8V5a4 4 0 018 0v3M10 12v2" },
  { id: "files", label: "File Tree", ic: "M2 4h5l2 2h9v10H2z" },
  { id: "report", label: "Report", ic: "M4 2h8l4 4v12H4zM12 2v4h4M6 10h8M6 13h5" },
];
const NAV_REF = [
  { id: "scoring", label: "Scoring", ic: "M3 17V9M9 17V3M15 17v-6M2 17h16" },
  { id: "wiki", label: "Wiki", ic: "M4 3h9a2 2 0 012 2v12H6a2 2 0 01-2-2zM4 3v12M8 7h5M8 10h5" },
];

export default function App() {
  const [state, setState] = useState("idle");
  const [step, setStep] = useState("");
  const [prog, setProg] = useState(0);
  const [tab, setTab] = useState("overview");
  const [R, setR] = useState(null);
  const [err, setErr] = useState("");
  const [q, setQ] = useState("");
  const [sev, setSev] = useState("all");
  const [drag, setDrag] = useState(false);
  const fileRef = useRef();

  const process = useCallback(async (file) => {
    setErr(""); setState("loading"); setTab("overview"); setProg(6); setStep("Reading file");
    try {
      const files = await extractFiles(file, setStep);
      setProg(45); setStep("Classifying first-party vs vendor code"); await new Promise((r) => setTimeout(r, 110));
      setProg(62); setStep("Correlating sinks and data sources"); await new Promise((r) => setTimeout(r, 110));
      setProg(80); setStep("Building capability model and attack chains"); await new Promise((r) => setTimeout(r, 110));
      const res = runScan(files);
      setProg(96); setStep("Scoring exposure"); await new Promise((r) => setTimeout(r, 160));
      setProg(100); setR(res); setState("done"); setTab("overview");
    } catch (e) { setErr(e.message || String(e)); setState("idle"); }
  }, []);

  const onDrop = (e) => { e.preventDefault(); setDrag(false); const f = e.dataTransfer.files[0]; if (f) process(f); };
  const counts = useMemo(() => {
    if (!R) return {};
    const c = {};
    ["findings", "js", "html", "network", "privacy", "secrets"].forEach((k) => { c[k] = k === "findings" ? R.findings.length : R.findings.filter((f) => f.cat === k).length; });
    return c;
  }, [R]);
  const sevCount = (s) => R ? R.findings.filter((f) => f.sev === s).length : 0;
  const filtered = useMemo(() => {
    if (!R) return [];
    let items = [...R.findings].sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);
    if (sev !== "all") items = items.filter((f) => f.sev === sev);
    if (q) { const l = q.toLowerCase(); items = items.filter((f) => (f.title + f.file + f.desc).toLowerCase().includes(l)); }
    return items;
  }, [R, sev, q]);
  const catFindings = (cat) => R.findings.filter((f) => f.cat === cat).sort((a, b) => SEV_ORDER[a.sev] - SEV_ORDER[b.sev]);
  const perms = R?.manifest ? [...(R.manifest.permissions || []), ...(R.manifest.optional_permissions || []), ...(R.manifest.host_permissions || [])] : [];

  const report = useMemo(() => {
    if (!R) return null;
    return {
      generated: new Date().toISOString(), tool: "L.A.Y.E.R.S. v4",
      extension: { name: R.name, version: R.version, manifest_version: R.manifest?.manifest_version },
      exposure_score: R.score, verdict: verdictText(R.score),
      capabilities: R.capabilities.map((c) => ({ id: c.id, name: c.name, severity: c.sev, source: c.source })),
      attack_chains: R.combos.map((c) => ({ name: c.name, severity: c.sev, flow: c.flow, weight: c.weight })),
      summary: { critical: sevCount("crit"), high: sevCount("high"), medium: sevCount("med"), low: sevCount("low"), total: R.findings.length },
      files_analyzed: Object.keys(R.files).length, urls_found: R.urls.length,
      findings: R.findings.map((f) => ({ severity: f.sev, category: f.cat, confidence: f.conf, title: f.title, file: f.file, occurrences: f.count, description: f.desc })),
    };
  }, [R]);
  const download = (type) => {
    let blob, ext;
    if (type === "csv") {
      const rows = [["severity", "category", "confidence", "title", "file", "occurrences", "description"],
        ...R.findings.map((f) => [f.sev, f.cat, f.conf || "high", `"${f.title.replace(/"/g, '""')}"`, `"${String(f.file).replace(/"/g, '""')}"`, f.count, `"${f.desc.replace(/"/g, '""')}"`])];
      blob = new Blob([rows.map((r) => r.join(",")).join("\n")], { type: "text/csv" }); ext = "csv";
    } else { blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }); ext = "json"; }
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = `layers-${R.name.replace(/\s+/g, "_")}-${Date.now()}.${ext}`; a.click();
  };

  const scanReady = state === "done" && R;
  const NavItem = ({ n }) => (
    <div className={`nav ${tab === n.id ? "on" : ""}`} onClick={() => setTab(n.id)} tabIndex={0} onKeyDown={(e) => e.key === "Enter" && setTab(n.id)}>
      <svg className="ic" viewBox="0 0 20 20"><path d={n.ic} strokeLinecap="round" strokeLinejoin="round" /></svg>
      {n.label}
      {counts[n.id] != null && <span className="n">{counts[n.id]}</span>}
    </div>
  );

  return (
    <div className="lyr">
      <style>{CSS}</style>
      <div className="amb"><div className="orb a" /><div className="orb b" /><div className="orb c" /><div className="grid" /></div>

      <div className="top">
        <svg className="mark" viewBox="0 0 36 36" fill="none">
          <circle className="ring" cx="18" cy="18" r="14" stroke="url(#g)" strokeWidth="1.4" strokeDasharray="5 4" />
          <path d="M18 8l7 4v8l-7 4-7-4v-8z" stroke="url(#g)" strokeWidth="1.4" fill="rgba(63,224,204,.08)" />
          <path d="M11 12l7 4 7-4M18 16v8" stroke="url(#g)" strokeWidth="1.1" />
          <defs><linearGradient id="g" x1="0" y1="0" x2="36" y2="36"><stop stopColor="#3fe0cc" /><stop offset="1" stopColor="#8b7cff" /></linearGradient></defs>
        </svg>
        <div className="brand"><b>L.A.Y.E.R.S</b><span>Extension Risk Analysis</span></div>
        <div className="local"><span className="dot" />Local only · nothing leaves this tab</div>
      </div>

      <div className="shell">
        <aside className="side">
          {scanReady && (<>
            <div className="slab">Analysis</div>
            {NAV_ANALYSIS.map((n) => <NavItem key={n.id} n={n} />)}
            <div className="slab">Severity</div>
            <div style={{ padding: "0 6px" }}>
              {["crit", "high", "med", "low"].map((s) => {
                const v = sevCount(s), max = Math.max(sevCount("crit"), sevCount("high"), sevCount("med"), sevCount("low"), 1);
                return <div key={s} style={{ marginBottom: 11 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 5, color: SEV_COLOR[s] }}><span>{s}</span><span>{v}</span></div>
                  <div style={{ height: 5, background: "var(--panel3)", borderRadius: 4, overflow: "hidden" }}><div style={{ height: "100%", width: (v / max) * 100 + "%", background: SEV_COLOR[s], borderRadius: 4, transition: "width .9s cubic-bezier(.2,.7,.2,1)" }} /></div>
                </div>;
              })}
            </div>
          </>)}
          <div className="slab">Reference</div>
          {NAV_REF.map((n) => <NavItem key={n.id} n={n} />)}
          {!scanReady && <div style={{ padding: "18px 8px 0", fontSize: 11, color: "var(--dim2)", lineHeight: 1.7 }}>Drop an extension to unlock the analysis views. Scoring and Wiki are available now.</div>}
        </aside>

        <main className="main">
          {tab === "scoring" && <ScoringTab R={scanReady ? R : null} />}
          {tab === "wiki" && <WikiTab />}

          {tab !== "scoring" && tab !== "wiki" && state === "idle" && (
            <div className="view">
              <div className={`dz ${drag ? "drag" : ""}`} onClick={() => fileRef.current.click()}
                onDragOver={(e) => { e.preventDefault(); setDrag(true); }} onDragLeave={(e) => { e.preventDefault(); setDrag(false); }} onDrop={onDrop}>
                <div className="sweep" />
                <div className="glyph"><svg viewBox="0 0 36 36"><path d="M18 6v16M11 14l7-7 7 7M6 28h24" strokeLinecap="round" strokeLinejoin="round" /></svg></div>
                <h2 className="disp">Drop a .crx or .zip extension</h2>
                <p>The archive is unpacked and analysed entirely in this tab. No file, no line of code, no finding is ever uploaded.</p>
                <div style={{ marginTop: 24 }}><button className="btn p" onClick={(e) => { e.stopPropagation(); fileRef.current.click(); }}>Choose file</button></div>
                <input ref={fileRef} type="file" accept=".crx,.zip" onChange={(e) => e.target.files[0] && process(e.target.files[0])} />
              </div>
              {err && <div className="verdict v-high" style={{ marginTop: 15 }}><svg viewBox="0 0 20 20"><path d="M10 6v5M10 14v.5" /><circle cx="10" cy="10" r="8" /></svg>{err}</div>}
              <div className="grid">
                {[["Capability model", "var(--trace)", "Maps permissions and code into what the extension can actually do — read pages, inject, intercept, exfiltrate, bridge to native."],
                  ["Attack-chain graph", "var(--crit)", "The constellation draws a live edge for every combination that forms a named threat: exfiltration engine, MITM, cookie theft, RCE channel."],
                  ["Source → sink taint", "var(--high)", "A sink is elevated only when a real data source shares the file — far fewer false alarms on bundled code."],
                  ["Vendor-aware scoring", "var(--violet)", "Classifies first-party vs library/minified code so framework internals don't sink the score."],
                  ["Gated secret hunt", "var(--med)", "20+ credential patterns with placeholder filtering and entropy gates on the generic ones."],
                  ["Transparent score", "var(--low)", "Open the Scoring tab to see exactly how every point is subtracted — no black box."]
                ].map(([t, c, d]) => <div className="fcard" key={t}><div className="t"><span className="pip" style={{ background: c, color: c }} />{t}</div><div className="d">{d}</div></div>)}
              </div>
            </div>
          )}

          {tab !== "scoring" && tab !== "wiki" && state === "loading" && (
            <div className="view load">
              <div className="ldisk">
                <svg viewBox="0 0 78 78"><circle cx="39" cy="39" r="31" fill="none" stroke="var(--panel3)" strokeWidth="4" /><circle className="larc" cx="39" cy="39" r="31" fill="none" strokeWidth="4" strokeLinecap="round" strokeDasharray="165" strokeDashoffset="70" /></svg>
                <div className="core"><b>SCAN</b></div>
              </div>
              <div className="ltitle disp">Analysing extension</div>
              <div className="lstep">{step}…</div>
              <div className="ltrack"><i style={{ width: prog + "%" }} /></div>
            </div>
          )}

          {tab !== "scoring" && tab !== "wiki" && scanReady && (
            <div className="view" key={tab}>
              {tab === "overview" && (<>
                <div className="h1"><span className="bar" /><span className="disp">{R.name}</span><em>v{R.version} · MV{R.manifest?.manifest_version || "?"}</em></div>
                <div className={`verdict ${verdictClass(R.score)}`}><svg viewBox="0 0 20 20"><path d="M10 5v6M10 14v.5" /><circle cx="10" cy="10" r="8" /></svg>{verdictText(R.score)}</div>
                <div className="hero"><Gauge score={R.score} /><Constellation capabilities={R.capabilities} combos={R.combos} /></div>
                <ComboList combos={R.combos} />
                <div className="stats">
                  {[["crit", sevCount("crit"), "var(--crit)"], ["high", sevCount("high"), "var(--high)"], ["med", sevCount("med"), "var(--med)"], ["low", sevCount("low"), "var(--low)"]].map(([l, v, c], i) => (
                    <div className="stat" key={l} style={{ animationDelay: i * .05 + "s" }}><div className="v" style={{ color: c }}>{v}</div><div className="k">{l}</div>
                      <div className="track"><i style={{ width: Math.min(100, (v / Math.max(R.findings.length, 1)) * 100) + "%", background: c }} /></div></div>
                  ))}
                  <div className="stat"><div className="v" style={{ color: "var(--trace)" }}>{Object.keys(R.files).length}</div><div className="k">files</div></div>
                  <div className="stat"><div className="v" style={{ color: "var(--violet)" }}>{R.urls.length}</div><div className="k">urls</div></div>
                  <div className="stat"><div className="v" style={{ color: "var(--info)" }}>{R.capabilities.length}</div><div className="k">powers</div></div>
                </div>
                <div className="panel">
                  <div className="phead"><div className="ptitle"><span className="l" />Score breakdown</div><span className="psub mono">100 → {R.score} · see Scoring tab</span></div>
                  {R.breakdown.map((b, i) => (
                    <div key={i} style={{ display: "flex", alignItems: "center", gap: 12, padding: "7px 0", fontSize: 12.5, borderBottom: "1px solid var(--line)" }}>
                      <span style={{ flex: 1, color: "var(--dim)" }}>{b.label}</span>
                      <div style={{ width: 120, height: 5, background: "var(--panel3)", borderRadius: 3, overflow: "hidden" }}><div style={{ height: "100%", width: Math.min(100, Math.abs(b.pts) * 2.5) + "%", background: "var(--crit)", borderRadius: 3 }} /></div>
                      <span className="mono" style={{ width: 44, textAlign: "right", fontWeight: 700, color: "var(--crit)" }}>{b.pts}</span>
                    </div>
                  ))}
                  <div style={{ display: "flex", justifyContent: "space-between", paddingTop: 11, fontWeight: 700 }}><span>Final exposure</span><span className="mono disp" style={{ color: scoreColor(R.score) }}>{R.score} / 100</span></div>
                </div>
                {perms.length > 0 && (
                  <div className="panel"><div className="phead"><div className="ptitle"><span className="l" />Permission heatmap</div><span className="psub">{perms.length} declared</span></div>
                    <div className="heat">{perms.map((p) => { const info = PERM_DB[p] || { risk: "low" }; return <div key={p} className={`ptile pt-${info.risk}`} title={info.desc || p}>{p}</div>; })}</div></div>
                )}
                <div className="panel"><div className="phead"><div className="ptitle"><span className="l" />Metadata</div></div>
                  <div className="meta">{[["Name", R.name], ["Version", R.version], ["Manifest", "V" + (R.manifest?.manifest_version || "?")], ["Background", R.manifest?.background?.service_worker || R.manifest?.background?.scripts?.join(",") || "none"], ["Permissions", (R.manifest?.permissions || []).length + " declared"], ["Files", Object.keys(R.files).length]].map(([k, v]) => <div className="mi" key={k}><div className="k">{k}</div><div className="v">{String(v)}</div></div>)}</div></div>
              </>)}

              {tab === "findings" && (<>
                <div className="h1"><span className="bar" /><span className="disp">All findings</span><em>{R.findings.length} total</em></div>
                <div className="search"><svg viewBox="0 0 20 20"><circle cx="8" cy="8" r="6" /><path d="M13 13l4 4" /></svg>
                  <input placeholder="Search by title, file or description…" value={q} onChange={(e) => setQ(e.target.value)} /></div>
                <div className="filters">{["all", "crit", "high", "med", "low"].map((s) => <button key={s} className={`fbtn ${sev === s ? "on" : ""}`} onClick={() => setSev(s)}>{s === "all" ? "All" : s} {s === "all" ? R.findings.length : sevCount(s)}</button>)}</div>
                {filtered.length ? filtered.map((f) => <Finding key={f.id} f={f} />) : <div className="panel"><div className="empty">Nothing matches this filter.</div></div>}
              </>)}

              {tab === "manifest" && (<>
                <div className="h1"><span className="bar" /><span className="disp">Manifest analysis</span></div>
                {!R.manifest ? <div className="panel"><div className="empty">No manifest.json found.</div></div> : (<>
                  <div className="panel"><div className="phead"><div className="ptitle"><span className="l" />Permission detail</div><span className="psub">{perms.length} declared</span></div>
                    {perms.slice().sort((a, b) => (SEV_ORDER[PERM_DB[a]?.risk] ?? 3) - (SEV_ORDER[PERM_DB[b]?.risk] ?? 3)).map((p) => {
                      const info = PERM_DB[p] || { risk: "low", desc: "Extension permission." };
                      return <div key={p} className={`find ${info.risk}`}><div className="fbody"><div className="ftitle"><Badge s={info.risk} /><span className="mono">{p}</span>
                        {(R.manifest.optional_permissions || []).includes(p) && <span className="conf">optional</span>}
                        {(R.manifest.host_permissions || []).includes(p) && <span className="conf">host</span>}</div><div className="fdesc">{info.desc}</div></div></div>;
                    })}
                  </div>
                  <div className="panel"><div className="phead"><div className="ptitle"><span className="l" />Raw manifest.json</div></div><pre className="pre">{JSON.stringify(R.manifest, null, 2)}</pre></div>
                </>)}
              </>)}

              {["js", "html", "privacy", "network"].includes(tab) && (<>
                <div className="h1"><span className="bar" /><span className="disp">{{ js: "JavaScript", html: "HTML", privacy: "Privacy & fingerprinting", network: "Network & URLs" }[tab]}</span>
                  <em>{catFindings(tab).length} finding{catFindings(tab).length !== 1 ? "s" : ""}</em></div>
                {tab === "network" && (
                  <div className="stats">{[["Total", R.urls.length, "var(--trace)"], ["External", R.urls.filter((u) => !/localhost|127\.0\.0\.1/.test(u.url)).length, "var(--high)"], ["HTTP", R.urls.filter((u) => u.url.startsWith("http:")).length, "var(--crit)"], ["Wildcard", R.urls.filter((u) => u.url.includes("*")).length, "var(--crit)"]].map(([l, v, c]) => <div className="stat" key={l}><div className="v" style={{ color: c }}>{v}</div><div className="k">{l}</div></div>)}</div>
                )}
                <div className="panel"><div className="phead"><div className="ptitle"><span className="l" />Findings</div></div>
                  {catFindings(tab).length ? catFindings(tab).map((f) => <Finding key={f.id} f={f} />) : <div className="empty">Nothing detected in this category.</div>}</div>
                {tab === "network" && (
                  <div className="panel"><div className="phead"><div className="ptitle"><span className="l" />Extracted URLs</div><span className="psub">{R.urls.length}</span></div>
                    <div>{R.urls.length ? R.urls.map(({ url }, i) => { const c = url.includes("*") || url === "<all_urls>" ? "d" : url.startsWith("http:") ? "w" : ""; return <span key={i} className={`chip ${c}`} title={url}>{url}</span>; }) : <div className="empty">No URLs found.</div>}</div></div>
                )}
              </>)}

              {tab === "secrets" && (<>
                <div className="h1"><span className="bar" /><span className="disp">Secrets & credentials</span><em>{catFindings("secrets").length} finding{catFindings("secrets").length !== 1 ? "s" : ""}</em></div>
                {catFindings("secrets").length ? (<>
                  <div className="verdict v-high"><svg viewBox="0 0 20 20"><path d="M10 5v6M10 14v.5" /><circle cx="10" cy="10" r="8" /></svg>All values are redacted. Confirm each is a live secret — placeholder and sample keys are filtered but not guaranteed absent.</div>
                  <div className="panel"><div className="phead"><div className="ptitle"><span className="l" />Detected credentials</div></div>{catFindings("secrets").map((f) => <Finding key={f.id} f={f} />)}</div>
                </>) : <div className="panel"><div className="empty">No hardcoded secrets detected.</div></div>}
              </>)}

              {tab === "files" && (<>
                <div className="h1"><span className="bar" /><span className="disp">File tree</span><em>{Object.keys(R.files).length} files</em></div>
                <div className="panel">
                  {Object.entries(R.files).sort(([a], [b]) => a.localeCompare(b)).map(([name, content]) => {
                    const e = name.split(".").pop().toLowerCase();
                    const size = content === "[binary]" ? "binary" : (new Blob([content]).size < 1024 ? new Blob([content]).size + "B" : (new Blob([content]).size / 1024).toFixed(1) + "KB");
                    const issues = R.findings.filter((f) => String(f.file).startsWith(name)).length;
                    const extColor = { js: "var(--med)", ts: "var(--med)", mjs: "var(--med)", html: "var(--high)", htm: "var(--high)", json: "var(--trace)", css: "var(--violet)" }[e] || "var(--dim2)";
                    return <div className="file" key={name}>
                      <span className="ext" style={{ color: extColor }}>{e}</span>
                      <span style={{ flex: 1, color: "var(--txt)" }}>{name}</span>
                      {R.cls[name] === "vendor" && <span className="tag t-vendor">vendor</span>}
                      {R.cls[name] === "minified" && <span className="tag t-min">min</span>}
                      {issues > 0 && <span className={`bdg b-${issues > 3 ? "crit" : "high"}`}>{issues}</span>}
                      <span style={{ color: "var(--dim2)", fontSize: 10 }}>{size}</span>
                    </div>;
                  })}
                </div>
              </>)}

              {tab === "report" && (<>
                <div className="h1"><span className="bar" /><span className="disp">Export report</span></div>
                <div className="panel"><div className="phead"><div className="ptitle"><span className="l" />Download</div></div>
                  <p style={{ fontSize: 12.5, color: "var(--dim)", marginBottom: 15, lineHeight: 1.7 }}>Full report: exposure score, capability model, attack chains and all {R.findings.length} findings with confidence and location. Secret values are redacted.</p>
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                    <button className="btn p sm" onClick={() => download("json")}>Download JSON</button>
                    <button className="btn g sm" onClick={() => download("csv")}>Download CSV</button>
                    <button className="btn g sm" onClick={() => navigator.clipboard?.writeText(JSON.stringify(report, null, 2))}>Copy JSON</button>
                    <button className="btn g sm" onClick={() => { setState("idle"); setR(null); setProg(0); setTab("overview"); }}>New scan</button>
                  </div></div>
                <div className="panel"><div className="phead"><div className="ptitle"><span className="l" />JSON preview</div></div><pre className="pre">{JSON.stringify(report, null, 2)}</pre></div>
              </>)}
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
