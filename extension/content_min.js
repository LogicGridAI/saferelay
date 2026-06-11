"use strict";
const CONFIG = {
REVERSE_SHIELD_MIN_SSN: 6,
BADGE_BG: "#d4edda",
BADGE_BORDER: "#28a745",
LOG_PREFIX: "🛡️ SafePaste Enterprise:"
};
const STORAGE = {
isLicensed: "isLicensed",
basicProtection: "basicProtection",
devsecMode: "devsecMode",
fintechShield: "fintechShield",
corporateShield: "corporateShield",
civicShield: "civicShield",
exfiltrationShield: "exfiltrationShield",
customWords: "customWords"
};
const STATE = {
isLicensed: false,
basicProtection: true,
devsecMode: true,
fintechShield: true,
corporateShield: true,
civicShield: true,
exfiltrationShield: true
};
let customWords = [];
function safeSendMessage(message) {
try {
chrome.runtime.sendMessage(message);
} catch (_err) {
console.warn('SafePaste: Extension context invalid. Please refresh the page.');
}
}
function escapeRegex(s) {
return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
function applyPatternPass(sanitized, pattern, licensed) {
const re = new RegExp(pattern.regex.source, pattern.regex.flags);
let count = 0;
const out = sanitized.replace(re, (match => {
if (pattern.validate && !pattern.validate(match)) return match;
count++;
if (!licensed) {
return `[REDACTED_${pattern.type}]`;
}
return SafeVault.store(pattern.type, match);
}));
return {
text: out,
count: count
};
}
function shouldApplyThreatPattern(pattern) {
if (pattern.basic === true) {
return STATE.basicProtection;
}
if (pattern.group === "devsec") {
return STATE.devsecMode;
}
if (pattern.group === "fintech") {
return STATE.fintechShield;
}
if (pattern.group === "corporate") {
return STATE.corporateShield;
}
if (pattern.group === "civic") {
return STATE.civicShield;
}
return false;
}
function tokenize(text) {
let sanitized = text;
let total = 0;
if (!STATE.isLicensed) {
if (!STATE.basicProtection) {
return {
sanitized: text,
count: 0
};
}
for (const pattern of THREAT_PATTERNS) {
if (!pattern.freeTier || pattern.basic !== true) continue;
const {text: next, count: count} = applyPatternPass(sanitized, pattern, false);
sanitized = next;
total += count;
}
return {
sanitized: sanitized,
count: total
};
}
const words = [ ...customWords ].sort(((a, b) => b.length - a.length));
for (const word of words) {
if (!word || word.length < 2) continue;
const re = new RegExp(`\\b${escapeRegex(word)}\\b`, "gi");
sanitized = sanitized.replace(re, (m => {
total++;
return SafeVault.store("NDA", m);
}));
}
for (const pattern of THREAT_PATTERNS) {
if (!shouldApplyThreatPattern(pattern)) continue;
const {text: next, count: count} = applyPatternPass(sanitized, pattern, true);
sanitized = next;
total += count;
}
return {
sanitized: sanitized,
count: total
};
}
let _storageReady = false;
let _pendingCallbacks = [];
function onStorageReady(fn) {
if (_storageReady) { fn(); return; }
_pendingCallbacks.push(fn);
}
function loadStorage() {
chrome.storage.local.get({
[STORAGE.isLicensed]: false,
[STORAGE.basicProtection]: true,
[STORAGE.devsecMode]: true,
[STORAGE.fintechShield]: true,
[STORAGE.corporateShield]: true,
[STORAGE.civicShield]: true,
[STORAGE.exfiltrationShield]: true,
[STORAGE.customWords]: []
}, (items => {
STATE.isLicensed = Boolean(items[STORAGE.isLicensed]);
STATE.basicProtection = items[STORAGE.basicProtection] !== false;
STATE.devsecMode = items[STORAGE.devsecMode] !== false;
STATE.fintechShield = items[STORAGE.fintechShield] !== false;
STATE.corporateShield = items[STORAGE.corporateShield] !== false;
STATE.civicShield = items[STORAGE.civicShield] !== false;
STATE.exfiltrationShield = items[STORAGE.exfiltrationShield] !== false;
customWords = Array.isArray(items[STORAGE.customWords]) ? items[STORAGE.customWords] : [];
_storageReady = true;
_pendingCallbacks.forEach(fn => fn());
_pendingCallbacks = [];
syncVaultObserver();
}));
}
loadStorage();
chrome.storage.onChanged.addListener(((changes, area) => {
if (area !== "local") return;
if (changes[STORAGE.isLicensed]) {
STATE.isLicensed = Boolean(changes[STORAGE.isLicensed].newValue);
syncVaultObserver();
}
if (changes[STORAGE.basicProtection]) {
STATE.basicProtection = changes[STORAGE.basicProtection].newValue !== false;
}
if (changes[STORAGE.devsecMode]) {
STATE.devsecMode = changes[STORAGE.devsecMode].newValue !== false;
}
if (changes[STORAGE.fintechShield]) {
STATE.fintechShield = changes[STORAGE.fintechShield].newValue !== false;
}
if (changes[STORAGE.corporateShield]) {
STATE.corporateShield = changes[STORAGE.corporateShield].newValue !== false;
}
if (changes[STORAGE.civicShield]) {
STATE.civicShield = changes[STORAGE.civicShield].newValue !== false;
}
if (changes[STORAGE.exfiltrationShield]) {
STATE.exfiltrationShield = changes[STORAGE.exfiltrationShield].newValue !== false;
}
if (changes[STORAGE.customWords]) {
customWords = Array.isArray(changes[STORAGE.customWords].newValue) ? changes[STORAGE.customWords].newValue : [];
}
}));
function isGoogleWorkspaceApp() {
try {
const topHost = window.top?.location?.hostname || '';
if (topHost === 'docs.google.com' ||
topHost === 'sheets.google.com' ||
topHost === 'slides.google.com') return true;
} catch(e) { return true; }
const host = location.hostname;
if (host === 'docs.google.com' ||
host === 'sheets.google.com' ||
host === 'slides.google.com') return true;
if (document.querySelector(
'.kix-appview-editor, .docs-editor, .grid-container, ' +
'[id="docs-editor"], .kix-page, .docs-texteventtarget-iframe'
)) return true;
return false;
}
document.addEventListener("paste", (event => {
if (isGoogleWorkspaceApp()) {
console.info(`${CONFIG.LOG_PREFIX} Google Workspace detected — paste interception skipped. Exfiltration Shield remains active.`);
return;
}
if (!_storageReady) {
const raw = (event.clipboardData || window.clipboardData)?.getData("text");
if (!raw) return;
event.preventDefault();
event.stopImmediatePropagation();
onStorageReady(() => insertSanitizedText(event.target, raw));
return;
}
const raw = (event.clipboardData || window.clipboardData)?.getData("text");
if (!raw) return;
const { sanitized, count } = tokenize(raw);
if (count === 0) return;
event.preventDefault();
event.stopPropagation();
event.stopImmediatePropagation();
insertSanitizedText(event.target, sanitized);
console.info(`${CONFIG.LOG_PREFIX} Redacted ${count} sensitive item(s).`);
if (STATE.isLicensed && count > 0) {
safeSendMessage({ type: "VAULT_STAT_UPDATE", vaultedDelta: count });
}
}), true);
function insertSanitizedText(target, text) {
const { sanitized } = tokenize(text);
const out = sanitized !== undefined ? sanitized : text;
if (target && typeof target.setRangeText === "function") {
const start = target.selectionStart ?? 0;
const end = target.selectionEnd ?? 0;
target.setRangeText(out, start, end, "end");
target.dispatchEvent(new Event("input", { bubbles: true }));
} else {
const selection = window.getSelection();
if (!selection?.rangeCount) return;
const range = selection.getRangeAt(0);
range.deleteContents();
range.insertNode(document.createTextNode(out));
range.collapse(false);
selection.removeAllRanges();
selection.addRange(range);
target?.dispatchEvent(new InputEvent("input", { bubbles: true, cancelable: true, data: out }));
}
}
const _processedNodes = new WeakSet;
function isInEditableOrScript(node) {
let el = node.nodeType === Node.TEXT_NODE ? node.parentElement : node;
while (el) {
const tag = el.tagName;
if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SCRIPT" || tag === "STYLE" || tag === "NOSCRIPT") return true;
if (el.isContentEditable) return true;
el = el.parentElement;
}
return false;
}
function swapPlaceholdersInNode(textNode) {
if (!STATE.isLicensed) return;
if (_processedNodes.has(textNode)) return;
if (!textNode.parentNode || isInEditableOrScript(textNode)) return;
if (SafeVault.size() === 0) return;
const text = textNode.nodeValue;
if (!text) return;
const hits = SafeVault.keys().filter((k => text.includes(k)));
if (hits.length === 0) return;
hits.sort(((a, b) => b.length - a.length));
const frag = document.createDocumentFragment();
let remaining = text;
while (remaining.length > 0) {
let earliest = -1;
let matchKey = null;
for (const key of hits) {
const idx = remaining.indexOf(key);
if (idx !== -1 && (earliest === -1 || idx < earliest)) {
earliest = idx;
matchKey = key;
}
}
if (earliest === -1) {
frag.appendChild(document.createTextNode(remaining));
break;
}
if (earliest > 0) frag.appendChild(document.createTextNode(remaining.slice(0, earliest)));
const real = SafeVault.resolve(matchKey);
if (real == null) {
frag.appendChild(document.createTextNode(matchKey));
} else {
const span = document.createElement("span");
span.setAttribute("data-logicgrid-devsec", "true");
span.style.cssText = [ `background-color: ${CONFIG.BADGE_BG}`, `border: 1px solid ${CONFIG.BADGE_BORDER}`, "border-radius: 4px", "padding: 1px 4px", "font-family: monospace", "font-size: inherit" ].join("; ");
span.textContent = "🔒 " + real;
frag.appendChild(span);
}
remaining = remaining.slice(earliest + matchKey.length);
}
_processedNodes.add(textNode);
textNode.parentNode.replaceChild(frag, textNode);
safeSendMessage({
type: "VAULT_STAT_UPDATE",
swapsDelta: 1
});
}
function runFullVaultSwap() {
if (!STATE.isLicensed || !document.body || SafeVault.size() === 0) return;
const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
acceptNode(node) {
if (_processedNodes.has(node)) return NodeFilter.FILTER_REJECT;
if (isInEditableOrScript(node)) return NodeFilter.FILTER_REJECT;
if (!node.nodeValue) return NodeFilter.FILTER_REJECT;
const has = SafeVault.keys().some((k => node.nodeValue.includes(k)));
return has ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
}
});
const batch = [];
let n;
while (n = walker.nextNode()) batch.push(n);
for (const node of batch) {
if (node.parentNode && !_processedNodes.has(node)) swapPlaceholdersInNode(node);
}
}
let _swapPending = false;
const vaultObserver = new MutationObserver((() => {
if (!STATE.isLicensed || SafeVault.size() === 0 || _swapPending) return;
_swapPending = true;
requestAnimationFrame((() => {
_swapPending = false;
if (!STATE.isLicensed || SafeVault.size() === 0 || !document.body) return;
vaultObserver.disconnect();
try {
runFullVaultSwap();
} finally {
if (STATE.isLicensed && document.body) {
vaultObserver.observe(document.body, {
childList: true,
subtree: true,
characterData: true
});
}
}
}));
}));
function syncVaultObserver() {
vaultObserver.disconnect();
if (STATE.isLicensed && document.body) {
vaultObserver.observe(document.body, {
childList: true,
subtree: true,
characterData: true
});
}
}
if (document.body) syncVaultObserver(); else document.addEventListener("DOMContentLoaded", syncVaultObserver);
function getUsSsnPattern() {
const p = THREAT_PATTERNS.find((x => x.type === "US_SSN"));
return p ? p.regex : /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g;
}
function collectSelectedTextForExfiltrationShield() {
const sel = window.getSelection();
let text = sel ? String(sel.toString()) : "";
if (text.trim()) return text;
if (sel && sel.rangeCount > 0) {
const range = sel.getRangeAt(0);
if (!range.collapsed) {
const holder = document.createElement("div");
holder.appendChild(range.cloneContents());
const fromFrag = holder.innerText || holder.textContent || "";
if (fromFrag.trim()) return fromFrag;
}
}
const active = document.activeElement;
if (active && (active.tagName === "INPUT" || active.tagName === "TEXTAREA")) {
const s = active.selectionStart ?? 0;
const e = active.selectionEnd ?? 0;
const slice = active.value.substring(s, e);
if (slice) return slice;
}
if (active && active instanceof HTMLElement && active.isContentEditable) {
const t = active.innerText || active.textContent || "";
if (t.trim()) return t;
}
if (sel && sel.anchorNode) {
const n = sel.anchorNode;
const fallback = n.nodeType === Node.TEXT_NODE ? n.textContent : n.textContent || "";
if (fallback && fallback.trim()) return fallback;
}
return "";
}
document.addEventListener("copy", (event => {
if (!_storageReady) {
onStorageReady(() => handleCopyEvent(event));
return;
}
handleCopyEvent(event);
}), true);
function handleCopyEvent(event) {
if (!STATE.isLicensed || !STATE.exfiltrationShield) return;
if (isGoogleWorkspaceApp()) {
setTimeout(() => {
navigator.clipboard.readText().then(text => {
if (!text || !text.trim()) return;
const ssnRe = getUsSsnPattern();
const flags = ssnRe.flags.includes("g") ? ssnRe.flags : ssnRe.flags + "g";
const re = new RegExp(ssnRe.source, flags);
const matches = text.match(re);
console.log("🛡️ SafePaste GDocs Copy Check. SSNs found:", matches ? matches.length : 0);
if (!matches || matches.length <= CONFIG.REVERSE_SHIELD_MIN_SSN) return;
navigator.clipboard.writeText("🚨 BLOCKED BY IT").then(() => {
showToast(`Blocked: ${matches.length} US SSN patterns detected. Bulk copy prevented.`, "danger");
safeSendMessage({
type: "REVERSE_SHIELD_EVENT",
timestamp: Date.now(),
matchCount: matches.length,
url: location.hostname
});
}).catch(() => {});
}).catch(() => {});
}, 100);
return;
}
const selected = collectSelectedTextForExfiltrationShield();
if (!selected || !selected.trim()) return;
const ssnRe = getUsSsnPattern();
const flags = ssnRe.flags.includes("g") ? ssnRe.flags : ssnRe.flags + "g";
const re = new RegExp(ssnRe.source, flags);
const matches = selected.match(re);
console.log("🛡️ SafePaste Copy Intercepted. Text length:", selected.length, "| SSNs found:", matches ? matches.length : 0);
if (!matches || matches.length <= CONFIG.REVERSE_SHIELD_MIN_SSN) return;
event.preventDefault();
event.clipboardData?.setData("text/plain", "🚨 BLOCKED BY IT");
showToast(`Blocked: ${matches.length} US SSN patterns detected. Bulk copy prevented.`, "danger");
safeSendMessage({
type: "REVERSE_SHIELD_EVENT",
timestamp: Date.now(),
matchCount: matches.length,
url: location.hostname
});
}
chrome.runtime.onMessage.addListener(((message, _sender, sendResponse) => {
if (message.type === "CLEAR_VAULT") {
SafeVault.clear();
console.info(`${CONFIG.LOG_PREFIX} Vault cleared.`);
sendResponse({
ok: true
});
}
return true;
}));
function showToast(message, type = "info") {
const colors = {
info: {
bg: "#d1ecf1",
border: "#17a2b8",
text: "#0c5460"
},
danger: {
bg: "#f8d7da",
border: "#dc3545",
text: "#721c24"
}
};
const c = colors[type] ?? colors.info;
const toast = document.createElement("div");
toast.setAttribute("role", "alert");
toast.style.cssText = [ "position:fixed", "top:16px", "right:16px", "z-index:2147483647", `background:${c.bg}`, `border:1px solid ${c.border}`, `color:${c.text}`, "padding:12px 16px", "border-radius:8px", "font:500 13px system-ui,sans-serif", "max-width:380px", "box-shadow:0 4px 12px rgba(0,0,0,0.15)" ].join(";");
toast.textContent = message;
document.body.appendChild(toast);
setTimeout((() => {
toast.style.opacity = "0";
setTimeout((() => toast.remove()), 300);
}), 4500);
}