// background.js — Service Worker
// ─────────────────────────────────────────────────────────────
// Receives audit events from content scripts.
// Stores to chrome.storage.local (encrypted at rest by Chrome profile).
// In v2: forward to enterprise SIEM webhook via managed storage config.
// ─────────────────────────────────────────────────────────────

// Note: 'use strict' removed — ES modules are always strict by default.

const MAX_LOG_ENTRIES = 500;

// Reset session stats when Chrome starts fresh
chrome.runtime.onStartup.addListener(() => {
    chrome.storage.local.set({ stat_vaulted: 0, stat_blocked: 0, stat_swaps: 0 });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  if (message.type === 'REVERSE_SHIELD_EVENT') {
    logAuditEvent({
      type:       'REVERSE_SHIELD',
      timestamp:  message.timestamp,
      matchCount: message.matchCount,
      hostname:   message.url,
      tabId:      sender.tab?.id ?? null,
    });
    // Increment blocked stat
    chrome.storage.local.get({ stat_blocked: 0 }, ({ stat_blocked }) => {
      chrome.storage.local.set({ stat_blocked: stat_blocked + 1 });
    });
  }

  if (message.type === 'VAULT_STAT_UPDATE') {
    // Content script reports how many items were vaulted / swapped
    if (message.vaultedDelta) {
      chrome.storage.local.get({ stat_vaulted: 0 }, ({ stat_vaulted }) => {
        chrome.storage.local.set({ stat_vaulted: stat_vaulted + message.vaultedDelta });
      });
    }
    if (message.swapsDelta) {
      chrome.storage.local.get({ stat_swaps: 0 }, ({ stat_swaps }) => {
        chrome.storage.local.set({ stat_swaps: stat_swaps + message.swapsDelta });
      });
    }
  }

  sendResponse({ ok: true });
  return true;
});

async function logAuditEvent(entry) {
  try {
    const { auditLog = [] } = await chrome.storage.local.get('auditLog');
    auditLog.push(entry);

    // Rolling window — keep only the last MAX_LOG_ENTRIES
    if (auditLog.length > MAX_LOG_ENTRIES) {
      auditLog.splice(0, auditLog.length - MAX_LOG_ENTRIES);
    }

    await chrome.storage.local.set({ auditLog });
  } catch (err) {
    console.error('SafePaste: Failed to write audit log', err);
  }
}
