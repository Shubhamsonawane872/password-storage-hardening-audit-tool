/* ═══════════════════════════════════════════════════════════════════════════
   Password Audit Tool — shared JS utilities
   ═══════════════════════════════════════════════════════════════════════════ */

'use strict';

const API_BASE = '/api';

/* ── Fetch helper ────────────────────────────────────────────────────────── */

/**
 * apiFetch(endpoint, options)
 *
 * Wraps fetch() with:
 *   - Automatic /api prefix (or /api/v2 for advanced endpoints)
 *   - Content-Type: application/json on non-FormData requests
 *   - Throws a structured {status, message} error on non-2xx responses
 *
 * Usage:
 *   apiFetch('/auth/me')               → GET /api/auth/me
 *   apiFetch('/v2/analytics/trends')   → GET /api/v2/analytics/trends
 */
async function apiFetch(endpoint, options = {}) {
  const url = API_BASE + endpoint;

  const headers = { ...(options.headers || {}) };

  // Don't force Content-Type for FormData — browser sets multipart boundary
  if (!(options.body instanceof FormData) && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }

  const resp = await fetch(url, { ...options, headers });

  if (!resp.ok) {
    let errMsg = `HTTP ${resp.status}`;
    try {
      const payload = await resp.json();
      errMsg = payload.error || payload.message || errMsg;
    } catch { /* non-JSON body */ }
    const err = new Error(errMsg);
    err.status = resp.status;
    throw err;
  }

  // 204 No Content — return empty object
  if (resp.status === 204) return {};

  return resp.json();
}

/* ── Auth helpers ────────────────────────────────────────────────────────── */

async function logout() {
  try { await apiFetch('/auth/logout', { method: 'POST' }); } catch { /* ignore */ }
  window.location.href = '/';
}

/* ── Toast / alert ───────────────────────────────────────────────────────── */

let _alertTimer = null;

/**
 * showAlert(message, type)
 * type: 'success' | 'error' | 'warning' | 'info'
 *
 * Inserts a dismissible flash above the page content and auto-removes after 5 s.
 */
function showAlert(message, type = 'info') {
  const container = document.getElementById('flashContainer')
    || document.querySelector('.page-container')
    || document.body;

  // Remove existing same-type alerts
  container.querySelectorAll('.flash').forEach(el => el.remove());

  const div = document.createElement('div');
  div.className = `flash flash-${type}`;
  div.setAttribute('role', 'alert');
  div.innerHTML = `
    <span>${escapeHtml(message)}</span>
    <button class="flash-close" aria-label="Dismiss" onclick="this.parentElement.remove()">×</button>`;

  container.insertBefore(div, container.firstChild);
  clearTimeout(_alertTimer);
  _alertTimer = setTimeout(() => div.remove(), 5500);
}

/* ── String helpers ──────────────────────────────────────────────────────── */

/** Escape HTML to prevent XSS when inserting user content via innerHTML. */
function escapeHtml(text) {
  if (text == null) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/** Format an ISO timestamp as a readable local date+time string. */
function formatDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

/** Human-readable file size (e.g. "2.4 MB"). */
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

/* ── Severity badge ──────────────────────────────────────────────────────── */

function createSeverityBadge(severity) {
  return `<span class="badge badge-${severity}">${severity.toUpperCase()}</span>`;
}

/* ── Validation helpers ──────────────────────────────────────────────────── */

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
}

/**
 * Validate password strength.
 * Returns an array of error strings (empty = valid).
 */
function validatePassword(password) {
  const errs = [];
  if (!password || password.length < 8)     errs.push('At least 8 characters');
  if (!/[A-Z]/.test(password))              errs.push('One uppercase letter');
  if (!/[a-z]/.test(password))              errs.push('One lowercase letter');
  if (!/\d/.test(password))                 errs.push('One digit');
  if (!/[!@#$%^&*()_+\-=\[\]{};:"\\|,.<>?/`~']/.test(password))
                                            errs.push('One special character');
  return errs;
}

/* ── Clipboard ───────────────────────────────────────────────────────────── */

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    showAlert('Copied to clipboard!', 'success');
  } catch {
    showAlert('Copy failed — select and copy manually.', 'warning');
  }
}

/* ── Initialisation ──────────────────────────────────────────────────────── */

document.addEventListener('DOMContentLoaded', () => {
  // Auto-dismiss any server-rendered flash messages
  document.querySelectorAll('.flash').forEach(el => {
    setTimeout(() => el.remove(), 6000);
  });
});
