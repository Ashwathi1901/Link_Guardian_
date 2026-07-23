/**
 * Link Guardian — Frontend Client Application
 * Communicates with FastAPI backend on Hugging Face Spaces / local dev.
 */

// Production Hugging Face Space URL format example:
// const BACKEND_URL = 'https://ashwathi1901-link-guardian-backend.hf.space';
const BACKEND_URL = 'http://localhost:7860';

document.addEventListener('DOMContentLoaded', () => {
  initAnalyzerForm();
  loadZapReport();
});

/**
 * Initializes the URL & Email analyzer form logic.
 */
function initAnalyzerForm() {
  const form = document.getElementById('analyze-form');
  const submitBtn = document.getElementById('submit-btn');
  const btnText = document.getElementById('btn-text');
  const btnSpinner = document.getElementById('btn-spinner');
  const wakeupBanner = document.getElementById('wakeup-banner');
  const errorBanner = document.getElementById('error-banner');
  const errorMessage = document.getElementById('error-message');
  const resultCard = document.getElementById('result-card');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const urlInput = document.getElementById('url-input').value.trim();
    const contentInput = document.getElementById('content-input').value.trim();

    if (!urlInput) {
      showError('Please enter a valid target URL.');
      return;
    }

    // UI Loading State
    hideError();
    resultCard.classList.add('hidden');
    submitBtn.disabled = true;
    btnText.textContent = 'Analyzing...';
    btnSpinner.classList.remove('hidden');

    // Cold-start detection timer (shows wake-up message if backend takes >2.5s)
    let wakeupTimer = setTimeout(() => {
      wakeupBanner.classList.remove('hidden');
    }, 2500);

    try {
      // Optional wake-up ping to health check
      fetch(`${BACKEND_URL}/health`, { method: 'GET' }).catch(() => {});

      // Call primary analyze endpoint
      const response = await fetch(`${BACKEND_URL}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: urlInput,
          content: contentInput
        })
      });

      clearTimeout(wakeupTimer);
      wakeupBanner.classList.add('hidden');

      if (!response.ok) {
        let errDetail = 'Analysis request failed.';
        try {
          const errData = await response.json();
          if (errData.detail) {
            errDetail = typeof errData.detail === 'string' 
              ? errData.detail 
              : (errData.detail[0]?.msg || JSON.stringify(errData.detail));
          }
        } catch (_) {}
        throw new Error(errDetail);
      }

      const data = await response.json();
      renderAnalysisResult(data);

    } catch (err) {
      clearTimeout(wakeupTimer);
      wakeupBanner.classList.add('hidden');
      
      let msg = err.message || 'Failed to connect to backend server.';
      if (err.name === 'TypeError' && err.message.includes('fetch')) {
        msg = `Unable to reach backend at ${BACKEND_URL}. If the container is cold-starting, please wait ~30 seconds and retry.`;
      }
      showError(msg);
    } finally {
      submitBtn.disabled = false;
      btnText.textContent = 'Analyze Threat';
      btnSpinner.classList.add('hidden');
    }
  });
}

/**
 * Renders the ML analysis result payload.
 */
function renderAnalysisResult(data) {
  const resultCard = document.getElementById('result-card');
  const verdictBadge = document.getElementById('verdict-badge');
  const verdictIcon = document.getElementById('verdict-icon');
  const verdictText = document.getElementById('verdict-text');
  const confidenceVal = document.getElementById('confidence-val');
  const confidenceBar = document.getElementById('confidence-bar');
  const reasonsList = document.getElementById('reasons-list');
  const timestampText = document.getElementById('scanned-timestamp');
  const urlText = document.getElementById('normalized-url-text');

  const verdict = (data.verdict || 'safe').toLowerCase();
  const confidence = data.confidence || 0;
  const reasons = data.reasons || [];
  const timestamp = data.scanned_at ? new Date(data.scanned_at).toLocaleString() : new Date().toLocaleString();
  const normalizedUrl = data.normalized_url || '';

  // Reset classes
  verdictBadge.className = 'verdict-badge';
  confidenceBar.className = 'progress-bar-fill';

  if (verdict === 'phishing') {
    verdictBadge.classList.add('badge-phishing');
    verdictIcon.textContent = '🚨';
    verdictText.textContent = 'PHISHING';
    confidenceBar.classList.add('fill-phishing');
  } else if (verdict === 'suspicious') {
    verdictBadge.classList.add('badge-suspicious');
    verdictIcon.textContent = '⚠️';
    verdictText.textContent = 'SUSPICIOUS';
    confidenceBar.classList.add('fill-suspicious');
  } else {
    verdictBadge.classList.add('badge-safe');
    verdictIcon.textContent = '✅';
    verdictText.textContent = 'SAFE';
    confidenceBar.classList.add('fill-safe');
  }

  confidenceVal.textContent = `${confidence.toFixed(1)}%`;
  confidenceBar.style.width = `${Math.min(Math.max(confidence, 5), 100)}%`;

  // Render reasons list
  reasonsList.innerHTML = '';
  if (reasons.length === 0) {
    const li = document.createElement('li');
    li.className = 'reason-item';
    li.textContent = 'No explicit risk signals detected.';
    reasonsList.appendChild(li);
  } else {
    reasons.forEach(reason => {
      const li = document.createElement('li');
      li.className = 'reason-item';
      li.innerHTML = `<span>⚡</span> <span>${escapeHtml(reason)}</span>`;
      reasonsList.appendChild(li);
    });
  }

  timestampText.textContent = `Scanned at: ${timestamp}`;
  urlText.textContent = `Target: ${normalizedUrl}`;

  resultCard.classList.remove('hidden');
  resultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

/**
 * Loads OWASP ZAP telemetry report from backend.
 */
async function loadZapReport() {
  const findingsList = document.getElementById('findings-list');
  const targetSite = document.getElementById('zap-target-site');

  try {
    const res = await fetch(`${BACKEND_URL}/api/zap-report`);
    if (!res.ok) throw new Error('Failed to load ZAP report');

    const data = await res.json();
    
    // Update summary counts
    if (data.summary) {
      document.getElementById('stat-high-count').textContent = data.summary.High ?? 0;
      document.getElementById('stat-medium-count').textContent = data.summary.Medium ?? 0;
      document.getElementById('stat-low-count').textContent = data.summary.Low ?? 0;
      document.getElementById('stat-info-count').textContent = data.summary.Informational ?? 0;
    }

    if (data.target_site) {
      targetSite.textContent = `Target: ${data.target_site.replace(/^https?:\/\//, '')}`;
    }

    // Render findings
    findingsList.innerHTML = '';
    const findings = data.findings || [];
    if (findings.length === 0) {
      findingsList.innerHTML = '<div class="loading-state">No security findings reported in scan telemetry.</div>';
      return;
    }

    findings.forEach(f => {
      const card = document.createElement('div');
      card.className = 'finding-card';
      const riskClass = f.risk ? `sev-${f.risk.toLowerCase()}` : 'sev-informational';
      
      card.innerHTML = `
        <div class="finding-header">
          <span class="finding-name">${escapeHtml(f.name || 'Security Finding')}</span>
          <span class="severity-badge ${riskClass}">${escapeHtml(f.risk || 'Info')}</span>
        </div>
        <div class="finding-desc">${escapeHtml(f.description || '')}</div>
      `;
      findingsList.appendChild(card);
    });

  } catch (err) {
    console.warn('ZAP report fetch error:', err);
    findingsList.innerHTML = `
      <div class="finding-card">
        <div class="finding-name" style="color: var(--suspicious-yellow);">Security Audit Data Offline</div>
        <div class="finding-desc">Could not connect to ${BACKEND_URL}/api/zap-report to load security scan findings.</div>
      </div>
    `;
  }
}

function showError(msg) {
  const errorBanner = document.getElementById('error-banner');
  const errorMessage = document.getElementById('error-message');
  errorMessage.textContent = msg;
  errorBanner.classList.remove('hidden');
}

function hideError() {
  const errorBanner = document.getElementById('error-banner');
  errorBanner.classList.add('hidden');
}

function escapeHtml(str) {
  return str.replace(/[&<>"']/g, function(m) {
    return {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    }[m];
  });
}
