/**
 * NMAP Security Suite — Scan Progress & Telemetry Polling
 * Phase 5: Safe Nmap Execution & Predefined Scan Profiles
 */

document.addEventListener('DOMContentLoaded', function () {
  'use strict';

  const progressContainer = document.getElementById('scanProgressContainer');
  if (!progressContainer) return;

  const scanId = progressContainer.getAttribute('data-scan-id');
  if (!scanId) return;

  const statusBadge = document.getElementById('scanStatusBadge');
  const elapsedTimer = document.getElementById('elapsedTimer');
  const progressBar = document.getElementById('scanProgressBar');
  const btnCancelScan = document.getElementById('btnCancelScan');
  const stageNmapExec = document.getElementById('stageNmapExec');
  const stageXmlSave = document.getElementById('stageXmlSave');
  const stageResults = document.getElementById('stageResults');
  const errorNotice = document.getElementById('scanErrorNotice');
  const errorNoticeText = document.getElementById('scanErrorNoticeText');

  let pollInterval = null;
  let secondsCounter = 0;
  let timerInterval = null;

  // CSRF helper
  const csrfTokenInput = document.querySelector('input[name="csrf_token"]');
  function getCsrfToken() {
    return csrfTokenInput ? csrfTokenInput.value : '';
  }

  // Elapsed timer tick
  function startElapsedTimer() {
    timerInterval = setInterval(() => {
      secondsCounter++;
      const mins = String(Math.floor(secondsCounter / 60)).padStart(2, '0');
      const secs = String(secondsCounter % 60).padStart(2, '0');
      if (elapsedTimer) {
        elapsedTimer.textContent = `${mins}:${secs}`;
      }
    }, 1000);
  }

  // Cancel Scan Button
  if (btnCancelScan) {
    btnCancelScan.addEventListener('click', async function () {
      if (!confirm('Are you sure you want to terminate this scanning session?')) {
        return;
      }

      btnCancelScan.disabled = true;
      btnCancelScan.innerHTML = '<i class="fa-solid fa-spinner fa-spin me-2"></i> Terminating...';

      try {
        const resp = await fetch(`/api/scans/${scanId}/cancel`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCsrfToken()
          }
        });
        const data = await resp.json();
        console.log('Cancellation response:', data);
      } catch (err) {
        console.error('Cancellation error:', err);
      }
    });
  }

  // Status Poll Loop
  async function checkScanStatus() {
    try {
      const resp = await fetch(`/api/scans/${scanId}/status`);
      if (!resp.ok) {
        throw new Error(`HTTP error: ${resp.status}`);
      }

      const scanData = await resp.json();

      // Update Timer if duration exists
      if (scanData.duration && !timerInterval) {
        secondsCounter = Math.floor(scanData.duration);
        const mins = String(Math.floor(secondsCounter / 60)).padStart(2, '0');
        const secs = String(secondsCounter % 60).padStart(2, '0');
        if (elapsedTimer) elapsedTimer.textContent = `${mins}:${secs}`;
      }

      if (scanData.status === 'running') {
        // Active Running State
        if (statusBadge) {
          statusBadge.className = 'badge bg-primary-soft text-primary border border-primary-subtle px-3 py-2';
          statusBadge.innerHTML = '<i class="fa-solid fa-spinner fa-spin me-1"></i> Running';
        }

        if (progressBar) {
          progressBar.style.width = '65%';
          progressBar.className = 'progress-bar progress-bar-striped progress-bar-animated bg-primary';
        }

        if (stageNmapExec) {
          stageNmapExec.innerHTML = `
            <div>
              <i class="fa-solid fa-spinner fa-spin text-primary me-3"></i>
              <span class="fw-medium">Nmap Execution & Output Capture</span>
            </div>
            <span class="badge bg-primary-soft text-primary">In Progress</span>
          `;
        }

      } else if (scanData.status === 'completed') {
        // Completed State
        clearInterval(pollInterval);
        clearInterval(timerInterval);

        if (statusBadge) {
          statusBadge.className = 'badge bg-success-soft text-success border border-success-subtle px-3 py-2';
          statusBadge.innerHTML = '<i class="fa-solid fa-circle-check me-1"></i> Completed';
        }

        if (progressBar) {
          progressBar.style.width = '100%';
          progressBar.className = 'progress-bar bg-success';
        }

        if (stageNmapExec) {
          stageNmapExec.innerHTML = `
            <div>
              <i class="fa-solid fa-circle-check text-success me-3"></i>
              <span class="fw-medium">Nmap Execution & Output Capture</span>
            </div>
            <span class="badge bg-success-soft text-success">Finished</span>
          `;
        }

        if (stageXmlSave) {
          stageXmlSave.className = 'list-group-item bg-transparent d-flex justify-content-between align-items-center py-2 px-0';
          stageXmlSave.innerHTML = `
            <div>
              <i class="fa-solid fa-circle-check text-success me-3"></i>
              <span class="fw-medium">XML Output Storage</span>
            </div>
            <span class="badge bg-success-soft text-success">Stored</span>
          `;
        }

        if (stageResults) {
          stageResults.className = 'list-group-item bg-transparent d-flex justify-content-between align-items-center py-2 px-0';
          stageResults.innerHTML = `
            <div>
              <i class="fa-solid fa-circle-check text-success me-3"></i>
              <span class="fw-medium">Scan Outcome Available</span>
            </div>
            <span class="badge bg-success-soft text-success">Ready</span>
          `;
        }

        if (btnCancelScan) {
          btnCancelScan.style.display = 'none';
        }

        // Auto-redirect to results page
        setTimeout(() => {
          window.location.href = scanData.redirect_results_url || `/scan/results/${scanId}`;
        }, 1200);

      } else {
        // Failed / Timeout / Cancelled State
        clearInterval(pollInterval);
        clearInterval(timerInterval);

        const statusLabel = scanData.status === 'timeout' ? 'Timeout' : (scanData.status === 'cancelled' ? 'Cancelled' : 'Failed');
        const badgeColor = scanData.status === 'timeout' ? 'warning' : 'danger';

        if (statusBadge) {
          statusBadge.className = `badge bg-${badgeColor}-soft text-${badgeColor} border border-${badgeColor}-subtle px-3 py-2`;
          statusBadge.innerHTML = `<i class="fa-solid fa-circle-xmark me-1"></i> ${statusLabel}`;
        }

        if (progressBar) {
          progressBar.style.width = '100%';
          progressBar.className = `progress-bar bg-${badgeColor}`;
        }

        if (errorNotice && errorNoticeText) {
          errorNotice.classList.remove('d-none');
          errorNotice.className = `alert alert-${badgeColor} mb-4 d-flex gap-3 align-items-center py-3 px-3`;
          errorNoticeText.textContent = scanData.error_message || `Scan execution terminated with status: ${statusLabel}.`;
        }

        if (btnCancelScan) {
          btnCancelScan.className = 'btn btn-outline-secondary btn-sm px-4';
          btnCancelScan.innerHTML = '<i class="fa-solid fa-clock-rotate-left me-2"></i> View Scan History';
          btnCancelScan.onclick = () => { window.location.href = '/scan/history'; };
        }
      }

    } catch (err) {
      console.error('Polling status error:', err);
    }
  }

  // Start polling
  startElapsedTimer();
  checkScanStatus();
  pollInterval = setInterval(checkScanStatus, 1500);
});
