/**
 * NMAP Security Suite — New Scan & Profile Controller
 * Phase 5: Safe Nmap Execution & Predefined Scan Profiles
 */

document.addEventListener('DOMContentLoaded', function () {
  'use strict';

  const targetInput = document.getElementById('targetInput');
  const btnValidateTarget = document.getElementById('btnValidateTarget');
  const btnStartScan = document.getElementById('btnStartScan');
  const validationStatusBadge = document.getElementById('validationStatusBadge');
  const validationFeedback = document.getElementById('validationFeedback');
  const scanForm = document.getElementById('scanConfigForm');
  const csrfTokenInput = document.querySelector('input[name="csrf_token"]');
  const quickTargetPills = document.querySelectorAll('.quick-target-pill');
  const scanProfileSelect = document.getElementById('scanProfileSelect');
  const profileDescText = document.getElementById('profileDescText');
  const profileTypeText = document.getElementById('profileTypeText');
  const profileDurationText = document.getElementById('profileDurationText');

  let currentValidationState = {
    valid: false,
    authorized: false,
    target: '',
    type: null
  };

  // Predefined profile client metadata
  const profileMetadata = {
    "host_discovery": {
      "name": "Host Discovery",
      "description": "Determine whether the target host is reachable on the local network without performing port scans.",
      "scan_type": "ICMP & ARP Ping Sweep",
      "estimated_duration": "~5-15s"
    },
    "basic_port_scan": {
      "name": "Basic Port Scan",
      "description": "Rapidly scan the top 100 most common TCP ports for open listening services.",
      "scan_type": "Fast TCP Port Scan",
      "estimated_duration": "~10-30s"
    },
    "service_enumeration": {
      "name": "Service Enumeration",
      "description": "Probe open TCP ports to determine service names and software version details.",
      "scan_type": "TCP Service & Version Probe",
      "estimated_duration": "~30-60s"
    },
    "service_default_nse": {
      "name": "Service + Default NSE",
      "description": "Perform service version detection combined with Nmap's default safe script suite.",
      "scan_type": "Service + Safe NSE Analysis",
      "estimated_duration": "~45-90s"
    },
    "http_enumeration": {
      "name": "HTTP Enumeration",
      "description": "Targeted inspection of web servers on ports 80 and 443 (title grab, headers, and methods).",
      "scan_type": "Targeted Web Service Inspection",
      "estimated_duration": "~20-45s"
    },
    "ssh_enumeration": {
      "name": "SSH Enumeration",
      "description": "Targeted inspection of SSH servers on port 22 (supported ciphers, key exchange algorithms, and host keys).",
      "scan_type": "Targeted SSH Protocol Inspection",
      "estimated_duration": "~15-30s"
    },
    "comprehensive_lab_scan": {
      "name": "Comprehensive Lab Scan",
      "description": "Full TCP assessment across all 65,535 ports with service version detection in an isolated lab.",
      "scan_type": "Full TCP Port & Service Assessment",
      "estimated_duration": "~60-180s"
    }
  };

  function getCsrfToken() {
    return csrfTokenInput ? csrfTokenInput.value : '';
  }

  // Update profile description box
  function updateProfileDetails() {
    if (!scanProfileSelect) return;
    const selectedKey = scanProfileSelect.value;
    const meta = profileMetadata[selectedKey];
    if (meta) {
      if (profileDescText) profileDescText.textContent = meta.description;
      if (profileTypeText) profileTypeText.textContent = meta.scan_type;
      if (profileDurationText) profileDurationText.textContent = meta.estimated_duration;
    }
  }

  if (scanProfileSelect) {
    scanProfileSelect.addEventListener('change', updateProfileDetails);
    updateProfileDetails();
  }

  // Quick target pill click handler
  if (quickTargetPills) {
    quickTargetPills.forEach(pill => {
      pill.addEventListener('click', function () {
        const selectedTarget = this.getAttribute('data-target');
        if (selectedTarget && targetInput) {
          targetInput.value = selectedTarget;
          validateCurrentTarget();
        }
      });
    });
  }

  // Target input editing
  if (targetInput) {
    targetInput.addEventListener('input', function () {
      if (currentValidationState.valid) {
        currentValidationState = { valid: false, authorized: false, target: '', type: null };
        updateValidationUI(null);
      }
    });

    targetInput.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') {
        e.preventDefault();
        validateCurrentTarget();
      }
    });
  }

  // Validate button click
  if (btnValidateTarget) {
    btnValidateTarget.addEventListener('click', function (e) {
      e.preventDefault();
      validateCurrentTarget();
    });
  }

  // Validate target against API
  async function validateCurrentTarget() {
    const rawTarget = targetInput ? targetInput.value.trim() : '';

    if (!rawTarget) {
      updateValidationUI({
        valid: false,
        authorized: false,
        message: 'Please enter a target address or hostname.'
      });
      return;
    }

    if (validationStatusBadge) {
      validationStatusBadge.className = 'badge bg-primary-soft text-primary border border-primary-subtle';
      validationStatusBadge.innerHTML = '<i class="fa-solid fa-spinner fa-spin me-1"></i> Validating...';
    }

    if (btnValidateTarget) {
      btnValidateTarget.disabled = true;
      btnValidateTarget.innerHTML = '<i class="fa-solid fa-spinner fa-spin me-1"></i> Checking...';
    }

    try {
      const response = await fetch('/api/validate-target', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': getCsrfToken()
        },
        body: JSON.stringify({ target: rawTarget })
      });

      if (!response.ok) {
        throw new Error(`Server responded with status ${response.status}`);
      }

      const result = await response.json();
      currentValidationState = {
        valid: Boolean(result.valid),
        authorized: Boolean(result.authorized),
        target: result.target || rawTarget,
        type: result.type || 'unknown'
      };

      updateValidationUI(result);

    } catch (err) {
      console.error('Validation request error:', err);
      updateValidationUI({
        valid: false,
        authorized: false,
        message: 'Unable to communicate with validation service. Please check network connection.'
      });
    } finally {
      if (btnValidateTarget) {
        btnValidateTarget.disabled = false;
        btnValidateTarget.innerHTML = '<i class="fa-solid fa-shield-check me-1"></i> Validate Target';
      }
    }
  }

  function updateValidationUI(result) {
    if (!validationFeedback || !validationStatusBadge) return;

    if (!result) {
      validationStatusBadge.className = 'badge bg-light text-secondary border';
      validationStatusBadge.textContent = 'Not Validated';
      validationFeedback.innerHTML = '';
      if (btnStartScan) btnStartScan.disabled = true;
      return;
    }

    if (result.valid && result.authorized) {
      let badgeHtml = '<i class="fa-solid fa-circle-check me-1"></i> Authorized Lab Target';
      let titleHtml = '✓ Target Validated & Authorized';
      
      if (result.type === 'PUBLIC') {
        badgeHtml = '<i class="fa-solid fa-circle-check me-1"></i> Authorized Public Target';
        titleHtml = '✓ Public Target Authorized';
      }
      
      validationStatusBadge.className = 'badge bg-success-soft text-success border border-success-subtle';
      validationStatusBadge.innerHTML = badgeHtml;

      validationFeedback.innerHTML = `
        <div class="card p-3 border-success border-1 bg-success-soft rounded-3">
          <div class="d-flex align-items-center justify-content-between mb-2">
            <div class="d-flex align-items-center gap-2">
              <i class="fa-solid fa-circle-check text-success fs-5"></i>
              <strong class="text-success fs-7">${titleHtml}</strong>
            </div>
            <span class="badge bg-light text-dark font-monospace text-uppercase">${result.type || 'IP'}</span>
          </div>
          <div class="row g-2 fs-8 text-secondary mt-1">
            <div class="col-sm-6">
              <span class="d-block text-muted fs-9">Target:</span>
              <code class="text-dark fw-bold fs-7">${result.target}</code>
            </div>
            <div class="col-sm-6">
              <span class="d-block text-muted fs-9">Status:</span>
              <span class="text-success fw-semibold">Ready for scanning</span>
            </div>
          </div>
        </div>
      `;

      if (btnStartScan) {
        btnStartScan.disabled = false;
      }

    } else if (result.valid && !result.authorized) {
      validationStatusBadge.className = 'badge bg-warning-soft text-warning border border-warning-subtle';
      validationStatusBadge.innerHTML = '<i class="fa-solid fa-triangle-exclamation me-1"></i> Boundary Rejection';

      let innerContent = `
        <div class="alert alert-warning mb-0 p-3 rounded-3 d-flex gap-3 align-items-center">
          <i class="fa-solid fa-ban text-warning fs-4"></i>
          <div>
            <strong class="d-block text-dark fs-8">Target Boundary Rejection</strong>
            <span class="fs-8 text-secondary">${result.message || 'Target is outside the configured authorized laboratory boundary.'}</span>
          </div>
        </div>
      `;

      if (result.type === 'PUBLIC') {
        innerContent = `
          <div class="alert alert-warning mb-0 p-3 rounded-3 d-flex flex-column gap-2">
            <div class="d-flex align-items-center gap-2">
              <i class="fa-solid fa-triangle-exclamation text-warning fs-4"></i>
              <div>
                <strong class="d-block text-dark fs-8">Public IPv4</strong>
                <span class="fs-8 text-secondary fw-bold text-dark">⚠ Target requires explicit authorization</span>
              </div>
            </div>
            <div class="mt-2 text-dark fs-8">
              <strong>⚠ Public Target</strong><br>
              This application can scan public targets only when you own the target or have explicit authorization to perform security testing against it.
            </div>
            <div class="mt-2">
              <a href="/authorized-targets" class="btn btn-sm btn-outline-warning text-dark"><i class="fa-solid fa-key"></i> Request/Configure Authorization</a>
            </div>
          </div>
        `;
      }

      validationFeedback.innerHTML = innerContent;

      if (btnStartScan) {
        btnStartScan.disabled = true;
      }

    } else {
      validationStatusBadge.className = 'badge bg-danger-soft text-danger border border-danger-subtle';
      validationStatusBadge.innerHTML = '<i class="fa-solid fa-circle-xmark me-1"></i> Invalid Target';

      validationFeedback.innerHTML = `
        <div class="alert alert-danger mb-0 p-3 rounded-3 d-flex gap-3 align-items-center">
          <i class="fa-solid fa-circle-xmark text-danger fs-4"></i>
          <div>
            <strong class="d-block text-danger fs-8">Validation Failed</strong>
            <span class="fs-8 text-secondary">${result.message || 'Invalid target format.'}</span>
          </div>
        </div>
      `;

      if (btnStartScan) {
        btnStartScan.disabled = true;
      }
    }
  }

  // Handle Form Submission -> Initiate Scan via API
  if (scanForm) {
    scanForm.addEventListener('submit', async function (e) {
      e.preventDefault();

      if (!currentValidationState.valid || !currentValidationState.authorized) {
        updateValidationUI({
          valid: false,
          authorized: false,
          message: 'Please validate an authorized laboratory target first.'
        });
        return;
      }

      const selectedProfile = scanProfileSelect ? scanProfileSelect.value : 'service_default_nse';
      const target = currentValidationState.target;

      if (btnStartScan) {
        btnStartScan.disabled = true;
        btnStartScan.innerHTML = '<i class="fa-solid fa-spinner fa-spin me-2"></i> Initializing Scan...';
      }

      try {
        const response = await fetch('/api/scans', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCsrfToken()
          },
          body: JSON.stringify({
            target: target,
            profile: selectedProfile
          })
        });

        const data = await response.json();

        if (response.ok && data.success) {
          // Redirect immediately to scan progress page
          window.location.href = data.redirect_url;
        } else {
          // Display error message
          alert(data.message || 'Failed to initialize scan session.');
          if (btnStartScan) {
            btnStartScan.disabled = false;
            btnStartScan.innerHTML = '<i class="fa-solid fa-play me-2"></i> Start Scan';
          }
        }
      } catch (err) {
        console.error('Scan launch error:', err);
        alert('An unexpected network error occurred while starting the scan.');
        if (btnStartScan) {
          btnStartScan.disabled = false;
          btnStartScan.innerHTML = '<i class="fa-solid fa-play me-2"></i> Start Scan';
        }
      }
    });
  }
});
