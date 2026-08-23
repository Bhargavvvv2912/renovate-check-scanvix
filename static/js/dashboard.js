/**
 * NMAP Security Suite — Dashboard Controller & Interactivity
 * Phase 3: Modern Light SaaS Dashboard
 */

document.addEventListener('DOMContentLoaded', function () {
  'use strict';

  // 1. Initialize KPI Sparklines
  const sparklineConfigs = [
    { id: 'sparklineTotalScans', data: [12, 14, 18, 16, 20, 22, 24], color: '#2563EB' },
    { id: 'sparklineHostsScanned', data: [90, 110, 125, 120, 140, 148, 156], color: '#0284C7' },
    { id: 'sparklineOpenPorts', data: [280, 310, 350, 380, 400, 415, 431], color: '#EA580C' },
    { id: 'sparklineServicesDetected', data: [180, 210, 230, 250, 265, 278, 289], color: '#16A34A' },
    { id: 'sparklineSecurityFindings', data: [45, 42, 38, 40, 36, 34, 32], color: '#DC2626' },
    { id: 'sparklineSuccessRate', data: [88, 90, 91, 92, 94, 95, 96], color: '#2563EB' }
  ];

  if (window.DashboardCharts) {
    sparklineConfigs.forEach(cfg => {
      window.DashboardCharts.initSparkline(cfg.id, cfg.data, cfg.color);
    });

    // 2. Initialize Main Charts with Embedded or Default Data
    const serverData = window.INITIAL_DASHBOARD_DATA || {};

    const sevData = serverData.findings_severity || { high: 0, medium: 0, low: 0, info: 0, total: 0 };
    window.DashboardCharts.initFindingsSeverityChart('chartFindingsSeverity', sevData);

    const openPorts = serverData.open_ports_by_service || {};
    const portValues = [
      openPorts.http || 0,
      openPorts.ssh || 0,
      openPorts.https || 0,
      openPorts.dns || 0,
      openPorts.ftp || 0,
      openPorts.others || 0
    ];
    window.DashboardCharts.initOpenPortsChart('chartOpenPorts', portValues);

    const activityData = serverData.scan_activity || {
      labels: ['No Scans'],
      data: [0]
    };
    window.DashboardCharts.initScanActivityChart('chartScanActivity', activityData);
  }

  // 3. Sidebar Toggle for Mobile / Small Screens
  const sidebarToggleBtn = document.getElementById('sidebarToggleBtn');
  const sidebar = document.querySelector('.sidebar');

  if (sidebarToggleBtn && sidebar) {
    sidebarToggleBtn.addEventListener('click', function (e) {
      e.stopPropagation();
      sidebar.classList.toggle('show');
    });

    document.addEventListener('click', function (e) {
      if (window.innerWidth <= 992 && !sidebar.contains(e.target) && !sidebarToggleBtn.contains(e.target)) {
        sidebar.classList.remove('show');
      }
    });
  }

  // 4. Keyboard Shortcut for Search ('/')
  const globalSearchInput = document.getElementById('globalSearchInput');
  document.addEventListener('keydown', function (e) {
    if (e.key === '/' && document.activeElement !== globalSearchInput && !['input', 'textarea', 'select'].includes(document.activeElement.tagName.toLowerCase())) {
      e.preventDefault();
      if (globalSearchInput) {
        globalSearchInput.focus();
        globalSearchInput.select();
      }
    }
  });

  // 5. Time Filter Dropdown Interactions
  const timeFilters = document.querySelectorAll('.select-time-filter');
  timeFilters.forEach(select => {
    select.addEventListener('change', function () {
      const period = this.value;
      // In production, this can trigger dynamic chart dataset updates via fetch('/api/dashboard/stats?period=' + period)
      console.log(`Filtering dashboard charts for period: ${period}`);
    });
  });
});
