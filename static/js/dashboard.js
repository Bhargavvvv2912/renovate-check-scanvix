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

  // 3. Sidebar Toggle for Desktop and Mobile
  const sidebarToggleBtn = document.getElementById('sidebarToggleBtn');
  const sidebar = document.getElementById('appSidebar');

  if (sidebarToggleBtn && sidebar) {
    sidebarToggleBtn.addEventListener('click', function (e) {
      e.stopPropagation();
      if (window.innerWidth <= 992) {
        sidebar.classList.toggle('show');
      } else {
        const isCollapsed = sidebar.classList.toggle('collapsed');
        localStorage.setItem('sidebar-collapsed', isCollapsed);
      }
    });

    document.addEventListener('click', function (e) {
      if (window.innerWidth <= 992 && !sidebar.contains(e.target) && !sidebarToggleBtn.contains(e.target)) {
        sidebar.classList.remove('show');
      }
    });
  }

  // Highlight active sidebar link based on current path (supporting nested routes and custom exported-reports path)
  function highlightActiveSidebarLink() {
    const pathname = window.location.pathname;
    const links = document.querySelectorAll('.sidebar-nav-link');
    links.forEach(link => {
      const hrefAttr = link.getAttribute('href');
      if (!hrefAttr) return;

      let linkPath = '';
      try {
        linkPath = new URL(hrefAttr, window.location.origin).pathname;
      } catch (err) {
        linkPath = hrefAttr;
      }

      let isActive = false;
      if (linkPath === '/' || linkPath === '/dashboard') {
        isActive = (pathname === '/' || pathname === '/dashboard');
      } else if (linkPath === '/exported-reports') {
        isActive = (pathname === '/exported-reports');
      } else if (linkPath === '/reports') {
        isActive = (pathname === '/reports' || (pathname.startsWith('/report/') && !pathname.startsWith('/report/exported')));
      } else if (linkPath === '/scan/history') {
        // Exclude results/progress paths from history highlight
        isActive = (pathname === '/scan/history' || pathname === '/history');
      } else if (linkPath && linkPath !== '#') {
        isActive = pathname.startsWith(linkPath);
      }

      if (isActive) {
        link.classList.add('active');
        link.setAttribute('aria-current', 'page');
      } else {
        link.classList.remove('active');
        link.removeAttribute('aria-current');
      }
    });
  }
  
  highlightActiveSidebarLink();
  window.addEventListener('popstate', highlightActiveSidebarLink);

  // Preserve sidebar scroll position
  const menuWrapper = document.querySelector('.sidebar-menu-wrapper');
  if (menuWrapper) {
    const savedScrollTop = sessionStorage.getItem('sidebar-scroll-top');
    if (savedScrollTop !== null) {
      menuWrapper.scrollTop = parseInt(savedScrollTop, 10);
    }
    menuWrapper.addEventListener('scroll', function () {
      sessionStorage.setItem('sidebar-scroll-top', menuWrapper.scrollTop);
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
      console.log(`Filtering dashboard charts for period: ${period}`);
    });
  });
});
