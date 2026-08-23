/**
 * NMAP Security Suite — Chart.js Visualizations Engine
 * Phase 3: Modern Light SaaS Dashboard Charts
 */

(function () {
  'use strict';

  // Global Chart.js defaults for Light SaaS aesthetic
  if (window.Chart) {
    Chart.defaults.font.family = "'Inter', system-ui, -apple-system, sans-serif";
    Chart.defaults.font.size = 11;
    Chart.defaults.color = '#64748B';
    Chart.defaults.plugins.tooltip.backgroundColor = '#0F172A';
    Chart.defaults.plugins.tooltip.titleColor = '#FFFFFF';
    Chart.defaults.plugins.tooltip.bodyColor = '#F8FAFC';
    Chart.defaults.plugins.tooltip.padding = 10;
    Chart.defaults.plugins.tooltip.cornerRadius = 8;
    Chart.defaults.plugins.tooltip.boxPadding = 4;
  }

  // Center Text Plugin for Doughnut Charts
  const doughnutCenterTextPlugin = {
    id: 'doughnutCenterText',
    beforeDraw(chart) {
      if (chart.config.options.elements && chart.config.options.elements.centerText) {
        const { ctx, width, height } = chart;
        const centerConfig = chart.config.options.elements.centerText;
        ctx.save();

        const count = centerConfig.count || '0';
        const label = centerConfig.label || '';

        // Draw main value
        ctx.font = `bold ${centerConfig.countFontSize || 22}px Inter, sans-serif`;
        ctx.fillStyle = centerConfig.countColor || '#0F172A';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(count, width / 2, height / 2 - 8);

        // Draw label text
        ctx.font = `500 ${centerConfig.labelFontSize || 10}px Inter, sans-serif`;
        ctx.fillStyle = centerConfig.labelColor || '#64748B';
        ctx.fillText(label, width / 2, height / 2 + 12);

        ctx.restore();
      }
    }
  };

  /**
   * Initialize Sparkline for KPI Card
   */
  function initSparkline(canvasId, dataPoints, strokeColor) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return null;

    const ctx = canvas.getContext('2d');
    return new Chart(ctx, {
      type: 'line',
      data: {
        labels: dataPoints.map((_, i) => i),
        datasets: [{
          data: dataPoints,
          borderColor: strokeColor,
          borderWidth: 2,
          fill: false,
          tension: 0.45,
          pointRadius: 0,
          pointHoverRadius: 3
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            enabled: true,
            displayColors: false,
            callbacks: {
              title: () => '',
              label: (ctx) => `Value: ${ctx.parsed.y}`
            }
          }
        },
        scales: {
          x: { display: false },
          y: { display: false }
        }
      }
    });
  }

  /**
   * Initialize Findings by Severity Doughnut Chart
   */
  function initFindingsSeverityChart(canvasId, data) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return null;

    const ctx = canvas.getContext('2d');
    const chartData = data || { high: 7, medium: 12, low: 8, info: 5, total: 32 };

    return new Chart(ctx, {
      type: 'doughnut',
      plugins: [doughnutCenterTextPlugin],
      data: {
        labels: ['High', 'Medium', 'Low', 'Info'],
        datasets: [{
          data: [chartData.high, chartData.medium, chartData.low, chartData.info],
          backgroundColor: ['#EF4444', '#F59E0B', '#EAB308', '#3B82F6'],
          hoverBackgroundColor: ['#DC2626', '#D97706', '#CA8A04', '#2563EB'],
          borderWidth: 0,
          spacing: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '74%',
        elements: {
          centerText: {
            count: String(chartData.total || 0),
            label: 'Total Findings',
            countFontSize: 20,
            labelFontSize: 9.5
          }
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: function (ctx) {
                const val = ctx.parsed;
                const total = chartData.total || 0;
                const pct = total > 0 ? ((val / total) * 100).toFixed(1) : '0.0';
                return ` ${ctx.label}: ${val} (${pct}%)`;
              }
            }
          }
        }
      }
    });
  }

  /**
   * Initialize Open Ports by Service Doughnut Chart
   */
  function initOpenPortsChart(canvasId, data) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return null;

    const ctx = canvas.getContext('2d');
    const portValues = data || [0, 0, 0, 0, 0, 0];

    return new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['HTTP', 'SSH', 'HTTPS', 'DNS', 'FTP', 'Others'],
        datasets: [{
          data: portValues,
          backgroundColor: ['#2563EB', '#60A5FA', '#06B6D4', '#10B981', '#F97316', '#94A3B8'],
          hoverBackgroundColor: ['#1D4ED8', '#3B82F6', '#0891B2', '#059669', '#EA580C', '#64748B'],
          borderWidth: 0,
          spacing: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '70%',
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: function (ctx) {
                const total = portValues.reduce((a, b) => a + b, 0);
                const val = ctx.parsed;
                const pct = total > 0 ? ((val / total) * 100).toFixed(1) : '0.0';
                return ` ${ctx.label}: ${val} (${pct}%)`;
              }
            }
          }
        }
      }
    });
  }

  /**
   * Initialize Scan Activity Line Chart
   */
  function initScanActivityChart(canvasId, activityData) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return null;

    const ctx = canvas.getContext('2d');
    
    // Create gradient fill
    const gradient = ctx.createLinearGradient(0, 0, 0, 160);
    gradient.addColorStop(0, 'rgba(37, 99, 235, 0.15)');
    gradient.addColorStop(1, 'rgba(37, 99, 235, 0.0)');

    const labels = (activityData && activityData.labels) || ['May 06', 'May 13', 'May 20', 'May 27', 'Jun 03', 'Jun 10'];
    const values = (activityData && activityData.data) || [4, 9, 7, 10, 18, 12, 10, 12, 18, 20, 24];

    return new Chart(ctx, {
      type: 'line',
      data: {
        labels: labels,
        datasets: [{
          label: 'Scans Run',
          data: values,
          borderColor: '#2563EB',
          borderWidth: 2.2,
          backgroundColor: gradient,
          fill: true,
          tension: 0.35,
          pointBackgroundColor: '#2563EB',
          pointBorderColor: '#FFFFFF',
          pointBorderWidth: 2,
          pointRadius: 3.5,
          pointHoverRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
          intersect: false,
          mode: 'index'
        },
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: {
              color: '#94A3B8',
              font: { size: 10 }
            }
          },
          y: {
            beginAtZero: true,
            max: 25,
            ticks: {
              stepSize: 5,
              color: '#94A3B8',
              font: { size: 10 }
            },
            grid: {
              color: '#F1F5F9',
              borderDash: [4, 4]
            }
          }
        }
      }
    });
  }

  // Export functions to window
  window.DashboardCharts = {
    initSparkline,
    initFindingsSeverityChart,
    initOpenPortsChart,
    initScanActivityChart
  };
})();
