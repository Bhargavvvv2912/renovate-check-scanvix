/**
 * ScanVix Landing Page — Interactive 3D Cyber Engine
 *
 * Implements:
 * 1. Multi-tiered glossy 3D cyber platform with metallic bevels, LED slots & reflections
 * 2. Floating holographic radar HUD with rotating amber/orange sweep beam
 * 3. Dynamic target blips that flare with ripple rings when swept
 * 4. 3D network particle cloud and connecting graph with moving data packets
 * 5. Full orbit camera controls (drag to rotate, wheel to zoom, touch support)
 * 6. Floating interactive command windows with 3D parallax, hover effects & focus mode
 * 7. Interactive Port exploration & Workflow pipeline modals
 * 8. Zero external dependencies required (Self-contained high-performance 3D engine)
 */

(function () {
  'use strict';

  var canvas = document.getElementById('scanvix3DCanvas');
  if (!canvas) return;

  var container = canvas.parentElement;
  var ctx = canvas.getContext('2d');
  if (!ctx) return;

  // --- State Variables ---
  var animFrameId = null;
  var isDisposed = false;
  var width = 0, height = 0;
  var lastTime = performance.now();

  // Camera Orbit State
  var cameraState = {
    yaw: 0.35,          // Horizontal rotation (radians)
    pitch: 0.52,        // Vertical tilt (radians ~30 deg)
    distance: 1.0,      // Zoom scale
    targetYaw: 0.35,
    targetPitch: 0.52,
    targetDistance: 1.0
  };

  var isDragging = false;
  var prevPointerX = 0, prevPointerY = 0;
  var mouseNorm = { x: 0, y: 0 };

  // Sweep Animation State
  var sweepAngle = 0;
  var SWEEP_SPEED = 1.35; // radians per sec

  // Dynamic Blips Data
  var blips = [
    { r: 70,  a: 0.45, label: 'SSH :22', port: '22', intensity: 0.4 },
    { r: 120, a: 1.30, label: 'HTTP :80', port: '80', intensity: 0.4 },
    { r: 165, a: 2.15, label: 'HTTPS :443', port: '443', intensity: 0.4 },
    { r: 195, a: 3.50, label: 'MySQL :3306', port: '3306', intensity: 0.4 },
    { r: 105, a: 4.25, label: 'DNS :53', port: '53', intensity: 0.4 },
    { r: 210, a: 5.10, label: 'PostgreSQL :5432', port: '5432', intensity: 0.4 },
    { r: 150, a: 5.90, label: 'RDP :3389', port: '3389', intensity: 0.4 }
  ];

  // Floating Network Nodes
  var networkNodes = [];
  var NODE_COUNT = 20;

  function initNetworkNodes() {
    networkNodes = [];
    for (var i = 0; i < NODE_COUNT; i++) {
      var angle = Math.random() * Math.PI * 2;
      var dist = 160 + Math.random() * 180;
      networkNodes.push({
        x: Math.cos(angle) * dist,
        y: (Math.random() - 0.5) * 90 - 40,
        z: Math.sin(angle) * dist,
        baseY: (Math.random() - 0.5) * 90 - 40,
        speed: 0.5 + Math.random() * 0.8,
        phase: Math.random() * Math.PI * 2,
        color: i % 3 === 0 ? '#00e5ff' : (i % 3 === 1 ? '#3b82f6' : '#f59e0b')
      });
    }
  }

  // -------------------------------------------------------------
  // 1. Canvas Resize & Initialization
  // -------------------------------------------------------------
  function handleResize() {
    if (isDisposed || !container || !canvas) return;
    width = container.clientWidth || 800;
    height = container.clientHeight || 640;
    var dpr = window.devicePixelRatio || 1;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    ctx.scale(dpr, dpr);
  }

  // -------------------------------------------------------------
  // 2. 3D Projection Helpers
  // -------------------------------------------------------------
  function project3D(x, y, z, cx, cy, yaw, pitch, scale) {
    // 1. Rotate Y (Yaw)
    var cosY = Math.cos(yaw);
    var sinY = Math.sin(yaw);
    var x1 = x * cosY - z * sinY;
    var z1 = x * sinY + z * cosY;

    // 2. Rotate X (Pitch)
    var cosX = Math.cos(pitch);
    var sinX = Math.sin(pitch);
    var y2 = y * cosX - z1 * sinX;
    var z2 = y * sinX + z1 * cosX;

    // 3. Perspective Project
    var fov = 650;
    var depth = (fov / (fov + z2 * 0.75)) * scale;

    return {
      x: cx + x1 * depth,
      y: cy + y2 * depth,
      depth: depth,
      z: z2
    };
  }

  // -------------------------------------------------------------
  // 3. Main Render Loop
  // -------------------------------------------------------------
  function render(time) {
    if (isDisposed) return;
    animFrameId = requestAnimationFrame(render);

    var delta = (time - lastTime) / 1000;
    lastTime = time;
    if (delta > 0.1) delta = 0.1;

    // Smooth Camera Damping
    cameraState.yaw += (cameraState.targetYaw - cameraState.yaw) * 0.08;
    cameraState.pitch += (cameraState.targetPitch - cameraState.pitch) * 0.08;
    cameraState.distance += (cameraState.targetDistance - cameraState.distance) * 0.08;

    // Idle Mouse Parallax
    if (!isDragging) {
      cameraState.targetYaw += mouseNorm.x * 0.0003;
    }

    // Sweep Rotation
    sweepAngle += delta * SWEEP_SPEED;

    // Clear Canvas
    ctx.clearRect(0, 0, width, height);

    var cx = width * 0.52;
    var cy = height * 0.56;
    var yaw = cameraState.yaw;
    var pitch = cameraState.pitch;
    var scale = cameraState.distance;

    // -------------------------------------------------------------
    // Draw 3D Multi-Tiered Cyber Platform
    // -------------------------------------------------------------
    drawPlatformTiers(cx, cy, yaw, pitch, scale);

    // -------------------------------------------------------------
    // Draw 3D Holographic Radar HUD
    // -------------------------------------------------------------
    drawRadarHUD(cx, cy, yaw, pitch, scale);

    // -------------------------------------------------------------
    // Draw Target Blips with Ripple Flares
    // -------------------------------------------------------------
    drawTargetBlips(cx, cy, yaw, pitch, scale, delta);

    // -------------------------------------------------------------
    // Draw Floating Network Nodes & Data Connections
    // -------------------------------------------------------------
    drawNetworkGraph(cx, cy, yaw, pitch, scale, time * 0.001);
  }

  // -------------------------------------------------------------
  // 4. Multi-Tiered Cyber Platform Rendering
  // -------------------------------------------------------------
  function drawPlatformTiers(cx, cy, yaw, pitch, scale) {
    var cosP = Math.cos(pitch);

    // Platform Tier Specs: { radius, yOffset, height, colorTop, colorSide }
    var tiers = [
      { r: 240, y: 70,  h: 24, rimCol: '#1d4ed8', glowCol: 'rgba(56, 189, 248, 0.4)' },
      { r: 190, y: 46,  h: 22, rimCol: '#2563eb', hasBlueSlots: true },
      { r: 140, y: 22,  h: 18, rimCol: '#0284c7', hasAmberSlots: true },
      { r: 95,  y: 4,   h: 12, rimCol: '#38bdf8', isCore: true }
    ];

    tiers.forEach(function (tier) {
      var r = tier.r * scale;
      var y = tier.y * scale;
      var h = tier.h * scale;
      var ry = r * cosP;

      // Tier Side Cylinder
      var sideGrad = ctx.createLinearGradient(cx - r, cy + y, cx + r, cy + y + h);
      sideGrad.addColorStop(0, '#040b17');
      sideGrad.addColorStop(0.3, '#0c1e3d');
      sideGrad.addColorStop(0.7, '#071329');
      sideGrad.addColorStop(1, '#020611');

      ctx.beginPath();
      ctx.ellipse(cx, cy + y, r, ry, 0, 0, Math.PI);
      ctx.lineTo(cx + r, cy + y + h);
      ctx.ellipse(cx, cy + y + h, r, ry, 0, Math.PI, 0, true);
      ctx.lineTo(cx - r, cy + y);
      ctx.closePath();
      ctx.fillStyle = sideGrad;
      ctx.fill();

      // Tier Top Disc
      var topGrad = ctx.createRadialGradient(cx, cy + y, r * 0.1, cx, cy + y, r);
      topGrad.addColorStop(0, '#08162e');
      topGrad.addColorStop(0.7, '#050f21');
      topGrad.addColorStop(1, '#020712');

      ctx.beginPath();
      ctx.ellipse(cx, cy + y, r, ry, 0, 0, Math.PI * 2);
      ctx.fillStyle = topGrad;
      ctx.fill();

      // Glowing Rim Stroke
      ctx.lineWidth = 1.5;
      ctx.strokeStyle = tier.rimCol;
      ctx.stroke();

      // Base tier glow
      if (tier.glowCol) {
        ctx.shadowColor = '#38bdf8';
        ctx.shadowBlur = 18;
        ctx.stroke();
        ctx.shadowBlur = 0;
      }

      // Tier 2: 24 Glowing Blue Light Slots around perimeter
      if (tier.hasBlueSlots) {
        for (var s = 0; s < 24; s++) {
          var slotAngle = yaw + (s / 24) * Math.PI * 2;
          var sx = Math.cos(slotAngle) * (r * 0.96);
          var sz = Math.sin(slotAngle) * (r * 0.96);
          var p = project3D(sx, -tier.y + 4, sz, cx, cy, 0, pitch, scale);

          ctx.fillStyle = s % 2 === 0 ? '#00e5ff' : '#2563eb';
          ctx.beginPath();
          ctx.arc(p.x, p.y, 2.2 * p.depth, 0, Math.PI * 2);
          ctx.fill();
        }
      }

      // Tier 3: 16 Amber LED indicator notches around perimeter
      if (tier.hasAmberSlots) {
        for (var a = 0; a < 16; a++) {
          var aAngle = yaw + (a / 16) * Math.PI * 2;
          var ax = Math.cos(aAngle) * (r * 0.95);
          var az = Math.sin(aAngle) * (r * 0.95);
          var ap = project3D(ax, -tier.y + 3, az, cx, cy, 0, pitch, scale);

          ctx.fillStyle = '#f59e0b';
          ctx.beginPath();
          ctx.arc(ap.x, ap.y, 2.5 * ap.depth, 0, Math.PI * 2);
          ctx.fill();
        }
      }
    });
  }

  // -------------------------------------------------------------
  // 5. Holographic Radar HUD & Rotating Orange Sweep
  // -------------------------------------------------------------
  function drawRadarHUD(cx, cy, yaw, pitch, scale) {
    var cosP = Math.cos(pitch);
    var radarY = -12 * scale; // Floating above platform top
    var maxRadius = 220 * scale;

    // 1. Concentric Glowing Cyan/Blue Range Rings
    var rings = [50, 100, 150, 200, 220];
    rings.forEach(function (rad, idx) {
      var r = rad * scale;
      var ry = r * cosP;

      ctx.beginPath();
      ctx.ellipse(cx, cy + radarY, r, ry, 0, 0, Math.PI * 2);
      ctx.lineWidth = idx === rings.length - 1 ? 2 : 1;
      ctx.strokeStyle = idx === rings.length - 1 ? 'rgba(56, 189, 248, 0.85)' : 'rgba(30, 64, 175, 0.45)';
      ctx.stroke();

      if (idx === rings.length - 1) {
        ctx.shadowColor = '#38bdf8';
        ctx.shadowBlur = 12;
        ctx.stroke();
        ctx.shadowBlur = 0;
      }
    });

    // 2. Radial Azimuth Lines & Degree Tick Marks
    for (var i = 0; i < 8; i++) {
      var angle = yaw + (i / 8) * Math.PI * 2;
      var rx = Math.cos(angle) * maxRadius;
      var rz = Math.sin(angle) * maxRadius;

      var p1 = project3D(0, 12, 0, cx, cy, 0, pitch, scale);
      var p2 = project3D(rx, 12, rz, cx, cy, 0, pitch, scale);

      ctx.beginPath();
      ctx.moveTo(p1.x, p1.y);
      ctx.lineTo(p2.x, p2.y);
      ctx.lineWidth = 1;
      ctx.strokeStyle = 'rgba(56, 189, 248, 0.25)';
      ctx.stroke();
    }

    // 3. Rotating Amber / Orange Sweep Beam (Sector Wedge)
    var sweepAngleSpan = Math.PI * 0.35; // ~63 deg
    var sweepSegments = 24;

    for (var seg = 0; seg < sweepSegments; seg++) {
      var frac = seg / sweepSegments;
      var segAngle1 = yaw + sweepAngle - frac * sweepAngleSpan;
      var segAngle2 = yaw + sweepAngle - (frac + 1 / sweepSegments) * sweepAngleSpan;

      var alpha = Math.pow(1 - frac, 1.8) * 0.45;
      ctx.fillStyle = 'rgba(249, 115, 22, ' + alpha + ')';

      var pCenter = project3D(0, 12, 0, cx, cy, 0, pitch, scale);
      var pEdge1 = project3D(Math.cos(segAngle1) * maxRadius, 12, Math.sin(segAngle1) * maxRadius, cx, cy, 0, pitch, scale);
      var pEdge2 = project3D(Math.cos(segAngle2) * maxRadius, 12, Math.sin(segAngle2) * maxRadius, cx, cy, 0, pitch, scale);

      ctx.beginPath();
      ctx.moveTo(pCenter.x, pCenter.y);
      ctx.lineTo(pEdge1.x, pEdge1.y);
      ctx.lineTo(pEdge2.x, pEdge2.y);
      ctx.closePath();
      ctx.fill();
    }

    // Leading Bright Orange Ray Line
    var leadAngle = yaw + sweepAngle;
    var pLead = project3D(Math.cos(leadAngle) * maxRadius, 12, Math.sin(leadAngle) * maxRadius, cx, cy, 0, pitch, scale);
    var pCtr = project3D(0, 12, 0, cx, cy, 0, pitch, scale);

    ctx.beginPath();
    ctx.moveTo(pCtr.x, pCtr.y);
    ctx.lineTo(pLead.x, pLead.y);
    ctx.lineWidth = 2.5;
    ctx.strokeStyle = '#ff9900';
    ctx.shadowColor = '#f97316';
    ctx.shadowBlur = 15;
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Orange illumination reflection on the central platform
    var reflGrad = ctx.createRadialGradient(cx, cy + 4, 10, cx + Math.cos(leadAngle) * 60, cy + 4, 120);
    reflGrad.addColorStop(0, 'rgba(249, 115, 22, 0.4)');
    reflGrad.addColorStop(0.5, 'rgba(249, 115, 22, 0.15)');
    reflGrad.addColorStop(1, 'transparent');
    ctx.beginPath();
    ctx.ellipse(cx, cy + 4, 90 * scale, 90 * scale * cosP, 0, 0, Math.PI * 2);
    ctx.fillStyle = reflGrad;
    ctx.fill();
  }

  // -------------------------------------------------------------
  // 6. Dynamic Target Blips with Ripple Waves
  // -------------------------------------------------------------
  function drawTargetBlips(cx, cy, yaw, pitch, scale, delta) {
    var normSweep = (sweepAngle % (Math.PI * 2) + Math.PI * 2) % (Math.PI * 2);

    blips.forEach(function (b) {
      var diff = Math.abs(normSweep - b.a);
      if (diff > Math.PI) diff = Math.PI * 2 - diff;

      // Sweep hit flare
      if (diff < 0.22) {
        b.intensity = 1.0;
      } else {
        b.intensity = Math.max(0.3, b.intensity - delta * 0.85);
      }

      var currentAngle = yaw + b.a;
      var bx = Math.cos(currentAngle) * (b.r * scale);
      var bz = Math.sin(currentAngle) * (b.r * scale);
      var bp = project3D(bx, 10, bz, cx, cy, 0, pitch, scale);

      // Expanding ripple wave when active
      if (b.intensity > 0.4) {
        var rippleRadius = (1.0 - b.intensity) * 20 * bp.depth;
        ctx.beginPath();
        ctx.arc(bp.x, bp.y, 4 * bp.depth + rippleRadius, 0, Math.PI * 2);
        ctx.strokeStyle = 'rgba(249, 115, 22, ' + (b.intensity * 0.6) + ')';
        ctx.lineWidth = 1;
        ctx.stroke();
      }

      // Blip Dot
      ctx.beginPath();
      ctx.arc(bp.x, bp.y, 3.5 * bp.depth, 0, Math.PI * 2);
      ctx.fillStyle = b.intensity > 0.6 ? '#f97316' : '#38bdf8';
      ctx.shadowColor = b.intensity > 0.6 ? '#f97316' : '#38bdf8';
      ctx.shadowBlur = 10 * b.intensity;
      ctx.fill();
      ctx.shadowBlur = 0;
    });
  }

  // -------------------------------------------------------------
  // 7. Floating Network Graph & Traveling Data Packets
  // -------------------------------------------------------------
  function drawNetworkGraph(cx, cy, yaw, pitch, scale, time) {
    if (!networkNodes.length) initNetworkNodes();

    // 1. Update and Project Nodes
    var projectedNodes = [];
    networkNodes.forEach(function (n) {
      n.y = n.baseY + Math.sin(time * n.speed + n.phase) * 14;
      var p = project3D(n.x, n.y, n.z, cx, cy, yaw, pitch, scale);
      projectedNodes.push(p);

      // Node sphere
      ctx.beginPath();
      ctx.arc(p.x, p.y, 2.5 * p.depth, 0, Math.PI * 2);
      ctx.fillStyle = n.color;
      ctx.fill();
    });

    // 2. Draw Connection Lines between close nodes
    ctx.lineWidth = 1;
    for (var a = 0; a < projectedNodes.length; a++) {
      for (var b = a + 1; b < projectedNodes.length; b++) {
        var dx = projectedNodes[a].x - projectedNodes[b].x;
        var dy = projectedNodes[a].y - projectedNodes[b].y;
        var d = Math.sqrt(dx * dx + dy * dy);

        if (d < 110 * scale) {
          var lineAlpha = (1 - d / (110 * scale)) * 0.3;
          ctx.strokeStyle = 'rgba(30, 64, 175, ' + lineAlpha + ')';
          ctx.beginPath();
          ctx.moveTo(projectedNodes[a].x, projectedNodes[a].y);
          ctx.lineTo(projectedNodes[b].x, projectedNodes[b].y);
          ctx.stroke();

          // Traveling Data Packet
          var packetProgress = (time * 0.5 + (a * 7 + b * 13)) % 1.0;
          var px = projectedNodes[a].x + (projectedNodes[b].x - projectedNodes[a].x) * packetProgress;
          var py = projectedNodes[a].y + (projectedNodes[b].y - projectedNodes[a].y) * packetProgress;

          ctx.beginPath();
          ctx.arc(px, py, 1.8, 0, Math.PI * 2);
          ctx.fillStyle = '#00e5ff';
          ctx.fill();
        }
      }
    }
  }

  // -------------------------------------------------------------
  // 8. Orbit & Touch Controls Setup
  // -------------------------------------------------------------
  function setupInteractions() {
    container.addEventListener('mousedown', function (e) {
      if (e.target.closest('.scanvix-cmd-win')) return;
      isDragging = true;
      prevPointerX = e.clientX;
      prevPointerY = e.clientY;
    });

    window.addEventListener('mousemove', function (e) {
      var rect = container.getBoundingClientRect();
      mouseNorm.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      mouseNorm.y = -(((e.clientY - rect.top) / rect.height) * 2 - 1);

      if (!isDragging) return;

      var dx = e.clientX - prevPointerX;
      var dy = e.clientY - prevPointerY;
      prevPointerX = e.clientX;
      prevPointerY = e.clientY;

      cameraState.targetYaw += dx * 0.008;
      cameraState.targetPitch = Math.max(0.2, Math.min(1.2, cameraState.targetPitch + dy * 0.006));
    });

    window.addEventListener('mouseup', function () {
      isDragging = false;
    });

    // Wheel Zoom
    container.addEventListener('wheel', function (e) {
      e.preventDefault();
      var zoomDelta = -e.deltaY * 0.0012;
      cameraState.targetDistance = Math.max(0.7, Math.min(1.4, cameraState.targetDistance + zoomDelta));
    }, { passive: false });

    // Touch Support
    var touchStartX = 0, touchStartY = 0, initialPinch = 0;

    container.addEventListener('touchstart', function (e) {
      if (e.touches.length === 1) {
        isDragging = true;
        touchStartX = e.touches[0].clientX;
        touchStartY = e.touches[0].clientY;
      } else if (e.touches.length === 2) {
        isDragging = false;
        var dx = e.touches[0].clientX - e.touches[1].clientX;
        var dy = e.touches[0].clientY - e.touches[1].clientY;
        initialPinch = Math.sqrt(dx * dx + dy * dy);
      }
    }, { passive: true });

    container.addEventListener('touchmove', function (e) {
      if (e.touches.length === 1 && isDragging) {
        var dx = e.touches[0].clientX - touchStartX;
        var dy = e.touches[0].clientY - touchStartY;
        touchStartX = e.touches[0].clientX;
        touchStartY = e.touches[0].clientY;

        cameraState.targetYaw += dx * 0.008;
        cameraState.targetPitch = Math.max(0.2, Math.min(1.2, cameraState.targetPitch + dy * 0.006));
      } else if (e.touches.length === 2) {
        var ndx = e.touches[0].clientX - e.touches[1].clientX;
        var ndy = e.touches[0].clientY - e.touches[1].clientY;
        var dist = Math.sqrt(ndx * ndx + ndy * ndy);
        var pinchDelta = (dist - initialPinch) * 0.004;
        initialPinch = dist;
        cameraState.targetDistance = Math.max(0.7, Math.min(1.4, cameraState.targetDistance + pinchDelta));
      }
    }, { passive: true });

    container.addEventListener('touchend', function () {
      isDragging = false;
    });

    window.addEventListener('resize', handleResize);
    window.addEventListener('beforeunload', dispose);
  }

  // -------------------------------------------------------------
  // 9. Floating Command Windows Focus Interaction
  // -------------------------------------------------------------
  function setupCommandWindows() {
    var windows = document.querySelectorAll('.scanvix-cmd-win');
    if (!windows.length) return;

    var activeFocused = null;

    windows.forEach(function (win) {
      win.addEventListener('click', function (e) {
        if (e.target.closest('.scanvix-win-close')) {
          e.stopPropagation();
          unfocusAllWindows();
          return;
        }

        if (activeFocused === win) return;

        unfocusAllWindows();
        win.classList.add('is-focused');
        activeFocused = win;

        windows.forEach(function (other) {
          if (other !== win) other.classList.add('is-dimmed');
        });
      });
    });

    container.addEventListener('click', function (e) {
      if (!e.target.closest('.scanvix-cmd-win')) {
        unfocusAllWindows();
      }
    });

    function unfocusAllWindows() {
      windows.forEach(function (w) {
        w.classList.remove('is-focused');
        w.classList.remove('is-dimmed');
      });
      activeFocused = null;
    }
  }

  // -------------------------------------------------------------
  // 10. Interactive Port & Workflow Modals
  // -------------------------------------------------------------
  function setupPortAndWorkflowModals() {
    var modal = document.getElementById('scanvixModal');
    var modalContent = document.getElementById('modalContent');
    var closeBtn = document.getElementById('modalCloseBtn');
    if (!modal || !modalContent) return;

    var PORT_INFO = {
      '22': {
        name: 'SSH (Secure Shell)',
        protocol: 'TCP',
        desc: 'Encrypted remote administrative command execution protocol.',
        security: 'Ensure root login is disabled, use strong Ed25519/RSA keys, disable weak CBC ciphers and legacy diffie-hellman key exchange algorithms.',
        cmd: 'nmap -sV -p 22 --script=ssh2-enum-algos 192.168.1.10'
      },
      '53': {
        name: 'DNS (Domain Name System)',
        protocol: 'TCP / UDP',
        desc: 'Resolves human-readable hostnames into IP addresses across networks.',
        security: 'Verify against open DNS recursion, DNS zone transfers (AXFR), and cache poisoning vulnerabilities.',
        cmd: 'nmap -sU -p 53 --script=dns-recursion,dns-zone-transfer 192.168.1.10'
      },
      '80': {
        name: 'HTTP (Hypertext Transfer Protocol)',
        protocol: 'TCP',
        desc: 'Standard unencrypted web server listener.',
        security: 'Cleartext protocol vulnerable to network sniffing. Must redirect to HTTPS (port 443) with HSTS headers enabled.',
        cmd: 'nmap -sV -p 80 --script=http-title,http-headers 192.168.1.10'
      },
      '443': {
        name: 'HTTPS (HTTP over TLS/SSL)',
        protocol: 'TCP',
        desc: 'Encrypted web transport securing web applications and REST APIs.',
        security: 'Enforce TLS 1.3/1.2, verify SSL certificate expiration and SANs, disable legacy SSLv3/TLS 1.0 protocols.',
        cmd: 'nmap -sV -p 443 --script=ssl-cert,ssl-enum-ciphers 192.168.1.10'
      },
      '3306': {
        name: 'MySQL Database',
        protocol: 'TCP',
        desc: 'Relational database management service listener.',
        security: 'Should never be exposed directly to untrusted public subnets. Restrict to localhost or private application VPC.',
        cmd: 'nmap -sV -p 3306 --script=mysql-info 192.168.1.10'
      },
      '5432': {
        name: 'PostgreSQL Database',
        protocol: 'TCP',
        desc: 'Object-relational database management service listener.',
        security: 'Ensure client authentication via pg_hba.conf is restricted and strong TLS encryption is required for connections.',
        cmd: 'nmap -sV -p 5432 192.168.1.10'
      },
      '3389': {
        name: 'RDP (Remote Desktop Protocol)',
        protocol: 'TCP',
        desc: 'Microsoft graphical remote desktop management protocol.',
        security: 'Enforce Network Level Authentication (NLA), restrict access via VPN, and monitor for brute-force login attempts.',
        cmd: 'nmap -sV -p 3389 --script=rdp-enum-encryption 192.168.1.10'
      }
    };

    var WORKFLOW_INFO = {
      '1': { title: 'Step 01: Target Specification', desc: 'Accepts authorized IPv4, IPv6, or lab hostname input. Validates syntax and strictly verifies that the target resides inside the permitted laboratory boundaries.' },
      '2': { title: 'Step 02: Safety & Authorization Validation', desc: 'Applies automated multi-tier security boundary checks to prevent scanning unauthorized external infrastructure or dangerous multicast ranges.' },
      '3': { title: 'Step 03: Safe Nmap Execution', desc: 'Launches non-blocking asynchronous Nmap worker jobs using predefined, safe command profiles with real-time status logging.' },
      '4': { title: 'Step 04: Structured XML Output', desc: 'Nmap generates comprehensive machine-readable XML results containing host status, port states, service banners, and NSE script tables.' },
      '5': { title: 'Step 05: Hardened XML Parsing', desc: 'Secure defused XML parsing extracts hosts, ports, protocols, service products, versions, and NSE output with complete entity expansion protection.' },
      '6': { title: 'Step 06: Service Enumeration Engine', desc: 'Normalizes and categorizes discovered daemons into standard categories (HTTP, SSH, Database, DNS, Mail) for structured analytics.' },
      '7': { title: 'Step 07: NSE Script Analytics', desc: 'Parses script outputs to detect security configurations, SSL certificate details, cryptographic ciphers, and information leaks.' },
      '8': { title: 'Step 08: Rule-Based Findings Analysis', desc: 'Runs automated rule engines to flag security findings categorized across High, Medium, Low, and Informational severity levels.' },
      '9': { title: 'Step 09: Actionable PDF Reports', desc: 'Generates professional, branded PDF security assessment reports complete with executive summaries, technical findings, and remediation advice.' }
    };

    // Port Click Listeners
    document.querySelectorAll('[data-port]').forEach(function (el) {
      el.addEventListener('click', function (e) {
        e.stopPropagation();
        var p = this.getAttribute('data-port');
        var info = PORT_INFO[p];
        if (!info) return;

        modalContent.innerHTML =
          '<div style="color: var(--lp-cyan); font-family: monospace; font-size: 0.85rem; font-weight: 700; margin-bottom: 8px;">' +
          '<i class="fa-solid fa-ethernet me-1"></i> PORT ' + p + ' / ' + info.protocol +
          '</div>' +
          '<h3 style="color: #ffffff; font-size: 1.4rem; font-weight: 800; margin: 0 0 12px;">' + info.name + '</h3>' +
          '<p style="color: var(--lp-text-secondary); font-size: 0.9rem; line-height: 1.6; margin-bottom: 16px;">' + info.desc + '</p>' +
          '<div style="background: rgba(30, 58, 138, 0.25); border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 8px; padding: 14px; margin-bottom: 16px;">' +
          '<strong style="color: var(--lp-cyan); display: block; font-size: 0.8rem; margin-bottom: 4px; text-transform: uppercase;">Security Consideration:</strong>' +
          '<span style="color: var(--lp-text-primary); font-size: 0.85rem; line-height: 1.5;">' + info.security + '</span>' +
          '</div>' +
          '<div style="font-family: monospace; font-size: 0.78rem; background: rgba(0,0,0,0.5); padding: 10px 12px; border-radius: 6px; color: var(--lp-emerald); border: 1px solid rgba(255,255,255,0.06);">' +
          '<span style="color: var(--lp-text-muted);">$</span> ' + info.cmd +
          '</div>';

        modal.classList.add('is-open');
      });
    });

    // Workflow Step Click Listeners
    document.querySelectorAll('[data-step]').forEach(function (el) {
      el.addEventListener('click', function () {
        var s = this.getAttribute('data-step');
        var sInfo = WORKFLOW_INFO[s];
        if (!sInfo) return;

        modalContent.innerHTML =
          '<div style="color: var(--lp-cyan); font-family: monospace; font-size: 0.85rem; font-weight: 700; margin-bottom: 8px;">' +
          '<i class="fa-solid fa-diagram-project me-1"></i> SCANVIX ARCHITECTURE' +
          '</div>' +
          '<h3 style="color: #ffffff; font-size: 1.35rem; font-weight: 800; margin: 0 0 14px;">' + sInfo.title + '</h3>' +
          '<p style="color: var(--lp-text-secondary); font-size: 0.95rem; line-height: 1.7; margin: 0;">' + sInfo.desc + '</p>';

        modal.classList.add('is-open');
      });
    });

    // Close Modal Handler
    if (closeBtn) {
      closeBtn.addEventListener('click', function () {
        modal.classList.remove('is-open');
      });
    }

    modal.addEventListener('click', function (e) {
      if (e.target === modal) modal.classList.remove('is-open');
    });
  }

  // -------------------------------------------------------------
  // 11. ScrollSpy & Sticky Navbar
  // -------------------------------------------------------------
  function setupScrollSpy() {
    var nav = document.getElementById('scanvixNav');
    var navLinks = document.querySelectorAll('.scanvix-nav-link');
    var sections = document.querySelectorAll('section[id]');

    window.addEventListener('scroll', function () {
      var scrollY = window.pageYOffset || document.documentElement.scrollTop;

      if (nav) {
        if (scrollY > 40) {
          nav.classList.add('nav-scrolled');
        } else {
          nav.classList.remove('nav-scrolled');
        }
      }

      var currentSec = '';
      sections.forEach(function (sec) {
        var top = sec.offsetTop - 120;
        var height = sec.offsetHeight;
        if (scrollY >= top && scrollY < top + height) {
          currentSec = sec.getAttribute('id');
        }
      });

      if (currentSec) {
        navLinks.forEach(function (link) {
          link.classList.remove('active');
          if (link.getAttribute('href') === '#' + currentSec) {
            link.classList.add('active');
          }
        });
      }
    }, { passive: true });
  }

  // -------------------------------------------------------------
  // 12. Complete Resource Cleanup
  // -------------------------------------------------------------
  function dispose() {
    if (isDisposed) return;
    isDisposed = true;

    if (animFrameId) {
      cancelAnimationFrame(animFrameId);
      animFrameId = null;
    }

    window.removeEventListener('resize', handleResize);
    window.removeEventListener('beforeunload', dispose);

    networkNodes = [];
    blips = [];
  }

  // Initialize
  handleResize();
  initNetworkNodes();
  setupInteractions();
  setupCommandWindows();
  setupPortAndWorkflowModals();
  setupScrollSpy();

  animFrameId = requestAnimationFrame(render);

})();
