import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { CSS3DRenderer, CSS3DObject } from 'three/addons/renderers/CSS3DRenderer.js';

(function () {
  'use strict';

  const canvasWrap = document.querySelector('.scanvix-3d-canvas-wrap');
  if (!canvasWrap) return;
  
  canvasWrap.innerHTML = ''; // Clear existing canvas if any

  // 1. Core Scene Setup
  const scene = new THREE.Scene();
  
  const camera = new THREE.PerspectiveCamera(45, canvasWrap.clientWidth / canvasWrap.clientHeight, 1, 8000);
  camera.position.set(0, 150, 1200);

  // 2. WebGL Renderer
  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
  renderer.setSize(canvasWrap.clientWidth, canvasWrap.clientHeight);
  renderer.setPixelRatio(window.devicePixelRatio);
  renderer.domElement.style.position = 'absolute';
  renderer.domElement.style.zIndex = '1';
  canvasWrap.appendChild(renderer.domElement);

  // 3. CSS3D Renderer
  const cssRenderer = new CSS3DRenderer();
  cssRenderer.setSize(canvasWrap.clientWidth, canvasWrap.clientHeight);
  cssRenderer.domElement.style.position = 'absolute';
  cssRenderer.domElement.style.top = '0px';
  cssRenderer.domElement.style.pointerEvents = 'auto'; // Immediate 1-click drag interaction
  cssRenderer.domElement.style.zIndex = '2';
  canvasWrap.appendChild(cssRenderer.domElement);
  
  // Make CSS children clickable and default cursor grab
  canvasWrap.style.cursor = 'grab';
  cssRenderer.domElement.style.cursor = 'grab';
  const style = document.createElement('style');
  style.textContent = `
    .scanvix-cmd-win { pointer-events: auto; }
    .scanvix-3d-canvas-wrap { cursor: grab; }
    .scanvix-3d-canvas-wrap:active { cursor: grabbing; }
  `;
  document.head.appendChild(style);

  // 4. Orbit Controls (Standard, Robust 3D Camera Controls)
  const controls = new OrbitControls(camera, cssRenderer.domElement);
  controls.enableDamping = true;
  controls.dampingFactor = 0.08;
  controls.enableRotate = true;
  controls.rotateSpeed = 0.85;
  controls.enableZoom = true;
  controls.zoomSpeed = 1.0;
  controls.enablePan = false;
  
  // Extended zoom limits
  controls.minDistance = 250;
  controls.maxDistance = 3500;

  // Full 360° horizontal rotation (unrestricted)
  controls.minAzimuthAngle = -Infinity;
  controls.maxAzimuthAngle = Infinity;

  // Controlled vertical tilt: 35° to 145° (approx -55° to +55° from horizontal)
  controls.minPolarAngle = (35 * Math.PI) / 180;
  controls.maxPolarAngle = (145 * Math.PI) / 180;

  controls.target.set(0, 0, 0);

  controls.mouseButtons = {
    LEFT: THREE.MOUSE.ROTATE,
    MIDDLE: THREE.MOUSE.DOLLY,
    RIGHT: THREE.MOUSE.NONE
  };
  controls.touches = {
    ONE: THREE.TOUCH.ROTATE,
    TWO: THREE.TOUCH.DOLLY_PAN
  };

  controls.addEventListener('start', () => {
    canvasWrap.style.cursor = 'grabbing';
    cssRenderer.domElement.style.cursor = 'grabbing';
  });

  controls.addEventListener('end', () => {
    canvasWrap.style.cursor = 'grab';
    cssRenderer.domElement.style.cursor = 'grab';
  });

  // Smooth double-click camera reset
  let isResettingCamera = false;
  let resetStartTime = 0;
  const resetDuration = 600;
  const resetStartCamPos = new THREE.Vector3();
  const resetStartTarget = new THREE.Vector3();
  const defaultCamPos = new THREE.Vector3(0, 150, 1200);
  const defaultTarget = new THREE.Vector3(0, 0, 0);

  function resetCameraView() {
    isResettingCamera = true;
    resetStartTime = performance.now();
    resetStartCamPos.copy(camera.position);
    resetStartTarget.copy(controls.target);
    if (typeof unfocusAll === 'function') unfocusAll();
  }

  cssRenderer.domElement.addEventListener('dblclick', (e) => {
    if (!e.target.closest('.scanvix-cmd-win')) {
      resetCameraView();
    }
  });

  // 5. Lighting
  const ambientLight = new THREE.AmbientLight(0x020817, 1);
  scene.add(ambientLight);
  
  const dirLight = new THREE.DirectionalLight(0x38bdf8, 2);
  dirLight.position.set(100, 500, 200);
  scene.add(dirLight);

  const orangeLight = new THREE.PointLight(0xf97316, 50, 600);
  orangeLight.position.set(0, 50, 0);
  scene.add(orangeLight);

  // 6. Build the 3D Hierarchy
  const scannerRoot = new THREE.Group();
  scene.add(scannerRoot);

  const platformGroup = new THREE.Group();
  scannerRoot.add(platformGroup);

  const radarSystem = new THREE.Group();
  scannerRoot.add(radarSystem);
  
  const commandOrbit = new THREE.Group();
  scannerRoot.add(commandOrbit);

  // Tier 1 (Base)
  const tier1Geo = new THREE.CylinderGeometry(300, 320, 20, 64);
  const tier1Mat = new THREE.MeshPhongMaterial({ color: 0x06101f, specular: 0x111111, shininess: 100, transparent: true, opacity: 0.9 });
  const tier1 = new THREE.Mesh(tier1Geo, tier1Mat);
  tier1.position.y = -40;
  platformGroup.add(tier1);
  
  // Tier 2
  const tier2Geo = new THREE.CylinderGeometry(240, 250, 16, 64);
  const tier2Mat = new THREE.MeshPhongMaterial({ color: 0x081329, specular: 0x38bdf8, shininess: 100 });
  const tier2 = new THREE.Mesh(tier2Geo, tier2Mat);
  tier2.position.y = -22;
  platformGroup.add(tier2);

  // Tier 3 (Radar Base)
  const tier3Geo = new THREE.CylinderGeometry(180, 180, 5, 64);
  const tier3Mat = new THREE.MeshPhongMaterial({ color: 0x020611, specular: 0x38bdf8, shininess: 150 });
  const tier3 = new THREE.Mesh(tier3Geo, tier3Mat);
  tier3.position.y = -10;
  radarSystem.add(tier3);
  
  // Concentric Rings
  const ringMaterial = new THREE.MeshBasicMaterial({ color: 0x38bdf8, side: THREE.DoubleSide, transparent: true, opacity: 0.3 });
  const glowMaterial = new THREE.MeshBasicMaterial({ color: 0x38bdf8, side: THREE.DoubleSide, transparent: true, opacity: 0.8 });
  
  [60, 100, 140, 175].forEach((radius, i) => {
    const ringGeo = new THREE.RingGeometry(radius, radius + 1.5, 64);
    const ring = new THREE.Mesh(ringGeo, i === 3 ? glowMaterial : ringMaterial);
    ring.rotation.x = -Math.PI / 2;
    ring.position.y = -7;
    radarSystem.add(ring);
  });

  // Radar Sweep Beam
  const sweepGroup = new THREE.Group();
  radarSystem.add(sweepGroup);
  
  const sweepGeo = new THREE.CircleGeometry(175, 32, 0, Math.PI / 3);
  const sweepMat = new THREE.MeshBasicMaterial({ color: 0xf97316, side: THREE.DoubleSide, transparent: true, opacity: 0.25 });
  const sweep = new THREE.Mesh(sweepGeo, sweepMat);
  sweep.rotation.x = -Math.PI / 2;
  sweep.position.y = -6.5;
  sweepGroup.add(sweep);

  const sweepLineGeo = new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(0,0,0), new THREE.Vector3(175,0,0)]);
  const sweepLineMat = new THREE.LineBasicMaterial({ color: 0xff9900, linewidth: 2 });
  const sweepLine = new THREE.Line(sweepLineGeo, sweepLineMat);
  sweepLine.position.y = -6.4;
  sweepGroup.add(sweepLine);

  // 7. Network Particles
  const particlesGeo = new THREE.BufferGeometry();
  const particleCount = 200;
  const posArray = new Float32Array(particleCount * 3);
  for(let i=0; i<particleCount*3; i++) {
    posArray[i] = (Math.random() - 0.5) * 800;
  }
  particlesGeo.setAttribute('position', new THREE.BufferAttribute(posArray, 3));
  const particleMat = new THREE.PointsMaterial({ size: 4, color: 0x38bdf8, transparent: true, opacity: 0.6 });
  const particles = new THREE.Points(particlesGeo, particleMat);
  scannerRoot.add(particles);

  // 8. Integrate CSS3D Terminals
  let unfocusAll = () => {};
  const cssLayer = document.querySelector('.scanvix-cmd-win-layer');
  if (cssLayer) {
    const terminals = cssLayer.querySelectorAll('.scanvix-cmd-win');
    
    // Positions in 3D Space (x, y, z)
    // Order matches DOM elements: 
    // 0: nmap -sS (upper-left)
    // 1: main terminal (center/front)
    // 2: nmap -Pn (upper-right)
    // 3: nmap -A (lower-right)
    // 4: nmap -sV (lower-left)
    // 5: nmap -p- (lower/mid background)
    const positions = [
      { x: -350, y: 150, z: 80, rotY: Math.PI / 8 },   // syn (upper-left)
      { x: 0, y: 110, z: 180, rotY: 0 },               // terminal (front-center)
      { x: 350, y: 140, z: 50, rotY: -Math.PI / 8 },   // pn (upper-right)
      { x: 380, y: 90, z: -100, rotY: -Math.PI / 10 }, // aggressive (right background)
      { x: -360, y: 80, z: -80, rotY: Math.PI / 10 },  // sV (left background)
      { x: 50, y: 200, z: -150, rotY: 0 }              // p- (upper center background)
    ];

    terminals.forEach((term, index) => {
      // Create CSS3DObject
      const cssObj = new CSS3DObject(term);
      const pos = positions[index] || { x: 0, y: 0, z: 0, rotY: 0 };
      cssObj.position.set(pos.x, pos.y, pos.z);
      cssObj.rotation.y = pos.rotY;
      
      // Keep terminal original styles overriding absolute pos where necessary
      term.style.top = 'auto';
      term.style.left = 'auto';
      term.style.right = 'auto';
      term.style.bottom = 'auto';
      term.style.position = 'relative';
      
      commandOrbit.add(cssObj);
      
      // Store original transform to restore on unfocus
      term.userData = { origPos: cssObj.position.clone(), origRot: cssObj.rotation.clone(), obj: cssObj };
      
      // Hover effects
      term.addEventListener('mouseenter', () => {
        if(!term.classList.contains('is-focused')) {
          cssObj.scale.set(1.03, 1.03, 1.03);
        }
      });
      term.addEventListener('mouseleave', () => {
        if(!term.classList.contains('is-focused')) {
          cssObj.scale.set(1, 1, 1);
        }
      });
      
      // Distinguish click vs drag
      let termDownX = 0;
      let termDownY = 0;
      term.addEventListener('pointerdown', (e) => {
        termDownX = e.clientX;
        termDownY = e.clientY;
      });

      // Focus interaction
      term.addEventListener('click', (e) => {
        if (e.target.closest('.scanvix-win-close')) {
            e.stopPropagation();
            unfocusAll();
            return;
        }

        const dist = Math.hypot(e.clientX - termDownX, e.clientY - termDownY);
        if (dist > 6) {
          // It was a drag rotation, not a click
          return;
        }

        unfocusAll();
        term.classList.add('is-focused');
        cssObj.scale.set(1.1, 1.1, 1.1);
        
        terminals.forEach(other => {
            if (other !== term) other.classList.add('is-dimmed');
        });
      });
    });
    
    // Unfocus when clicking empty space without dragging
    let emptyDownX = 0;
    let emptyDownY = 0;
    cssRenderer.domElement.addEventListener('pointerdown', (e) => {
      emptyDownX = e.clientX;
      emptyDownY = e.clientY;
    });

    cssRenderer.domElement.addEventListener('click', (e) => {
      if(!e.target.closest('.scanvix-cmd-win')) {
        const dist = Math.hypot(e.clientX - emptyDownX, e.clientY - emptyDownY);
        if (dist < 6) {
          unfocusAll();
        }
      }
    });
    
    unfocusAll = function() {
      terminals.forEach(term => {
          term.classList.remove('is-focused');
          term.classList.remove('is-dimmed');
          if(term.userData.obj) {
              term.userData.obj.scale.set(1, 1, 1);
          }
      });
    };
  }

  // 9. Resize Handler
  window.addEventListener('resize', onWindowResize);
  function onWindowResize() {
    if(!canvasWrap) return;
    camera.aspect = canvasWrap.clientWidth / canvasWrap.clientHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(canvasWrap.clientWidth, canvasWrap.clientHeight);
    cssRenderer.setSize(canvasWrap.clientWidth, canvasWrap.clientHeight);
  }

  // 10. Animation Loop
  const clock = new THREE.Clock();
  
  function animate() {
    requestAnimationFrame(animate);
    
    const delta = clock.getDelta();
    const time = clock.getElapsedTime();
    
    // Smooth camera reset interpolation or normal controls damping
    if (isResettingCamera) {
      const elapsed = performance.now() - resetStartTime;
      const progress = Math.min(elapsed / resetDuration, 1);
      const ease = 1 - Math.pow(1 - progress, 3); // ease-out cubic
      camera.position.lerpVectors(resetStartCamPos, defaultCamPos, ease);
      controls.target.lerpVectors(resetStartTarget, defaultTarget, ease);
      controls.update();
      if (progress >= 1) {
        isResettingCamera = false;
      }
    } else {
      controls.update();
    }
    
    // Continuous Independent Animations
    radarSystem.rotation.y += delta * 0.25; // Slow rotation of radar
    sweepGroup.rotation.y -= delta * 1.6;   // Fast orange sweep rotation
    commandOrbit.rotation.y += delta * 0.04; // Very slow orbit of terminals
    
    // Subtle Platform Bob (very small amplitude)
    platformGroup.position.y = Math.sin(time) * 4;
    
    // Terminals small floating
    const cssLayer = document.querySelector('.scanvix-cmd-win-layer');
    if (cssLayer) {
        const terminals = cssLayer.querySelectorAll('.scanvix-cmd-win');
        terminals.forEach((term, index) => {
            if (term.userData && term.userData.obj && !term.classList.contains('is-focused')) {
                // Add a small individual float based on index
                term.userData.obj.position.y = term.userData.origPos.y + Math.sin(time * 1.5 + index) * 5;
            }
        });
    }
    
    // Particles slow rotate
    particles.rotation.y += delta * 0.08;

    renderer.render(scene, camera);
    cssRenderer.render(scene, camera);
  }
  
  animate();

  // 11. Scroll Intersection Observer for Animations & Workflow Data Pulse
  const animElements = document.querySelectorAll('.anim-up');
  
  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry, index) => {
      if (entry.isIntersecting) {
        // Stagger if multiple appear at once
        setTimeout(() => {
          entry.target.classList.add('is-visible');
          
          // If this is the workflow section, trigger stagger on steps
          const steps = entry.target.querySelectorAll('.scanvix-step-card');
          if(steps.length > 0) {
              steps.forEach((step, i) => {
                  setTimeout(() => {
                      step.classList.add('active'); // active triggers glow/icon change in css
                  }, i * 150); // 150ms stagger
              });
          }
        }, index * 100);
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.1 });
  
  animElements.forEach(el => observer.observe(el));

  // Add the port modals logic here (copied from old script)
  function setupPortAndWorkflowModals() {
    var modal = document.getElementById('scanvixModal');
    var modalContent = document.getElementById('modalContent');
    var closeBtn = document.getElementById('modalCloseBtn');
    if (!modal || !modalContent) return;

    var PORT_INFO = {
      '22': { name: 'SSH (Secure Shell)', protocol: 'TCP', desc: 'Encrypted remote administrative command execution protocol.', security: 'Ensure root login is disabled, use strong Ed25519/RSA keys.', cmd: 'nmap -sV -p 22 --script=ssh2-enum-algos 192.168.1.10' },
      '53': { name: 'DNS (Domain Name System)', protocol: 'TCP / UDP', desc: 'Resolves human-readable hostnames into IP addresses.', security: 'Verify against open DNS recursion.', cmd: 'nmap -sU -p 53 --script=dns-recursion 192.168.1.10' },
      '80': { name: 'HTTP', protocol: 'TCP', desc: 'Standard unencrypted web server listener.', security: 'Cleartext protocol vulnerable to network sniffing.', cmd: 'nmap -sV -p 80 --script=http-title 192.168.1.10' },
      '443': { name: 'HTTPS', protocol: 'TCP', desc: 'Encrypted web transport securing web applications.', security: 'Enforce TLS 1.3/1.2.', cmd: 'nmap -sV -p 443 --script=ssl-cert 192.168.1.10' },
      '3306': { name: 'MySQL Database', protocol: 'TCP', desc: 'Relational database management service.', security: 'Restrict to localhost or private application VPC.', cmd: 'nmap -sV -p 3306 192.168.1.10' },
      '5432': { name: 'PostgreSQL Database', protocol: 'TCP', desc: 'Object-relational database management service.', security: 'Ensure client authentication is restricted.', cmd: 'nmap -sV -p 5432 192.168.1.10' },
      '3389': { name: 'RDP', protocol: 'TCP', desc: 'Microsoft graphical remote desktop management protocol.', security: 'Enforce Network Level Authentication (NLA).', cmd: 'nmap -sV -p 3389 192.168.1.10' }
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

    if (closeBtn) {
      closeBtn.addEventListener('click', function () {
        modal.classList.remove('is-open');
      });
    }

    modal.addEventListener('click', function (e) {
      if (e.target === modal) modal.classList.remove('is-open');
    });
  }

  // ScrollSpy
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

  setupPortAndWorkflowModals();
  setupScrollSpy();

})();
