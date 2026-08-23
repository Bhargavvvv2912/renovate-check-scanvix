"""
NMAP Execution Engine & Process Lifecycle Service
=================================================
Executes predefined Nmap scan profiles against authorized laboratory targets
using safe subprocess argument lists (shell=False). Enforces execution timeouts,
concurrency limits, structured XML output capture, and database state updates.
"""

import os
import shutil
import subprocess
import threading
import time
import logging
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple

from services.target_validator import validate_target
from services.scan_profiles import get_profile_by_id, is_valid_profile, SCAN_PROFILES
from models import db, Scan

logger = logging.getLogger(__name__)

# Concurrency & active scan tracker
_active_scans_lock = threading.Lock()
_active_scans: Dict[int, Dict[str, Any]] = {}

class ScanExecutionError(Exception):
    """Base exception for scan execution failures."""
    pass

class ScanConcurrencyError(ScanExecutionError):
    """Raised when maximum concurrent scan limit is exceeded."""
    pass

class ScanAuthorizationError(ScanExecutionError):
    """Raised when a target fails authorization checks before execution."""
    pass

class ScanProfileError(ScanExecutionError):
    """Raised when an invalid or unapproved profile is requested."""
    pass

def check_nmap_availability(nmap_path: str = 'nmap') -> Dict[str, Any]:
    """
    Safely checks whether the Nmap executable is installed and available.
    Executes 'nmap --version' using subprocess without shell=True.
    """
    resolved_path = shutil.which(nmap_path)
    if not resolved_path:
        # Check standard Windows paths if not in PATH
        for fallback in [
            r'C:\Program Files (x86)\Nmap\nmap.exe',
            r'C:\Program Files\Nmap\nmap.exe'
        ]:
            if os.path.exists(fallback):
                resolved_path = fallback
                break

    if not resolved_path:
        return {
            'available': False,
            'version': None,
            'path': None,
            'message': 'Nmap Engine is unavailable. Please install Nmap to enable live scanning.'
        }

    try:
        proc = subprocess.run(
            [resolved_path, '--version'],
            capture_output=True,
            text=True,
            timeout=5,
            shell=False
        )
        if proc.returncode == 0 and 'Nmap version' in proc.stdout:
            # Extract version token (e.g. "Nmap version 7.94 ...")
            lines = proc.stdout.splitlines()
            first_line = lines[0] if lines else ''
            version_str = '7.94'
            parts = first_line.split()
            if len(parts) >= 3 and parts[1].lower() == 'version':
                version_str = parts[2]

            return {
                'available': True,
                'version': version_str,
                'path': resolved_path,
                'message': f'Nmap Engine {version_str} is ready.'
            }
    except Exception as e:
        logger.warning(f"Nmap detection execution failed: {str(e)}")

    return {
        'available': False,
        'version': None,
        'path': None,
        'message': 'Nmap Engine is unavailable.'
    }

def get_active_scans_count() -> int:
    """Returns number of currently running scans."""
    with _active_scans_lock:
        return len(_active_scans)

def is_scan_running(scan_id: int) -> bool:
    """Checks if a specific scan ID is currently running."""
    with _active_scans_lock:
        return scan_id in _active_scans

def cancel_active_scan(scan_id: int) -> bool:
    """
    Cancels an active running scan process.
    """
    with _active_scans_lock:
        scan_info = _active_scans.get(scan_id)
        if not scan_info:
            return False

        proc = scan_info.get('process')
        if proc and hasattr(proc, 'poll') and proc.poll() is None:
            try:
                proc.terminate()
                # Give process a moment to exit gracefully
                time.sleep(0.5)
                if proc.poll() is None:
                    proc.kill()
            except Exception as e:
                logger.error(f"Error terminating scan process {scan_id}: {str(e)}")

        scan_info['cancelled'] = True
        return True

def start_scan_job(
    app,
    user_id: int,
    target: str,
    profile_id: str
) -> Tuple[Scan, str]:
    """
    Validates parameters, creates database record, and dispatches background execution.
    """
    # 1. Profile Validation
    profile = get_profile_by_id(profile_id)
    if not profile:
        raise ScanProfileError(f"Invalid scan profile requested: '{profile_id}'")

    # 2. Target Validation & Authorization Check (Phase 4 boundary)
    allowed_targets = app.config.get('ALLOWED_LAB_TARGETS', [])
    allow_private = app.config.get('ALLOW_PRIVATE_SUBNETS', True)
    allow_localhost = app.config.get('ALLOW_LOCALHOST', True)

    with app.app_context():
        from models.authorized_target import AuthorizedTarget
        db_auth_targets = AuthorizedTarget.query.all()
        for at in db_auth_targets:
            allowed_targets.append(at.target)

    val_result = validate_target(
        target=target,
        authorized_targets=allowed_targets,
        allow_private_subnets=allow_private,
        allow_localhost=allow_localhost
    )

    if not val_result['valid'] or not val_result['authorized']:
        raise ScanAuthorizationError(val_result['message'])

    normalized_target = val_result['target']

    # 3. Concurrency Limit Check
    max_concurrent = app.config.get('MAX_CONCURRENT_SCANS', 1)
    if get_active_scans_count() >= max_concurrent:
        raise ScanConcurrencyError(
            "A scan is already running. Please wait for it to finish or terminate it before starting a new scan."
        )

    # 4. Create Database Record
    with app.app_context():
        new_scan = Scan(
            user_id=user_id,
            target=normalized_target,
            scan_profile=profile['id'],
            start_time=datetime.utcnow(),
            status='running'
        )
        db.session.add(new_scan)
        db.session.commit()
        scan_id = new_scan.id

    # 5. Dispatch background thread
    worker_thread = threading.Thread(
        target=_run_scan_thread,
        args=(app, scan_id, normalized_target, profile),
        daemon=True,
        name=f"NmapWorker-Scan-{scan_id}"
    )
    worker_thread.start()

    logger.info(f"Scan #{scan_id} initiated for target '{normalized_target}' using profile '{profile['id']}'")
    return new_scan, "Scan initialized successfully."

def _run_scan_thread(app, scan_id: int, target: str, profile: Dict[str, Any]):
    """
    Background worker thread executing Nmap subprocess or simulation.
    """
    scan_dir = os.path.join(app.config['SCANS_FOLDER'], str(scan_id))
    os.makedirs(scan_dir, exist_ok=True)

    xml_path = os.path.join(scan_dir, 'result.xml')
    stdout_path = os.path.join(scan_dir, 'stdout.log')
    stderr_path = os.path.join(scan_dir, 'stderr.log')

    timeout_seconds = app.config.get('SCAN_TIMEOUT_SECONDS', 300)
    nmap_check = check_nmap_availability(app.config.get('NMAP_PATH', 'nmap'))

    start_mono = time.monotonic()
    status = 'completed'
    error_msg = None

    with _active_scans_lock:
        _active_scans[scan_id] = {
            'process': None,
            'start_time': time.time(),
            'cancelled': False
        }

    try:
        if nmap_check['available']:
            # Live Nmap Subprocess Execution
            nmap_bin = nmap_check['path']
            cmd_args = [nmap_bin, '-oX', xml_path] + profile['arguments'] + [target]
            logger.info(f"Scan #{scan_id}: Spawning subprocess {' '.join(cmd_args[:3])} ... [target: {target}]")

            with open(stdout_path, 'wb') as stdout_f, open(stderr_path, 'wb') as stderr_f:
                proc = subprocess.Popen(
                    cmd_args,
                    stdout=stdout_f,
                    stderr=stderr_f,
                    shell=False
                )

                with _active_scans_lock:
                    if scan_id in _active_scans:
                        _active_scans[scan_id]['process'] = proc

                try:
                    proc.wait(timeout=timeout_seconds)
                    if proc.returncode != 0:
                        status = 'failed'
                        error_msg = f"Nmap process exited with return code {proc.returncode}"
                except subprocess.TimeoutExpired:
                    logger.warning(f"Scan #{scan_id} exceeded timeout limit of {timeout_seconds}s. Killing process.")
                    proc.kill()
                    status = 'timeout'
                    error_msg = f"Scan exceeded configured timeout of {timeout_seconds} seconds."

        else:
            # Simulation / Fallback Generator (Educational Demonstration when Nmap binary is absent)
            logger.info(f"Scan #{scan_id}: Running educational simulation engine for '{target}' (Profile: {profile['id']})")
            
            # Simulate real-time scanning steps with cancellation checks
            total_simulation_steps = 4
            for step in range(total_simulation_steps):
                time.sleep(1.0)
                with _active_scans_lock:
                    if _active_scans.get(scan_id, {}).get('cancelled'):
                        status = 'cancelled'
                        error_msg = "Scan was cancelled by user."
                        break

            if status != 'cancelled':
                _write_simulated_nmap_xml(xml_path, stdout_path, target, profile)
                status = 'completed'

        # Check if cancelled during execution
        with _active_scans_lock:
            if _active_scans.get(scan_id, {}).get('cancelled'):
                status = 'cancelled'
                error_msg = "Scan was cancelled by user."

    except Exception as e:
        logger.error(f"Scan #{scan_id} unexpected execution exception: {str(e)}")
        status = 'failed'
        error_msg = "An unexpected error occurred during scan execution."

    finally:
        end_mono = time.monotonic()
        duration = end_mono - start_mono

        with _active_scans_lock:
            _active_scans.pop(scan_id, None)

        # Update SQLite database record & parse XML output if completed
        with app.app_context():
            try:
                scan = db.session.get(Scan, scan_id)
                if scan:
                    scan.status = status
                    scan.end_time = datetime.utcnow()
                    scan.duration = duration
                    scan.xml_path = xml_path if os.path.exists(xml_path) else None
                    scan.error_message = error_msg
                    db.session.commit()

                    # Trigger XML Parsing Pipeline if scan completed successfully
                    if status == 'completed' and os.path.exists(xml_path):
                        try:
                            from services.parser import parse_and_store_scan
                            parse_and_store_scan(scan_id, xml_path, app=app)
                            logger.info(f"Scan #{scan_id} results parsed and saved to database.")
                            
                            # Trigger NSE Script execution on the detected services automatically
                            from services.nse_service import execute_nse_scripts_for_scan
                            execute_nse_scripts_for_scan(scan_id, app)
                            logger.info(f"Scan #{scan_id} NSE scripts executed.")

                            # Trigger Rule-Based Findings Analyzer automatically
                            from services.findings_analyzer import analyze_scan_results
                            analyze_scan_results(scan_id, app)
                            logger.info(f"Scan #{scan_id} findings analysis completed.")
                        except Exception as pe:
                            logger.error(f"Error parsing XML/running NSE/running findings analyzer for scan #{scan_id}: {str(pe)}")

                    logger.info(f"Scan #{scan_id} finalized with status '{scan.status}' in {duration:.2f}s")
            except Exception as dbe:
                logger.error(f"Database commit error for scan #{scan_id}: {str(dbe)}")


def _write_simulated_nmap_xml(xml_path: str, stdout_path: str, target: str, profile: Dict[str, Any]):
    """
    Generates standard valid Nmap XML for laboratory demonstration when Nmap is not installed locally.
    """
    timestamp = int(time.time())
    timestr = datetime.utcnow().strftime('%a %b %d %H:%M:%S %Y')
    
    xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<nmaprun scanner="nmap" args="nmap -oX {xml_path} {' '.join(profile['arguments'])} {target}" start="{timestamp}" startstr="{timestr}" version="7.94" xmloutputversion="1.05">
<scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>
<verbose level="0"/>
<debugging level="0"/>
<host starttime="{timestamp}" endtime="{timestamp + 4}">
<status state="up" reason="echo-reply" reason_ttl="64"/>
<address addr="{target}" addrtype="ipv4"/>
<hostnames>
<hostname name="lab-target.local" type="user"/>
</hostnames>
<ports>
<extraports state="closed" count="996">
<extrareasons reason="resets" count="996"/>
</extraports>
<port protocol="tcp" portid="22">
<state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="ssh" product="OpenSSH" version="8.2p1 Ubuntu" extrainfo="Ubuntu Linux" method="probed" conf="10"/>
<script id="ssh2-enum-algos" output="&#xa;  kex_algorithms: (9)&#xa;    curve25519-sha256&#xa;    curve25519-sha256@libssh.org"/>
</port>
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="http" product="Apache httpd" version="2.4.41" extrainfo="(Ubuntu)" method="probed" conf="10"/>
<script id="http-title" output="VulnApp Laboratory Landing Page"/>
<script id="http-methods" output="&#xa;  Supported Methods: GET HEAD POST OPTIONS"/>
</port>
<port protocol="tcp" portid="443">
<state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="https" product="Apache httpd" version="2.4.41" extrainfo="(Ubuntu) SSL" method="probed" conf="10"/>
<script id="http-title" output="VulnApp Secure Portal"/>
</port>
<port protocol="tcp" portid="3306">
<state state="open" reason="syn-ack" reason_ttl="64"/>
<service name="mysql" product="MySQL" version="8.0.35" extrainfo="MySQL Community Server" method="probed" conf="10"/>
</port>
</ports>
<times srtt="1245" rttvar="250" to="100000"/>
</host>
<runstats>
<finished time="{timestamp + 4}" timestr="{timestr}" elapsed="4.25" summary="Nmap done at {timestr}; 1 IP address (1 host up) scanned in 4.25 seconds" exit="success"/>
<hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>
"""
    with open(xml_path, 'w', encoding='utf-8') as f:
        f.write(xml_content)

    stdout_content = f"""Starting Nmap 7.94 ( https://nmap.org ) at {timestr}
Nmap scan report for {target}
Host is up (0.0012s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp   open  http    Apache httpd 2.4.41
443/tcp  open  https   Apache httpd 2.4.41
3306/tcp open  mysql   MySQL 8.0.35

Nmap done: 1 IP address (1 host up) scanned in 4.25 seconds
"""
    with open(stdout_path, 'w', encoding='utf-8') as f:
        f.write(stdout_content)
