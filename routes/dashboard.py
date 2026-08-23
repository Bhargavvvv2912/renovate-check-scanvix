from datetime import datetime, timedelta
from flask import Blueprint, render_template, jsonify, request, redirect, url_for
from flask_login import login_required, current_user
from models import db, Scan, Host, Port, Finding

dashboard_bp = Blueprint('dashboard', __name__)

def get_dashboard_data():
    """
    Fetch live statistics from the database if scans exist;
    otherwise provide the comprehensive reference dataset.
    """
    from models.nse_result import NSEResult
    from services.service_enumerator import get_service_category

    # Count scans owned by this specific user
    total_scans_db = Scan.query.filter_by(user_id=current_user.id).count()

    if total_scans_db > 0:
        # Compute live statistics from database
        hosts_count = Host.query.join(Scan).filter(Scan.user_id == current_user.id).count()
        ports_count = Port.query.join(Host).join(Scan).filter(Scan.user_id == current_user.id, Port.state == 'open').count()
        findings_count = Finding.query.join(Scan).filter(Scan.user_id == current_user.id).count()
        nse_scripts_executed = NSEResult.query.join(Scan).filter(Scan.user_id == current_user.id).count()
        completed_scans = Scan.query.filter_by(user_id=current_user.id, status='completed').count()
        success_rate = round((completed_scans / total_scans_db) * 100) if total_scans_db > 0 else 100

        # Findings by severity
        sev_high = Finding.query.join(Scan).filter(Scan.user_id == current_user.id, Finding.severity.ilike('high')).count()
        sev_med = Finding.query.join(Scan).filter(Scan.user_id == current_user.id, Finding.severity.ilike('medium')).count()
        sev_low = Finding.query.join(Scan).filter(Scan.user_id == current_user.id, Finding.severity.ilike('low')).count()
        sev_info = Finding.query.join(Scan).filter(Scan.user_id == current_user.id, Finding.severity.ilike('info')).count()

        # Recent scans
        recent_scans_db = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.start_time.desc()).limit(5).all()
        recent_scans = []
        for s in recent_scans_db:
            recent_scans.append({
                'id': s.id,
                'target': s.target,
                'scan_profile': s.scan_profile.replace('_', ' ').title(),
                'date': s.start_time.strftime('%b %d, %Y %I:%M %p') if s.start_time else 'N/A',
                'status': s.status.capitalize(),
                'hosts': s.number_of_hosts or len(s.hosts),
                'open_ports': s.number_of_open_ports or sum(len(h.ports) for h in s.hosts),
                'findings': s.number_of_findings or len(s.findings),
                'findings_severity': 'high' if any(f.severity.lower() == 'high' for f in s.findings) else ('medium' if any(f.severity.lower() == 'medium' for f in s.findings) else 'info'),
                'report_available': bool(s.report_path or s.reports)
            })

        # Top hosts by findings
        hosts_db = Host.query.join(Scan).filter(Scan.user_id == current_user.id).all()
        top_hosts = []
        for h in sorted(hosts_db, key=lambda x: len(x.findings), reverse=True)[:4]:
            highest_sev = 'INFO'
            for f in h.findings:
                if f.severity.lower() == 'high':
                    highest_sev = 'HIGH'
                    break
                elif f.severity.lower() == 'medium' and highest_sev != 'HIGH':
                    highest_sev = 'MEDIUM'
                elif f.severity.lower() == 'low' and highest_sev not in ('HIGH', 'MEDIUM'):
                    highest_sev = 'LOW'

            top_hosts.append({
                'ip': h.ip_address,
                'findings_count': len(h.findings),
                'severity': highest_sev,
                'percentage': min(100, int((len(h.findings) / max(findings_count, 1)) * 100))
            })

        # Services statistics from real open ports
        open_ports_db = Port.query.join(Host).join(Scan).filter(Scan.user_id == current_user.id, Port.state.ilike('open')).all()
        services_counter = {}
        for p in open_ports_db:
            srv_name = get_service_category(p.service, p.port_number).lower()
            services_counter[srv_name] = services_counter.get(srv_name, 0) + 1

        services_detected_count = len([s for s in services_counter.keys() if s != 'other']) or (1 if services_counter else 0)

        # Build service breakdown dictionary
        svc_dict = {
            'http': services_counter.get('http', 0),
            'ssh': services_counter.get('ssh', 0),
            'https': services_counter.get('https', 0),
            'dns': services_counter.get('dns', 0),
            'ftp': services_counter.get('ftp', 0),
            'mysql': services_counter.get('mysql', 0),
        }
        known_sum = sum(svc_dict.values())
        svc_dict['others'] = max(0, len(open_ports_db) - known_sum)

        # Services list for UI display
        services_list = []
        icon_map = {
            'http': 'fa-solid fa-globe',
            'ssh': 'fa-solid fa-terminal',
            'https': 'fa-solid fa-lock',
            'dns': 'fa-solid fa-cubes',
            'ftp': 'fa-solid fa-right-left',
            'mysql': 'fa-solid fa-database'
        }
        for name, count in sorted(services_counter.items(), key=lambda x: x[1], reverse=True)[:6]:
            services_list.append({
                'name': name.upper(),
                'count': count,
                'icon': icon_map.get(name, 'fa-solid fa-network-wired')
            })

        if not services_list:
            services_list = [
                {'name': 'HTTP', 'count': 0, 'icon': 'fa-solid fa-globe'},
                {'name': 'SSH', 'count': 0, 'icon': 'fa-solid fa-terminal'}
            ]

        data = {
            'is_mock': False,
            'kpi': {
                'total_scans': total_scans_db,
                'total_scans_trend': 'Active',
                'hosts_scanned': hosts_count,
                'hosts_scanned_trend': 'Active',
                'open_ports': ports_count,
                'open_ports_trend': 'Active',
                'services_detected': services_detected_count,
                'services_detected_trend': 'Active',
                'nse_scripts_executed': nse_scripts_executed,
                'nse_scripts_executed_trend': 'Active',
                'security_findings': findings_count,
                'security_findings_trend': 'Active',
                'success_rate': f"{success_rate}%",
                'success_rate_trend': 'Completed'
            },
            'findings_severity': {
                'total': findings_count,
                'high': sev_high,
                'medium': sev_med,
                'low': sev_low,
                'info': sev_info
            },
            'open_ports_by_service': svc_dict,
            'scan_activity': {
                'labels': [s.start_time.strftime('%b %d') for s in reversed(recent_scans_db)] if recent_scans_db else ['Today'],
                'data': [s.number_of_open_ports or 0 for s in reversed(recent_scans_db)] if recent_scans_db else [0]
            },
            'recent_scans': recent_scans,
            'top_hosts': top_hosts,
            'scan_profiles': [
                {'name': 'Service + Default NSE', 'count': Scan.query.filter_by(user_id=current_user.id, scan_profile='service_default_nse').count(), 'percentage': 80},
                {'name': 'Basic Port Scan', 'count': Scan.query.filter_by(user_id=current_user.id, scan_profile='basic_port_scan').count(), 'percentage': 60},
                {'name': 'Comprehensive Lab Scan', 'count': Scan.query.filter_by(user_id=current_user.id, scan_profile='comprehensive_lab').count(), 'percentage': 40}
            ],
            'services_detected_list': services_list
        }
        return data

    # Clean Zero / Empty Initial State for Fresh Application Lifecycle
    return {
        'is_mock': False,
        'kpi': {
            'total_scans': 0,
            'total_scans_trend': 'No scans yet',
            'hosts_scanned': 0,
            'hosts_scanned_trend': 'No hosts yet',
            'open_ports': 0,
            'open_ports_trend': 'No ports yet',
            'services_detected': 0,
            'services_detected_trend': 'No services yet',
            'nse_scripts_executed': 0,
            'nse_scripts_executed_trend': 'No scripts yet',
            'security_findings': 0,
            'security_findings_trend': 'No findings yet',
            'success_rate': '0%',
            'success_rate_trend': 'Ready'
        },
        'findings_severity': {
            'total': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'high_pct': '0%',
            'medium_pct': '0%',
            'low_pct': '0%',
            'info_pct': '0%'
        },
        'open_ports_by_service': {
            'http': 0,
            'ssh': 0,
            'https': 0,
            'dns': 0,
            'ftp': 0,
            'others': 0
        },
        'scan_activity': {
            'labels': ['No Scans'],
            'data': [0]
        },
        'recent_scans': [],
        'top_hosts': [],
        'scan_profiles': [
            {'name': 'Service + Default NSE', 'count': 0, 'percentage': 0},
            {'name': 'Basic Port Scan', 'count': 0, 'percentage': 0},
            {'name': 'Comprehensive Lab Scan', 'count': 0, 'percentage': 0},
            {'name': 'HTTP Enumeration', 'count': 0, 'percentage': 0},
            {'name': 'SSH Enumeration', 'count': 0, 'percentage': 0},
            {'name': 'Others', 'count': 0, 'percentage': 0}
        ],
        'services_detected_list': []
    }

@dashboard_bp.route('/')
@login_required
def index():
    dashboard_data = get_dashboard_data()
    return render_template('dashboard.html', data=dashboard_data)

@dashboard_bp.route('/api/dashboard/stats')
@login_required
def api_dashboard_stats():
    time_filter = request.args.get('period', 'month')
    dashboard_data = get_dashboard_data()
    return jsonify(dashboard_data)

@dashboard_bp.route('/about')
@login_required
def about():
    return render_template('about.html')

@dashboard_bp.route('/settings')
@login_required
def settings():
    from flask import current_app
    allowed_targets = current_app.config.get('ALLOWED_LAB_TARGETS', [])
    allow_private = current_app.config.get('ALLOW_PRIVATE_SUBNETS', True)
    allow_localhost = current_app.config.get('ALLOW_LOCALHOST', True)
    return render_template('settings.html', 
                           allowed_targets=allowed_targets,
                           allow_private=allow_private,
                           allow_localhost=allow_localhost)

@dashboard_bp.route('/dashboard')
@login_required
def dashboard_alias():
    return redirect(url_for('dashboard.index'))

@dashboard_bp.route('/services')
@login_required
def services_list():
    from services.service_enumerator import enumerate_services, get_service_counts
    services = enumerate_services(current_user.id)
    counts = get_service_counts(current_user.id)
    return render_template('services.html', services=services, counts=counts)

@dashboard_bp.route('/api/services')
@login_required
def api_services():
    from services.service_enumerator import enumerate_services
    search = request.args.get('search')
    service = request.args.get('service')
    protocol = request.args.get('protocol')
    state = request.args.get('state')
    host = request.args.get('host')
    
    filters = {
        'service': service,
        'protocol': protocol,
        'state': state,
        'host': host
    }
    services = enumerate_services(current_user.id, filters=filters, search_query=search)
    return jsonify(services)

@dashboard_bp.route('/nse-scripts')
@login_required
def nse_scripts_list():
    from services.nse_service import NSE_SCRIPTS_LIBRARY
    return render_template('nse_scripts.html', library=NSE_SCRIPTS_LIBRARY)

@dashboard_bp.route('/hosts')
@login_required
def hosts():
    hosts = Host.query.join(Scan).filter(Scan.user_id == current_user.id).all()
    return render_template('hosts.html', hosts=hosts)


