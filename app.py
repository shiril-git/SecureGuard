from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import create_access_token, JWTManager, jwt_required, get_jwt_identity
import requests
from urllib.parse import urljoin
import re
import pyotp
import sqlite3
import secrets
import string
import json
from bs4 import BeautifulSoup
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER
import io
import base64
from datetime import datetime
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

app = Flask(__name__)
CORS(app)
app.config['JWT_SECRET_KEY'] = 'secureguard-secret-key-2024'
jwt = JWTManager(app)

# ============ DATABASE FUNCTIONS ============

def init_db():
    conn = sqlite3.connect('security.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT UNIQUE,
                  phone TEXT,
                  password TEXT,
                  twofa_secret TEXT,
                  twofa_enabled INTEGER DEFAULT 0)''')
    
    # Scan History Table
    c.execute('''CREATE TABLE IF NOT EXISTS scan_history
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  scan_type TEXT,
                  target_url TEXT,
                  risk_level TEXT,
                  results TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users(id))''')
    
    # Activity Logs Table
    c.execute('''CREATE TABLE IF NOT EXISTS activity_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  action TEXT,
                  details TEXT,
                  ip_address TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users(id))''')
    
    conn.commit()
    conn.close()

def save_scan_result(user_id, scan_type, target_url, risk_level, results):
    """Save scan results to database"""
    try:
        conn = sqlite3.connect('security.db')
        c = conn.cursor()
        c.execute("""INSERT INTO scan_history 
                     (user_id, scan_type, target_url, risk_level, results) 
                     VALUES (?, ?, ?, ?, ?)""",
                  (user_id, scan_type, target_url, risk_level, json.dumps(results)))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error saving scan result: {e}")
        return False

def save_activity_log(user_id, action, details, ip_address=None):
    """Save activity log to database"""
    try:
        conn = sqlite3.connect('security.db')
        c = conn.cursor()
        c.execute("""INSERT INTO activity_logs 
                     (user_id, action, details, ip_address) 
                     VALUES (?, ?, ?, ?)""",
                  (user_id, action, details, ip_address or '127.0.0.1'))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error saving activity log: {e}")
        return False

def get_scan_history(user_id, limit=20):
    """Get scan history for a user"""
    try:
        conn = sqlite3.connect('security.db')
        c = conn.cursor()
        c.execute("""SELECT id, scan_type, target_url, risk_level, results, created_at 
                     FROM scan_history 
                     WHERE user_id = ? 
                     ORDER BY created_at DESC 
                     LIMIT ?""", (user_id, limit))
        scans = c.fetchall()
        conn.close()
        
        scan_list = []
        for scan in scans:
            try:
                results_data = json.loads(scan[4]) if scan[4] else {}
            except:
                results_data = {}
            scan_list.append({
                'id': scan[0],
                'scan_type': scan[1],
                'target_url': scan[2],
                'risk_level': scan[3],
                'results': results_data,
                'created_at': scan[5]
            })
        return scan_list
    except Exception as e:
        print(f"Error getting scan history: {e}")
        return []

def get_activity_logs(user_id, limit=50):
    """Get activity logs for a user"""
    try:
        conn = sqlite3.connect('security.db')
        c = conn.cursor()
        c.execute("""SELECT id, action, details, ip_address, created_at 
                     FROM activity_logs 
                     WHERE user_id = ? 
                     ORDER BY created_at DESC 
                     LIMIT ?""", (user_id, limit))
        logs = c.fetchall()
        conn.close()
        
        log_list = []
        for log in logs:
            log_list.append({
                'id': log[0],
                'action': log[1],
                'details': log[2],
                'ip_address': log[3],
                'created_at': log[4]
            })
        return log_list
    except Exception as e:
        print(f"Error getting activity logs: {e}")
        return []

def clear_scan_history(user_id):
    """Clear scan history for a user"""
    try:
        conn = sqlite3.connect('security.db')
        c = conn.cursor()
        c.execute("DELETE FROM scan_history WHERE user_id = ?", (user_id,))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error clearing scan history: {e}")
        return False

init_db()

# ============ ML RISK SCORING ============

class MLRiskScorer:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_names = [
            'admin_panels_count',
            'missing_headers_count',
            'outdated_software_count',
            'malware_signatures_count',
            'suspicious_urls_count',
            'password_strength_score',
            'inline_events_count',
            'external_scripts_count'
        ]
        
    def train_model(self):
        """Train a Random Forest model with synthetic data"""
        
        X_train = np.array([
            [0, 0, 0, 0, 0, 5, 5, 5],
            [0, 1, 0, 0, 0, 4, 8, 10],
            [1, 0, 0, 0, 0, 5, 6, 8],
            [0, 2, 0, 0, 0, 4, 10, 12],
            [1, 1, 0, 0, 0, 5, 7, 9],
            [2, 3, 1, 0, 0, 3, 15, 20],
            [3, 2, 1, 1, 0, 3, 18, 25],
            [2, 4, 1, 0, 1, 2, 20, 30],
            [4, 3, 2, 0, 0, 3, 22, 28],
            [1, 5, 1, 1, 0, 3, 25, 35],
            [5, 5, 3, 2, 2, 1, 40, 50],
            [6, 4, 3, 3, 2, 1, 45, 55],
            [4, 6, 4, 2, 3, 1, 50, 60],
            [7, 5, 3, 3, 3, 0, 55, 70],
            [5, 7, 5, 4, 3, 0, 60, 80],
        ])
        
        y_train = np.array([10, 15, 20, 25, 18, 45, 50, 55, 48, 52, 75, 82, 88, 92, 95])
        
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X_train)
        
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        y_classes = np.array([0 if score <= 33 else 1 if score <= 66 else 2 for score in y_train])
        
        self.model.fit(X_scaled, y_classes)
        print("✅ ML Risk Scoring Model trained successfully")
        
    def predict_risk(self, features):
        if self.model is None or self.scaler is None:
            self.train_model()
        
        feature_vector = np.array([features[f] for f in self.feature_names]).reshape(1, -1)
        feature_scaled = self.scaler.transform(feature_vector)
        
        risk_class = self.model.predict(feature_scaled)[0]
        probabilities = self.model.predict_proba(feature_scaled)[0]
        
        if risk_class == 0:
            base_score = 20
            score = base_score + (probabilities[0] * 20)
        elif risk_class == 1:
            base_score = 50
            score = base_score + (probabilities[1] * 30)
        else:
            base_score = 80
            score = base_score + (probabilities[2] * 20)
        
        score = min(100, max(0, score))
        
        risk_levels = {0: 'LOW', 1: 'MEDIUM', 2: 'HIGH'}
        risk_descriptions = {
            'LOW': 'Your security posture is good. Continue regular monitoring.',
            'MEDIUM': 'Security issues detected. Review and fix identified risks.',
            'HIGH': 'Critical security vulnerabilities found. Take immediate action!'
        }
        
        return {
            'risk_score': round(score, 2),
            'risk_level': risk_levels[risk_class],
            'confidence': round(max(probabilities) * 100, 2),
            'probabilities': {
                'LOW': round(probabilities[0] * 100, 2),
                'MEDIUM': round(probabilities[1] * 100, 2),
                'HIGH': round(probabilities[2] * 100, 2)
            },
            'risk_description': risk_descriptions[risk_levels[risk_class]],
            'features_used': {name: features[name] for name in self.feature_names}
        }

ml_scorer = MLRiskScorer()

try:
    ml_scorer.train_model()
except Exception as e:
    print(f"⚠️ ML Model training warning: {e}")

# ============ ADMIN PANEL SCANNER ============
ADMIN_PATHS = [
    '/admin', '/wp-admin', '/administrator', '/login', '/admin/login',
    '/cms', '/dashboard', '/admin.php', '/manage', '/backend'
]

@app.route('/api/scan/admin-panel', methods=['POST'])
@jwt_required()  # FIX: Added JWT authentication
def check_admin_panel():
    try:
        user_id = get_jwt_identity()  # FIX: Get user_id from JWT token
        data = request.json
        website_url = data.get('url', '').strip()
        
        if not website_url:
            return jsonify({'error': 'URL is required'}), 400
        
        if not website_url.startswith(('http://', 'https://')):
            website_url = 'https://' + website_url
        
        exposed_panels = []
        
        for path in ADMIN_PATHS:
            full_url = urljoin(website_url, path)
            try:
                response = requests.get(full_url, timeout=5, allow_redirects=False)
                if response.status_code == 200:
                    exposed_panels.append({'url': full_url, 'status': response.status_code})
                elif response.status_code in [301, 302, 307, 308]:
                    redirect_location = response.headers.get('Location', '')
                    if 'login' in redirect_location.lower() or 'admin' in redirect_location.lower():
                        exposed_panels.append({'url': full_url, 'status': response.status_code})
            except:
                continue
        
        risk_level = 'HIGH' if len(exposed_panels) > 3 else 'MEDIUM' if len(exposed_panels) > 0 else 'LOW'
        
        result = {
            'url': website_url,
            'exposed_panels': exposed_panels,
            'total_found': len(exposed_panels),
            'risk_level': risk_level,
            'recommendation': 'Restrict access to admin panels using IP whitelisting and strong passwords.'
        }
        
        if user_id:
            save_scan_result(user_id, 'admin_panel', website_url, risk_level, result)
            save_activity_log(user_id, 'Admin Panel Scan', f'Scanned {website_url} - Risk: {risk_level}')
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============ MISCONFIGURATION SCANNER ============
@app.route('/api/scan/misconfigurations', methods=['POST'])
@jwt_required()  # FIX: Added JWT authentication
def check_misconfigurations():
    try:
        user_id = get_jwt_identity()  # FIX: Get user_id from JWT token
        data = request.json
        website_url = data.get('url', '').strip()
        
        if not website_url:
            return jsonify({'error': 'URL is required'}), 400
        
        if not website_url.startswith(('http://', 'https://')):
            website_url = 'https://' + website_url
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(website_url, timeout=10, allow_redirects=True, headers=headers)
            response_headers = response.headers
            
            issues = []
            
            security_headers = {
                'Strict-Transport-Security': 'Missing HSTS header - risk of SSL stripping attacks',
                'Content-Security-Policy': 'Missing CSP header - risk of XSS attacks',
                'X-Frame-Options': 'Missing X-Frame-Options - risk of clickjacking',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options - risk of MIME sniffing',
                'X-XSS-Protection': 'Missing XSS protection header'
            }
            
            for header, message in security_headers.items():
                if header not in response_headers:
                    issues.append({'type': 'missing_security_header', 'header': header, 'message': message, 'severity': 'MEDIUM'})
            
            if 'Server' in response_headers:
                issues.append({'type': 'information_disclosure', 'message': f'Server information disclosed: {response_headers["Server"]}', 'severity': 'LOW'})
            
            risk_level = 'HIGH' if len(issues) > 3 else 'MEDIUM' if len(issues) > 0 else 'LOW'
            
            result = {
                'url': response.url,
                'status_code': response.status_code,
                'issues': issues,
                'total_issues': len(issues),
                'risk_level': risk_level,
                'recommendation': 'Implement missing security headers and enforce HTTPS to protect against common web attacks.'
            }
            
            if user_id:
                save_scan_result(user_id, 'security_headers', website_url, risk_level, result)
                save_activity_log(user_id, 'Security Headers Scan', f'Scanned {website_url} - Risk: {risk_level}')
            
            return jsonify(result)
            
        except requests.exceptions.Timeout:
            return jsonify({'error': 'Website took too long to respond', 'url': website_url}), 408
        except requests.exceptions.ConnectionError:
            return jsonify({'error': 'Could not connect to website', 'url': website_url}), 400
        except Exception as e:
            return jsonify({'error': f'Could not reach website: {str(e)}'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============ PASSWORD STRENGTH CHECKER ============
@app.route('/api/check-password', methods=['POST'])
def check_password_strength():
    try:
        data = request.json
        password = data.get('password', '')
        
        score = 0
        suggestions = []
        
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
            suggestions.append("Use at least 12 characters")
        
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            suggestions.append("Add uppercase letters")
        
        if re.search(r'[a-z]', password):
            score += 1
        else:
            suggestions.append("Add lowercase letters")
        
        if re.search(r'\d', password):
            score += 1
        else:
            suggestions.append("Add numbers")
        
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            score += 1
        else:
            suggestions.append("Add special characters")
        
        common_patterns = ['123', 'password', 'qwerty', 'admin']
        for pattern in common_patterns:
            if pattern in password.lower():
                score -= 1
                suggestions.append(f"Avoid '{pattern}'")
                break
        
        if score >= 5:
            strength = "STRONG"
        elif score >= 3:
            strength = "MEDIUM"
        else:
            strength = "WEAK"
        
        return jsonify({
            'strength': strength,
            'score': max(0, score),
            'suggestions': suggestions,
            'suggested_password': ''.join(secrets.choice(string.ascii_letters + string.digits + "!@#$%^&*") for i in range(16)) if strength == "WEAK" else None
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============ OUTDATED SOFTWARE DETECTION ============

SOFTWARE_DB = {
    'wordpress': {
        'name': 'WordPress',
        'latest': '7.0',
        'vulnerable_versions': ['< 5.8', '5.8-6.4'],
        'check_method': 'meta_generator'
    },
    'jquery': {
        'name': 'jQuery',
        'latest': '3.7.1',
        'vulnerable_versions': ['< 3.5.0', '1.x', '2.x'],
        'check_method': 'js_file'
    },
    'bootstrap': {
        'name': 'Bootstrap',
        'latest': '5.3.3',
        'vulnerable_versions': ['< 4.6.0', '3.x'],
        'check_method': 'css_file'
    },
    'react': {
        'name': 'React',
        'latest': '18.3.1',
        'vulnerable_versions': ['< 16.8.0', '15.x'],
        'check_method': 'js_file'
    },
    'drupal': {
        'name': 'Drupal',
        'latest': '10.3.0',
        'vulnerable_versions': ['< 7.98', '8.x', '9.x'],
        'check_method': 'meta_generator'
    },
    'joomla': {
        'name': 'Joomla',
        'latest': '5.1.0',
        'vulnerable_versions': ['< 3.10.12', '4.x'],
        'check_method': 'meta_generator'
    },
    'angular': {
        'name': 'Angular',
        'latest': '18.0.0',
        'vulnerable_versions': ['< 15.0.0'],
        'check_method': 'js_file'
    },
    'vue': {
        'name': 'Vue.js',
        'latest': '3.4.27',
        'vulnerable_versions': ['< 2.7.0'],
        'check_method': 'js_file'
    }
}

@app.route('/api/scan/outdated-software', methods=['POST'])
@jwt_required()  # FIX: Added JWT authentication
def scan_outdated_software():
    try:
        user_id = get_jwt_identity()  # FIX: Get user_id from JWT token
        data = request.json
        website_url = data.get('url', '').strip()
        
        if not website_url:
            return jsonify({'error': 'URL is required'}), 400
        
        if not website_url.startswith(('http://', 'https://')):
            website_url = 'https://' + website_url
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(website_url, timeout=15, allow_redirects=True, headers=headers)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            outdated_software = []
            recommendations = []
            
            wp_check = check_wordpress(soup, response.text, website_url)
            if wp_check:
                outdated_software.append(wp_check)
                if wp_check.get('is_outdated'):
                    recommendations.append(f"Update {wp_check['name']} from {wp_check['version']} to {wp_check['latest_version']}")
            
            jquery_check = check_jquery(response.text)
            if jquery_check:
                outdated_software.append(jquery_check)
                if jquery_check.get('is_outdated'):
                    recommendations.append(f"Update {jquery_check['name']} from {jquery_check['version']} to {jquery_check['latest_version']}")
            
            bootstrap_check = check_bootstrap(response.text)
            if bootstrap_check:
                outdated_software.append(bootstrap_check)
                if bootstrap_check.get('is_outdated'):
                    recommendations.append(f"Update {bootstrap_check['name']} from {bootstrap_check['version']} to {bootstrap_check['latest_version']}")
            
            react_check = check_react(response.text)
            if react_check:
                outdated_software.append(react_check)
                if react_check.get('is_outdated'):
                    recommendations.append(f"Update {react_check['name']} from {react_check['version']} to {react_check['latest_version']}")
            
            drupal_check = check_drupal(soup, response.text)
            if drupal_check:
                outdated_software.append(drupal_check)
                if drupal_check.get('is_outdated'):
                    recommendations.append(f"Update {drupal_check['name']} from {drupal_check['version']} to {drupal_check['latest_version']}")
            
            joomla_check = check_joomla(soup, response.text)
            if joomla_check:
                outdated_software.append(joomla_check)
                if joomla_check.get('is_outdated'):
                    recommendations.append(f"Update {joomla_check['name']} from {joomla_check['version']} to {joomla_check['latest_version']}")
            
            angular_check = check_angular(response.text)
            if angular_check:
                outdated_software.append(angular_check)
                if angular_check.get('is_outdated'):
                    recommendations.append(f"Update {angular_check['name']} from {angular_check['version']} to {angular_check['latest_version']}")
            
            vue_check = check_vue(response.text)
            if vue_check:
                outdated_software.append(vue_check)
                if vue_check.get('is_outdated'):
                    recommendations.append(f"Update {vue_check['name']} from {vue_check['version']} to {vue_check['latest_version']}")
            
            outdated_count = sum(1 for sw in outdated_software if sw.get('is_outdated', False))
            if outdated_count >= 3:
                risk_level = 'HIGH'
            elif outdated_count >= 1:
                risk_level = 'MEDIUM'
            else:
                risk_level = 'LOW'
            
            result = {
                'url': website_url,
                'software_found': outdated_software,
                'outdated_count': outdated_count,
                'total_found': len(outdated_software),
                'risk_level': risk_level,
                'recommendations': recommendations,
                'recommendation_summary': f'Found {outdated_count} outdated software components. Update to latest versions to patch security vulnerabilities.'
            }
            
            if user_id:
                save_scan_result(user_id, 'outdated_software', website_url, risk_level, result)
                save_activity_log(user_id, 'Outdated Software Scan', f'Scanned {website_url} - Risk: {risk_level}')
            
            return jsonify(result)
            
        except requests.exceptions.Timeout:
            return jsonify({'error': 'Website took too long to respond', 'url': website_url}), 408
        except requests.exceptions.ConnectionError:
            return jsonify({'error': 'Could not connect to website', 'url': website_url}), 400
        except Exception as e:
            return jsonify({'error': f'Error scanning website: {str(e)}'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============ HELPER FUNCTIONS FOR SOFTWARE DETECTION ============
# [All helper functions remain the same - check_wordpress, check_jquery, etc.]

def check_wordpress(soup, html, url):
    try:
        version = None
        meta_generator = soup.find('meta', {'name': 'generator'})
        if meta_generator and 'wordpress' in meta_generator.get('content', '').lower():
            version_match = re.search(r'WordPress\s+([0-9.]+)', meta_generator.get('content', ''))
            if version_match:
                version = version_match.group(1)
        
        if '/wp-content/' in html or '/wp-includes/' in html:
            if not version:
                version = 'Unknown (WordPress detected)'
        
        if version:
            is_outdated = False
            if version != 'Unknown (WordPress detected)':
                latest = SOFTWARE_DB['wordpress']['latest']
                if version < latest:
                    is_outdated = True
            
            return {
                'name': 'WordPress',
                'version': version,
                'latest_version': SOFTWARE_DB['wordpress']['latest'],
                'is_outdated': is_outdated,
                'vulnerable_versions': SOFTWARE_DB['wordpress']['vulnerable_versions'],
                'severity': 'HIGH' if is_outdated else 'LOW'
            }
    except:
        pass
    return None

def check_jquery(html):
    try:
        jquery_patterns = [
            r'jquery[.-]([\d.]+)(?:\.min)?\.js',
            r'jquery-([\d.]+)\.js',
            r'jQuery\s+v([\d.]+)'
        ]
        
        for pattern in jquery_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                version = match.group(1)
                latest = SOFTWARE_DB['jquery']['latest']
                is_outdated = version < latest
                
                return {
                    'name': 'jQuery',
                    'version': version,
                    'latest_version': latest,
                    'is_outdated': is_outdated,
                    'vulnerable_versions': SOFTWARE_DB['jquery']['vulnerable_versions'],
                    'severity': 'MEDIUM' if is_outdated else 'LOW'
                }
    except:
        pass
    return None

def check_bootstrap(html):
    try:
        bootstrap_patterns = [
            r'bootstrap[.-]([\d.]+)(?:\.min)?\.css',
            r'bootstrap[.-]([\d.]+)(?:\.min)?\.js',
            r'Bootstrap\s+v([\d.]+)'
        ]
        
        for pattern in bootstrap_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                version = match.group(1)
                latest = SOFTWARE_DB['bootstrap']['latest']
                is_outdated = version < latest
                
                return {
                    'name': 'Bootstrap',
                    'version': version,
                    'latest_version': latest,
                    'is_outdated': is_outdated,
                    'vulnerable_versions': SOFTWARE_DB['bootstrap']['vulnerable_versions'],
                    'severity': 'MEDIUM' if is_outdated else 'LOW'
                }
    except:
        pass
    return None

def check_react(html):
    try:
        react_patterns = [
            r'react(?:\.min)?\.js.*?v([\d.]+)',
            r'React\s+v([\d.]+)',
            r'react@([\d.]+)'
        ]
        
        for pattern in react_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                version = match.group(1)
                latest = SOFTWARE_DB['react']['latest']
                is_outdated = version < latest
                
                return {
                    'name': 'React',
                    'version': version,
                    'latest_version': latest,
                    'is_outdated': is_outdated,
                    'vulnerable_versions': SOFTWARE_DB['react']['vulnerable_versions'],
                    'severity': 'HIGH' if is_outdated else 'LOW'
                }
    except:
        pass
    return None

def check_drupal(soup, html):
    try:
        meta_generator = soup.find('meta', {'name': 'generator'})
        if meta_generator and 'drupal' in meta_generator.get('content', '').lower():
            version_match = re.search(r'Drupal\s+([0-9.]+)', meta_generator.get('content', ''))
            if version_match:
                version = version_match.group(1)
                latest = SOFTWARE_DB['drupal']['latest']
                is_outdated = version < latest
                
                return {
                    'name': 'Drupal',
                    'version': version,
                    'latest_version': latest,
                    'is_outdated': is_outdated,
                    'vulnerable_versions': SOFTWARE_DB['drupal']['vulnerable_versions'],
                    'severity': 'HIGH' if is_outdated else 'LOW'
                }
    except:
        pass
    return None

def check_joomla(soup, html):
    try:
        meta_generator = soup.find('meta', {'name': 'generator'})
        if meta_generator and 'joomla' in meta_generator.get('content', '').lower():
            version_match = re.search(r'Joomla!\s+([0-9.]+)', meta_generator.get('content', ''))
            if version_match:
                version = version_match.group(1)
                latest = SOFTWARE_DB['joomla']['latest']
                is_outdated = version < latest
                
                return {
                    'name': 'Joomla',
                    'version': version,
                    'latest_version': latest,
                    'is_outdated': is_outdated,
                    'vulnerable_versions': SOFTWARE_DB['joomla']['vulnerable_versions'],
                    'severity': 'HIGH' if is_outdated else 'LOW'
                }
    except:
        pass
    return None

def check_angular(html):
    try:
        angular_patterns = [
            r'angular(?:\.min)?\.js.*?v([\d.]+)',
            r'AngularJS\s+v([\d.]+)',
            r'@angular/core@([\d.]+)'
        ]
        
        for pattern in angular_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                version = match.group(1)
                latest = SOFTWARE_DB['angular']['latest']
                is_outdated = version < latest
                
                return {
                    'name': 'Angular',
                    'version': version,
                    'latest_version': latest,
                    'is_outdated': is_outdated,
                    'vulnerable_versions': SOFTWARE_DB['angular']['vulnerable_versions'],
                    'severity': 'HIGH' if is_outdated else 'LOW'
                }
    except:
        pass
    return None

def check_vue(html):
    try:
        vue_patterns = [
            r'vue(?:\.min)?\.js.*?v([\d.]+)',
            r'Vue\.js\s+v([\d.]+)',
            r'vue@([\d.]+)'
        ]
        
        for pattern in vue_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                version = match.group(1)
                latest = SOFTWARE_DB['vue']['latest']
                is_outdated = version < latest
                
                return {
                    'name': 'Vue.js',
                    'version': version,
                    'latest_version': latest,
                    'is_outdated': is_outdated,
                    'vulnerable_versions': SOFTWARE_DB['vue']['vulnerable_versions'],
                    'severity': 'MEDIUM' if is_outdated else 'LOW'
                }
    except:
        pass
    return None

# ============ MALWARE DETECTION ============

MALWARE_SIGNATURES = {
    'base64_decode': {
        'pattern': r'base64_decode\s*\(\s*[\'"]',
        'description': 'Base64 decode function often used in PHP malware to hide malicious code',
        'severity': 'HIGH'
    },
    'eval_execution': {
        'pattern': r'eval\s*\(\s*[\'"]',
        'description': 'Eval() function used to execute arbitrary code - common in backdoors',
        'severity': 'HIGH'
    },
    'system_command': {
        'pattern': r'system\s*\(\s*[\'"]|shell_exec\s*\(\s*[\'"]|exec\s*\(\s*[\'"]',
        'description': 'System command execution functions - can be used for remote code execution',
        'severity': 'HIGH'
    },
    'obfuscated_js': {
        'pattern': r'(?:\w+)\s*=\s*function\s*\(\s*\)\s*\{\s*var\s+\w+\s*=\s*[\'"]\\x[\da-f]{2}',
        'description': 'Obfuscated JavaScript commonly used in malware',
        'severity': 'MEDIUM'
    },
    'iframe_injection': {
        'pattern': r'<iframe[^>]*src\s*=\s*[\'"](?:http[s]?:\/\/)?(?:[\da-z\.-]+)\.(?:tk|cf|ga|ml)',
        'description': 'Suspicious iframe pointing to malicious domains',
        'severity': 'HIGH'
    },
    'php_shell': {
        'pattern': r'<\?php\s*(?:eval|system|exec|passthru|shell_exec)\s*\(\s*\$_(?:GET|POST|REQUEST)',
        'description': 'PHP web shell backdoor pattern',
        'severity': 'HIGH'
    },
    'cryptominer': {
        'pattern': r'coinhive|miner|coin-hive|cryptonight|webassembly',
        'description': 'Cryptocurrency miner script detected',
        'severity': 'MEDIUM'
    },
    'redirect_malware': {
        'pattern': r'window\.location\s*=\s*[\'"]http[s]?:\/\/[\da-z\.-]+\.(?:xyz|top|club)',
        'description': 'Malicious redirect to suspicious domain',
        'severity': 'MEDIUM'
    },
    'phishing_keywords': {
        'pattern': r'phish|verify\s+your\s+account|confirm\s+your\s+identity|login\s+to\s+verify',
        'description': 'Potential phishing content detected',
        'severity': 'HIGH'
    }
}

SUSPICIOUS_DOMAINS = [
    'malware-domain.com',
    'bad-site.net',
    'phishing-site.org',
    'coin-hive.com',
    'miner-site.com'
]

@app.route('/api/scan/malware', methods=['POST'])
@jwt_required()  # FIX: Added JWT authentication
def scan_malware():
    try:
        user_id = get_jwt_identity()  # FIX: Get user_id from JWT token
        data = request.json
        website_url = data.get('url', '').strip()
        
        if not website_url:
            return jsonify({'error': 'URL is required'}), 400
        
        if not website_url.startswith(('http://', 'https://')):
            website_url = 'https://' + website_url
        
        print(f"🛡️ Malware scanning: {website_url}")
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            
            response = requests.get(website_url, timeout=15, allow_redirects=True, headers=headers)
            response.raise_for_status()
            
            malware_findings = []
            suspicious_urls = []
            
            for sig_name, sig_data in MALWARE_SIGNATURES.items():
                pattern = re.compile(sig_data['pattern'], re.IGNORECASE)
                matches = pattern.findall(response.text)
                
                if matches:
                    malware_findings.append({
                        'signature': sig_name,
                        'description': sig_data['description'],
                        'severity': sig_data['severity'],
                        'matches_found': len(matches)
                    })
            
            url_pattern = re.compile(r'(?:https?://|//)([^/\s"\']+)', re.IGNORECASE)
            found_urls = url_pattern.findall(response.text)
            
            for domain in found_urls:
                domain_lower = domain.lower()
                for suspicious in SUSPICIOUS_DOMAINS:
                    if suspicious in domain_lower:
                        suspicious_urls.append({
                            'url': domain,
                            'reason': f'Matches suspicious domain: {suspicious}'
                        })
            
            script_pattern = re.compile(r'<script[^>]*src\s*=\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE)
            external_scripts = script_pattern.findall(response.text)
            
            inline_events = re.findall(r'on\w+\s*=\s*[\'"][^\'"]*[\'"]', response.text, re.IGNORECASE)
            if len(inline_events) > 20:
                malware_findings.append({
                    'signature': 'excessive_inline_events',
                    'description': f'Excessive inline event handlers found ({len(inline_events)}) - potential XSS risk',
                    'severity': 'MEDIUM',
                    'matches_found': len(inline_events)
                })
            
            suspicious_iframes = []
            iframe_pattern = re.compile(r'<iframe[^>]*src\s*=\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE)
            iframes = iframe_pattern.findall(response.text)
            
            for iframe in iframes:
                if 'google' not in iframe.lower() and 'youtube' not in iframe.lower():
                    suspicious_iframes.append({
                        'url': iframe,
                        'reason': 'External iframe from unknown source'
                    })
            
            hidden_elements = re.findall(r'style\s*=\s*[\'"]display\s*:\s*none[\'"]', response.text, re.IGNORECASE)
            if len(hidden_elements) > 10:
                malware_findings.append({
                    'signature': 'excessive_hidden_elements',
                    'description': f'Excessive hidden elements found ({len(hidden_elements)}) - possible cloaking',
                    'severity': 'MEDIUM',
                    'matches_found': len(hidden_elements)
                })
            
            high_risk_count = sum(1 for f in malware_findings if f['severity'] == 'HIGH')
            medium_risk_count = sum(1 for f in malware_findings if f['severity'] == 'MEDIUM')
            
            if high_risk_count > 0:
                risk_level = 'HIGH'
            elif medium_risk_count > 2 or len(suspicious_urls) > 0:
                risk_level = 'MEDIUM'
            elif medium_risk_count > 0:
                risk_level = 'LOW_MEDIUM'
            else:
                risk_level = 'LOW'
            
            recommendations = []
            if malware_findings:
                recommendations.append("Remove malicious code immediately")
            if suspicious_urls:
                recommendations.append("Investigate and remove suspicious external links")
            if suspicious_iframes:
                recommendations.append("Review and remove unnecessary iframes")
            if high_risk_count > 0:
                recommendations.append("URGENT: High-risk malware detected - take immediate action")
            
            result = {
                'url': website_url,
                'status_code': response.status_code,
                'malware_findings': malware_findings,
                'suspicious_urls': suspicious_urls,
                'suspicious_iframes': suspicious_iframes[:5],
                'external_scripts_count': len(external_scripts),
                'inline_events_count': len(inline_events),
                'total_issues': len(malware_findings) + len(suspicious_urls) + len(suspicious_iframes),
                'high_risk_count': high_risk_count,
                'medium_risk_count': medium_risk_count,
                'risk_level': risk_level,
                'recommendations': recommendations,
                'recommendation_summary': f"Found {len(malware_findings)} malware signatures and {len(suspicious_urls)} suspicious URLs"
            }
            
            if user_id:
                save_scan_result(user_id, 'malware', website_url, risk_level, result)
                save_activity_log(user_id, 'Malware Scan', f'Scanned {website_url} - Risk: {risk_level}')
            
            print(f"✅ Malware scan complete: {result['risk_level']} risk")
            return jsonify(result)
            
        except requests.exceptions.Timeout:
            return jsonify({'error': 'Website took too long to respond', 'url': website_url}), 408
        except requests.exceptions.ConnectionError:
            return jsonify({'error': 'Could not connect to website', 'url': website_url}), 400
        except requests.exceptions.HTTPError as e:
            return jsonify({'error': f'HTTP error: {e.response.status_code}', 'url': website_url}), 400
        except Exception as e:
            return jsonify({'error': f'Error scanning website: {str(e)}'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============ HISTORY ENDPOINTS ============

@app.route('/api/scan-history', methods=['GET'])
@jwt_required()
def get_scan_history_endpoint():
    try:
        user_id = get_jwt_identity()
        limit = request.args.get('limit', 20, type=int)
        
        scans = get_scan_history(user_id, limit)
        
        return jsonify({
            'success': True,
            'scans': scans,
            'total': len(scans)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/activity-logs', methods=['GET'])
@jwt_required()
def get_activity_logs_endpoint():
    try:
        user_id = get_jwt_identity()
        limit = request.args.get('limit', 50, type=int)
        
        logs = get_activity_logs(user_id, limit)
        
        return jsonify({
            'success': True,
            'logs': logs,
            'total': len(logs)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/clear-history', methods=['POST'])
@jwt_required()
def clear_history():
    try:
        user_id = get_jwt_identity()
        
        success = clear_scan_history(user_id)
        
        if success:
            save_activity_log(user_id, 'Clear History', 'Cleared scan history')
            return jsonify({'success': True, 'message': 'Scan history cleared'})
        else:
            return jsonify({'error': 'Failed to clear history'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============ ML RISK SCORING ENDPOINTS ============

@app.route('/api/ml-risk-score', methods=['POST'])
def calculate_ml_risk():
    try:
        data = request.json
        scan_data = data.get('scan_data', {})
        
        features = {}
        
        admin_panel_data = scan_data.get('admin_panel', {})
        features['admin_panels_count'] = admin_panel_data.get('total_found', 0)
        
        headers_data = scan_data.get('security_headers', {})
        features['missing_headers_count'] = headers_data.get('total_issues', 0)
        
        software_data = scan_data.get('outdated_software', {})
        features['outdated_software_count'] = software_data.get('outdated_count', 0)
        
        malware_data = scan_data.get('malware', {})
        features['malware_signatures_count'] = len(malware_data.get('malware_findings', []))
        features['suspicious_urls_count'] = len(malware_data.get('suspicious_urls', []))
        features['inline_events_count'] = malware_data.get('inline_events_count', 0)
        features['external_scripts_count'] = malware_data.get('external_scripts_count', 0)
        
        features['password_strength_score'] = 3
        
        result = ml_scorer.predict_risk(features)
        
        return jsonify({
            'success': True,
            'risk_assessment': result,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============ PDF REPORT EXPORT ============

@app.route('/api/export-report', methods=['POST'])
def export_report():
    try:
        data = request.json
        scan_data = data.get('scan_data', {})
        report_type = data.get('report_type', 'full')
        
        buffer = io.BytesIO()
        
        doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72)
        styles = getSampleStyleSheet()
        story = []
        
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#667eea'),
            alignment=TA_CENTER,
            spaceAfter=30
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#764ba2'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        risk_style = ParagraphStyle(
            'RiskStyle',
            parent=styles['Normal'],
            fontSize=12,
            textColor=colors.HexColor('#f56565'),
            spaceAfter=6
        )
        
        story.append(Paragraph("🛡️ SecureGuard Security Report", title_style))
        story.append(Spacer(1, 0.2*inch))
        
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        story.append(Paragraph(f"Generated: {current_time}", styles['Normal']))
        story.append(Paragraph(f"Report Type: {report_type.upper()}", styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        story.append(Paragraph("Executive Summary", heading_style))
        summary_text = """
        SecureGuard conducted a comprehensive security assessment of your digital assets. 
        The scan identified potential security risks that require attention to protect 
        your infrastructure from threats.
        """
        story.append(Paragraph(summary_text, styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        story.append(Paragraph("Risk Overview", heading_style))
        
        risk_data = [
            ['Asset', 'Risk Level', 'Issues Found', 'Recommendation'],
        ]
        
        total_issues = 0
        high_risk_count = 0
        
        if scan_data.get('admin_panel'):
            admin_data = scan_data['admin_panel']
            risk_level = admin_data.get('risk_level', 'LOW')
            total_found = admin_data.get('total_found', 0)
            total_issues += total_found
            if risk_level == 'HIGH':
                high_risk_count += 1
            risk_data.append([
                'Admin Panels',
                risk_level,
                str(total_found),
                admin_data.get('recommendation', 'Restrict access')[:50] + '...'
            ])
        
        if scan_data.get('security_headers'):
            headers_data = scan_data['security_headers']
            risk_level = headers_data.get('risk_level', 'LOW')
            total_issues_found = headers_data.get('total_issues', 0)
            total_issues += total_issues_found
            if risk_level == 'HIGH':
                high_risk_count += 1
            risk_data.append([
                'Security Headers',
                risk_level,
                str(total_issues_found),
                headers_data.get('recommendation', 'Implement security headers')[:50] + '...'
            ])
        
        if scan_data.get('outdated_software'):
            software_data = scan_data['outdated_software']
            risk_level = software_data.get('risk_level', 'LOW')
            outdated_count = software_data.get('outdated_count', 0)
            total_issues += outdated_count
            if risk_level == 'HIGH':
                high_risk_count += 1
            risk_data.append([
                'Outdated Software',
                risk_level,
                str(outdated_count),
                f"Update {outdated_count} components"
            ])
        
        if scan_data.get('malware'):
            malware_data = scan_data['malware']
            risk_level = malware_data.get('risk_level', 'LOW')
            total_issues_found = malware_data.get('total_issues', 0)
            total_issues += total_issues_found
            if risk_level in ['HIGH', 'LOW_MEDIUM']:
                high_risk_count += 1
            risk_data.append([
                'Malware Detection',
                risk_level,
                str(total_issues_found),
                malware_data.get('recommendation_summary', 'Review findings')[:50] + '...'
            ])
        
        if len(risk_data) > 1:
            risk_table = Table(risk_data, colWidths=[1.5*inch, 1*inch, 1*inch, 2.5*inch])
            risk_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 10),
            ]))
            story.append(risk_table)
            story.append(Spacer(1, 0.3*inch))
        else:
            story.append(Paragraph("No scan data available. Please run security scans first.", styles['Normal']))
            story.append(Spacer(1, 0.3*inch))
        
        story.append(Paragraph("Overall Security Score", heading_style))
        
        max_issues = max(total_issues, 1)
        score = max(0, 100 - (total_issues * 5))
        score_color = colors.green if score >= 70 else colors.orange if score >= 50 else colors.red
        
        score_text = f"""
        <b>Score: {score}/100</b><br/>
        <font color='{score_color.hexval()}'>Risk Level: {'Low' if score >= 70 else 'Medium' if score >= 50 else 'High'}</font>
        """
        story.append(Paragraph(score_text, styles['Normal']))
        story.append(Spacer(1, 0.2*inch))
        
        story.append(Paragraph("Detailed Findings", heading_style))
        
        if scan_data.get('admin_panel'):
            story.append(Paragraph("🔍 Admin Panel Detection", heading_style))
            admin_data = scan_data['admin_panel']
            story.append(Paragraph(f"URL: {admin_data.get('url', 'N/A')}", styles['Normal']))
            story.append(Paragraph(f"Risk Level: {admin_data.get('risk_level', 'LOW')}", risk_style if admin_data.get('risk_level') == 'HIGH' else styles['Normal']))
            story.append(Paragraph(f"Exposed Panels Found: {admin_data.get('total_found', 0)}", styles['Normal']))
            if admin_data.get('exposed_panels'):
                story.append(Paragraph("Exposed URLs:", styles['Normal']))
                for panel in admin_data['exposed_panels'][:5]:
                    story.append(Paragraph(f"• {panel['url']} (Status: {panel['status']})", styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
        
        if scan_data.get('security_headers'):
            story.append(Paragraph("⚠️ Security Headers Check", heading_style))
            headers_data = scan_data['security_headers']
            story.append(Paragraph(f"URL: {headers_data.get('url', 'N/A')}", styles['Normal']))
            story.append(Paragraph(f"Risk Level: {headers_data.get('risk_level', 'LOW')}", risk_style if headers_data.get('risk_level') == 'HIGH' else styles['Normal']))
            story.append(Paragraph(f"Issues Found: {headers_data.get('total_issues', 0)}", styles['Normal']))
            if headers_data.get('issues'):
                for issue in headers_data['issues'][:5]:
                    story.append(Paragraph(f"• {issue['message']}", styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
        
        if scan_data.get('outdated_software'):
            story.append(Paragraph("📦 Outdated Software Detection", heading_style))
            software_data = scan_data['outdated_software']
            story.append(Paragraph(f"URL: {software_data.get('url', 'N/A')}", styles['Normal']))
            story.append(Paragraph(f"Risk Level: {software_data.get('risk_level', 'LOW')}", risk_style if software_data.get('risk_level') == 'HIGH' else styles['Normal']))
            story.append(Paragraph(f"Outdated Components: {software_data.get('outdated_count', 0)}", styles['Normal']))
            if software_data.get('software_found'):
                for sw in software_data['software_found']:
                    status = "OUTDATED" if sw.get('is_outdated') else "UP TO DATE"
                    story.append(Paragraph(f"• {sw['name']}: {sw['version']} ({status})", styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
        
        if scan_data.get('malware'):
            story.append(Paragraph("🦠 Malware Detection", heading_style))
            malware_data = scan_data['malware']
            story.append(Paragraph(f"URL: {malware_data.get('url', 'N/A')}", styles['Normal']))
            story.append(Paragraph(f"Risk Level: {malware_data.get('risk_level', 'LOW')}", risk_style if malware_data.get('risk_level') in ['HIGH', 'LOW_MEDIUM'] else styles['Normal']))
            story.append(Paragraph(f"Issues Found: {malware_data.get('total_issues', 0)}", styles['Normal']))
            if malware_data.get('malware_findings'):
                for finding in malware_data['malware_findings']:
                    story.append(Paragraph(f"• {finding['signature'].replace('_', ' ')}: {finding['description']}", styles['Normal']))
            story.append(Spacer(1, 0.2*inch))
        
        story.append(Paragraph("Security Recommendations", heading_style))
        recommendations = []
        
        if scan_data.get('admin_panel') and scan_data['admin_panel'].get('total_found', 0) > 0:
            recommendations.append("Restrict access to admin panels using IP whitelisting and strong passwords")
        if scan_data.get('security_headers') and scan_data['security_headers'].get('total_issues', 0) > 0:
            recommendations.append("Implement missing security headers (HSTS, CSP, X-Frame-Options)")
        if scan_data.get('outdated_software') and scan_data['outdated_software'].get('outdated_count', 0) > 0:
            recommendations.append("Update outdated software components to latest versions")
        if scan_data.get('malware') and scan_data['malware'].get('total_issues', 0) > 0:
            recommendations.append("Remove malicious code and suspicious elements immediately")
        
        if not recommendations:
            recommendations.append("No immediate security concerns detected. Continue regular monitoring.")
        
        for rec in recommendations:
            story.append(Paragraph(f"• {rec}", styles['Normal']))
        
        story.append(Spacer(1, 0.3*inch))
        
        story.append(Paragraph("This report was generated by SecureGuard - Automated Security Monitoring Platform", styles['Normal']))
        story.append(Paragraph("© 2024 SecureGuard. All rights reserved.", styles['Normal']))
        
        doc.build(story)
        
        pdf_bytes = buffer.getvalue()
        pdf_base64 = base64.b64encode(pdf_bytes).decode('utf-8')
        
        return jsonify({
            'success': True,
            'pdf_base64': pdf_base64,
            'filename': f'secureguard_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf',
            'message': 'PDF report generated successfully'
        })
        
    except Exception as e:
        print(f"Error generating PDF: {str(e)}")
        return jsonify({'error': f'Failed to generate PDF: {str(e)}'}), 500

# ============ AUTHENTICATION ============
def check_password_strength_local(password):
    score = 0
    suggestions = []
    if len(password) >= 12: score += 2
    elif len(password) >= 8: score += 1
    if re.search(r'[A-Z]', password): score += 1
    else: suggestions.append("Add uppercase")
    if re.search(r'[a-z]', password): score += 1
    else: suggestions.append("Add lowercase")
    if re.search(r'\d', password): score += 1
    else: suggestions.append("Add numbers")
    if re.search(r'[!@#$%^&*]', password): score += 1
    else: suggestions.append("Add special chars")
    strength = "STRONG" if score >= 5 else "MEDIUM" if score >= 3 else "WEAK"
    return {'strength': strength, 'score': score, 'suggestions': suggestions}

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.json
        email = data.get('email')
        phone = data.get('phone')
        password = data.get('password')
        
        if not email and not phone:
            return jsonify({'error': 'Email or phone required'}), 400
        
        password_check = check_password_strength_local(password)
        if password_check['strength'] == 'WEAK':
            return jsonify({
                'error': 'Password too weak',
                'suggestions': password_check['suggestions']
            }), 400
        
        twofa_secret = pyotp.random_base32()
        
        conn = sqlite3.connect('security.db')
        c = conn.cursor()
        
        try:
            c.execute("INSERT INTO users (email, phone, password, twofa_secret) VALUES (?, ?, ?, ?)",
                     (email, phone, password, twofa_secret))
            conn.commit()
            # Get the last inserted ID
            user_id = c.lastrowid
        except sqlite3.IntegrityError:
            return jsonify({'error': 'User already exists'}), 400
        
        conn.close()
        
        # FIX: Save activity log with correct user_id
        save_activity_log(user_id, 'User Registration', f'User registered with email: {email}')
        
        return jsonify({
            'message': 'User registered successfully',
            'twofa_secret': twofa_secret,
            'qr_data': f'otpauth://totp/SecureGuard:{email}?secret={twofa_secret}&issuer=SecureGuard'
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        twofa_code = data.get('twofa_code')
        
        conn = sqlite3.connect('security.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email=? OR phone=?", (username, username))
        user = c.fetchone()
        conn.close()
        
        if not user:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if user[3] != password:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        if user[5] == 1:
            if not twofa_code:
                return jsonify({'require_2fa': True}), 200
            
            totp = pyotp.TOTP(user[4])
            if not totp.verify(twofa_code):
                return jsonify({'error': 'Invalid 2FA code'}), 401
        
        access_token = create_access_token(identity=user[0])
        
        save_activity_log(user[0], 'User Login', f'User logged in')
        
        return jsonify({
            'access_token': access_token,
            'user': {
                'id': user[0],
                'email': user[1],
                'phone': user[2]
            }
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/enable-2fa', methods=['POST'])
@jwt_required()
def enable_2fa():
    try:
        user_id = get_jwt_identity()
        
        conn = sqlite3.connect('security.db')
        c = conn.cursor()
        c.execute("UPDATE users SET twofa_enabled=1 WHERE id=?", (user_id,))
        conn.commit()
        conn.close()
        
        save_activity_log(user_id, '2FA Enabled', 'Two-factor authentication enabled')
        
        return jsonify({'message': '2FA enabled successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============ HEALTH CHECK ============
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy', 'service': 'SecureGuard Backend'})

if __name__ == '__main__':
    print("🚀 SecureGuard Backend Starting...")
    print("📡 Running on: http://localhost:5000")
    print("✅ API Endpoints:")
    print("   POST /api/scan/admin-panel - Check for exposed admin panels")
    print("   POST /api/scan/misconfigurations - Check security headers")
    print("   POST /api/scan/outdated-software - Check for outdated CMS and libraries")
    print("   POST /api/scan/malware - Scan for malware and malicious code")
    print("   GET  /api/scan-history - Get scan history")
    print("   GET  /api/activity-logs - Get activity logs")
    print("   POST /api/clear-history - Clear scan history")
    print("   POST /api/ml-risk-score - Calculate ML-based risk assessment")
    print("   POST /api/export-report - Export security report as PDF")
    print("   POST /api/check-password - Check password strength")
    print("   POST /api/register - Register new user")
    print("   POST /api/login - Login with 2FA")
    print("   POST /api/enable-2fa - Enable 2FA (requires JWT)")
    
    app.run(debug=True, port=5000)