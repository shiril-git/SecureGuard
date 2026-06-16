# 🛡️ SecureGuard - Security Dashboard

## Overview

SecureGuard is a web-based cybersecurity dashboard designed to help users analyze website security, detect vulnerabilities, and assess overall risk using multiple security scanning modules and machine learning-based risk assessment.

The dashboard provides an interactive interface for security monitoring, vulnerability detection, password analysis, scan history management, and report generation.

---

## Features

### 🔐 User Authentication
- User Registration
- Secure Login
- Two-Factor Authentication (2FA) Support
- JWT-based Authentication
- Session Management

### 🔍 Security Scanning Modules

#### 1. Admin Panel Detection
- Detects exposed administrative panels
- Identifies common admin endpoints
- Risk-level assessment

#### 2. Security Header Analysis
- Checks for missing security headers
- Detects security misconfigurations
- Provides security recommendations

#### 3. Outdated Software Detection
- Identifies website technologies
- Detects outdated software versions
- Suggests updates and patches

#### 4. Malware Detection
- Detects suspicious scripts
- Identifies malicious patterns
- Detects phishing indicators
- Scans for cryptomining signatures

### 🤖 Machine Learning Risk Assessment
- Calculates overall security risk score
- Uses collected scan results
- Generates risk probabilities
- Provides confidence metrics

### 🔐 Password Strength Checker
- Evaluates password strength
- Provides security recommendations
- Scores passwords based on complexity

### 📄 PDF Report Generation
- Export comprehensive security reports
- Download scan results in PDF format

### 📜 Activity & History Tracking
- Scan history management
- User activity logging
- Historical risk analysis

---

## Technologies Used

### Frontend
- HTML5
- CSS3
- JavaScript (Vanilla JS)

### Security Features
- JWT Authentication
- Two-Factor Authentication (2FA)
- Password Strength Validation

### Backend Integration
- REST API Communication
- JSON Data Exchange
- Security Scanning Services

### Machine Learning
- Risk Prediction Model
- Security Risk Classification
- Probability-Based Analysis

---SecureGuard/
│
├── dashboard.html
├── README.md
│
├── Authentication
│ ├── Login
│ ├── Registration
│ └── 2FA Verification
│
├── Security Modules
│ ├── Admin Panel Scanner
│ ├── Header Checker
│ ├── Software Detection
│ └── Malware Scanner
│
├── ML Risk Assessment
│
├── Report Generation
│
└── Activity Logging


---

## API Endpoints Used

| Endpoint | Function |
|-----------|-----------|
| `/api/login` | User Login |
| `/api/register` | User Registration |
| `/api/check-password` | Password Analysis |
| `/api/scan/admin-panel` | Admin Panel Detection |
| `/api/scan/misconfigurations` | Security Header Analysis |
| `/api/scan/outdated-software` | Software Detection |
| `/api/scan/malware` | Malware Detection |
| `/api/ml-risk-score` | ML Risk Assessment |
| `/api/export-report` | PDF Report Generation |
| `/api/scan-history` | Scan History |
| `/api/activity-logs` | Activity Logs |

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/shiril-git/secureguard.git
Open the project folder:
cd secureguard
Configure the backend API URL:
const API_BASE = 'http://localhost:5000';
Start the backend server.
Open dashboard.html in a web browser.
Usage
Register a new account.
Log in to the dashboard.
Enter a target website URL.
Run security scans.
Review identified vulnerabilities.
Generate ML-based risk scores.
Export security reports as PDF.
Monitor scan history and activity logs.
Security Objectives
Identify exposed attack surfaces
Detect configuration weaknesses
Monitor software vulnerabilities
Analyze malware indicators
Improve password security
Generate actionable security recommendations
Future Enhancements
Real-time monitoring
Email alerts
Vulnerability database integration
Threat intelligence feeds
Multi-user administration
Advanced AI-powered threat detection
Author

Developed as a Cybersecurity and Machine Learning Project.

License

This project is intended for educational and research purposes.

