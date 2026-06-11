# Vulnerability Scanner & AI Chatbot Finder

A collection of security tools for identifying AI chatbots and performing OWASP Top 10 vulnerability scans on domains, IPs, and Postman collections.

## Features

### 1. AI Chatbot Detection
- **`detect_chatbot.py`**: Fast static analysis for common chatbot providers (Intercom, Drift, Zendesk, etc.).
- **`detect_chatbot_pro.py`**: Advanced dynamic analysis using Playwright to identify hidden or custom AI integrations (Amelia, Amazon Lex, etc.).

### 2. OWASP Top 10 Scanner
- **`owasp_scanner.py`**: Unified scanner that orchestrates Nmap, Nuclei, and Nikto.
- **Bulk Scanning**: Supports lists of IPs/Domains from a file.
- **API Testing**: Automatically parses **Postman Collections** and scans API endpoints for vulnerabilities.

## Installation

### Prerequisites
Ensure you have the following tools installed on your system:
- `nmap`
- `nuclei`
- `nikto`
- `python3` & `pip`

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/darkshell809/vuln-scanner-pro.git
   cd vuln-scanner-pro
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Install Playwright browser:
   ```bash
   python3 -m playwright install chromium
   ```

## Usage

### Detect Chatbots
```bash
# Basic check
python3 detect_chatbot.py https://example.com

# Dynamic check (more accurate)
python3 detect_chatbot_pro.py https://example.com
```

### Vulnerability Scan
```bash
# Scan a single domain
python3 owasp_scanner.py -u example.com

# Scan a list of targets
python3 owasp_scanner.py -l targets.txt

# Scan API from Postman collection
python3 owasp_scanner.py -p collection.json --deep

# You can even combine a list of IPs, a single URL, and a Postman collection all at once
python3 owasp_scanner.py -l targets.txt -u example.com -p collection.json --deep
```

## Disclaimer
These tools are for educational and authorized security testing purposes only. Always obtain permission before scanning targets you do not own.
# vuln-scanner-pro
