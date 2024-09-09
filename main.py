from flask import Flask, render_template, request
import requests
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, redirect, url_for
import psutil
import logging

app = Flask(__name__)
# Setup logging
logging.basicConfig(filename="vulnerability_scanner_log.log", level=logging.INFO)


# System Vulnerability Scanner
def check_system_vulnerabilities():
    vulnerabilities = []
    # Check open ports (3389, 445, and 135 are commonly targeted ports)
    open_ports = [conn.laddr.port for conn in psutil.net_connections() if conn.status == 'LISTEN']
    risky_ports = [3389, 445, 135]
    found_risky_ports = [port for port in open_ports if port in risky_ports]
    if found_risky_ports:
        vulnerabilities.append(f"Open vulnerable ports found: {found_risky_ports}")

    # Check for antivirus running (example vulnerability check)
    antivirus_running = False
    for process in psutil.process_iter():
        if "antivirus" in process.name().lower():
            antivirus_running = True
            break
    if not antivirus_running:
        vulnerabilities.append("No antivirus detected. This could be a vulnerability.")

    if not vulnerabilities:
        vulnerabilities.append("No significant vulnerabilities found.")

    logging.info("Vulnerability scan completed.")
    return vulnerabilities


# Route for vulnerability scanning page
@app.route('/vulnerability_scan')
def vulnerability_scan():
    vulnerabilities = check_system_vulnerabilities()
    return render_template('vulnerability_scan.html', vulnerabilities=vulnerabilities)
# Recommendations for improving privacy
RECOMMENDATIONS = [
    "Consider using a VPN to mask your IP address.",
    "Disable third-party cookies in your browser settings.",
    "Use browser extensions like uBlock Origin to block trackers.",
    "Regularly clear your cookies and browser cache.",
    "Use privacy-focused search engines like DuckDuckGo."
]

# Function to check for tracking patterns
def analyze_privacy(url):
    results = {
        "cookies": False,
        "trackers": [],
        "recommendations": []
    }

    try:
        # Fetch the HTML content of the webpage
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')

        # Check for cookies
        cookies = response.cookies
        if cookies:
            results["cookies"] = True

        # Check for trackers in the HTML <script> tags
        scripts = soup.find_all('script', src=True)
        tracker_domains = ['google-analytics.com', 'doubleclick.net', 'facebook.net', 'adservice.google.com']
        for script in scripts:
            for tracker in tracker_domains:
                if tracker in script['src']:
                    results["trackers"].append(tracker)

        # Add recommendations based on detected elements
        if results["cookies"]:
            results["recommendations"].append("This site uses cookies. " + RECOMMENDATIONS[1])

        if results["trackers"]:
            results["recommendations"].append("Trackers detected: " + ", ".join(results["trackers"]))
            results["recommendations"].append(RECOMMENDATIONS[2])

        # General VPN recommendation
        results["recommendations"].append(RECOMMENDATIONS[0])

    except Exception as e:
        results["error"] = f"Failed to analyze the site: {e}"

    return results

# Home page route
@app.route('/')
def home():
    return render_template('home.html')

# Analyze route to handle form input
@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.form['url']
    if not url.startswith('http'):
        url = 'http://' + url  # Ensure URL has http/https
    results = analyze_privacy(url)
    return render_template('result.html', url=url, results=results)

if __name__ == '__main__':
    app.run(debug=True)
