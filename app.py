from flask import Flask, render_template, request
import joblib
import numpy as np
from urllib.parse import urlparse
import re, socket, requests, tldextract
from bs4 import BeautifulSoup
from datetime import datetime
from collections import Counter

# Optional imports
try:
    import whois
except:
    whois = None
try:
    import dns.resolver
except:
    dns = None

app = Flask(__name__)

# === Load Model and Features ===
model = joblib.load('best_phishing_model.joblib')
feature_list = joblib.load('feature_tolist.joblib')

HEADERS = {"User-Agent": "Mozilla/5.0"}
HTTP_TIMEOUT = 4


# === Utility Functions ===
def has_ip_address(domain):
    try:
        socket.inet_aton(domain)
        return True
    except:
        return False


def get_domain_age(domain):
    """Returns age of domain in days"""
    try:
        w = whois.whois(domain)
        if w.creation_date:
            creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            if isinstance(creation, datetime):
                return (datetime.now() - creation).days
        return -1
    except:
        return -1


def has_dns_record(domain):
    try:
        dns.resolver.resolve(domain, 'A')
        return 1
    except:
        return 0


def get_website_traffic(domain):
    """Placeholder for Alexa-like check"""
    try:
        url = f"https://data.alexa.com/data?cli=10&dat=s&url={domain}"
        response = requests.get(url, timeout=2)
        if "<POPULARITY" in response.text:
            return 1
        return 0
    except:
        return 0


# === Main Feature Extraction ===
def extract_features(url):
    if not url.startswith("http"):
        url = "http://" + url
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path or ""

    features = {}

    # Basic lexical features
    features['UsingIP'] = 1 if has_ip_address(domain) else 0
    features['LongURL'] = 1 if len(url) > 75 else 0
    features['ShortURL'] = 1 if len(url) < 20 else 0
    features['Symbol@'] = 1 if '@' in url else 0
    features['Redirecting//'] = 1 if '//' in path else 0
    features['PrefixSuffix-'] = 1 if '-' in domain else 0

    # Subdomain count
    t = tldextract.extract(domain)
    subdomain = t.subdomain
    features['SubDomains'] = len(subdomain.split('.')) if subdomain else 0

    # HTTPS
    features['HTTPS'] = 1 if parsed.scheme == 'https' else 0

    # Domain registration length (approx)
    features['DomainRegLen'] = get_domain_age(domain)

    # Favicon
    features['Favicon'] = 0

    # Non-standard port
    features['NonStdPort'] = 1 if ':' in domain else 0

    # HTTPS in domain URL
    features['HTTPSDomainURL'] = 1 if 'https' in domain else 0

    # Request URL and anchor analysis
    try:
        r = requests.get(url, headers=HEADERS, timeout=HTTP_TIMEOUT)
        html = r.text
        soup = BeautifulSoup(html, "html.parser")

        total_links = len(soup.find_all('a'))
        same_domain_links = len([a for a in soup.find_all('a', href=True) if domain in a['href']])
        features['RequestURL'] = 1 if same_domain_links < (total_links / 2 if total_links else 1) else 0
        features['AnchorURL'] = 1 if '#' in html else 0
    except:
        features['RequestURL'] = 0
        features['AnchorURL'] = 0

    # Other heuristic placeholders
    features.update({
        'LinksInScriptTags': 0,
        'ServerFormHandler': 0,
        'InfoEmail': 1 if re.search(r"mailto:", url) else 0,
        'AbnormalURL': 0,
        'WebsiteForwarding': 0,
        'StatusBarCust': 0,
        'DisableRightClick': 0,
        'UsingPopupWindow': 0,
        'IframeRedirection': 0,
        'AgeofDomain': get_domain_age(domain),
        'DNSRecording': has_dns_record(domain),
        'WebsiteTraffic': get_website_traffic(domain),
        'PageRank': 0,
        'GoogleIndex': 1 if 'google' in domain else 0,
        'LinksPointingToPage': 0,
        'StatsReport': 0
    })

    # Align features with training order
    values = [features.get(f, 0) for f in feature_list]

    return np.array(values).reshape(1, -1)


# === Flask Routes ===
@app.route('/')
def home():
    return render_template('index.html')


@app.route('/predict', methods=['POST'])
def predict():
    url = request.form.get('url', '').strip()
    if not url:
        return render_template('index.html', prediction_text="⚠️ Please enter a valid URL.")

    features = extract_features(url)

    expected = getattr(model, 'n_features_in_', None)
    if expected and features.shape[1] != expected:
        return render_template('index.html',
                               prediction_text=f"⚠️ Feature mismatch: expected {expected}, got {features.shape[1]}")

    prediction = model.predict(features)[0]
    output = "🚨 Phishing Website Detected!" if prediction == 1 else "✅ Safe Website"

    return render_template('index.html', prediction_text=output, url=url)


if __name__ == '__main__':
    app.run(debug=True)
