from flask import Flask, render_template, jsonify, request
from scapy.all import Dot11, Dot11Beacon, sniff
import threading
import time
import os
import numpy as np
from PIL import Image
import re
import pyperclip # Still useful if we want a local desktop version, but not directly for web input.

app = Flask(__name__)
suspicious_networks = []

# --- Wi-Fi Scanning Logic (from original main.py) ---
def packet_handler(packet):
    if packet.haslayer(Dot11Beacon):
        ssid = packet[Dot11].info.decode('utf-8', errors='ignore')
        bssid = packet[Dot11].addr2
        # Basic checks for suspicious networks
        # Add a check to avoid duplicates based on BSSID
        if not any(net['bssid'] == bssid for net in suspicious_networks):
            if not ssid or ssid.strip() == "" or ssid.lower() in ["free wifi", "public wifi", "default", "linksys", "netgear"]:
                suspicious_networks.append({
                    'ssid': ssid if ssid and ssid.strip() != "" else 'Hidden/Common Fake',
                    'bssid': bssid,
                    'reason': "Suspicious open network or common fake SSID"
                })

def scan_thread():
    # Only run if on Linux and wlan0 is likely available
    if os.name == 'posix':
        print("[*] Starting Wi-Fi scanning thread. Requires 'wlan0' interface and root/sudo privileges.")
        while True:
            global suspicious_networks
            suspicious_networks = [] # Clear previous scans
            try:
                # Set store=0 to not store packets in memory, reducing memory usage
                sniff(iface="wlan0", prn=packet_handler, timeout=10, store=0)
            except Exception as e:
                print(f"[❌] Error during Wi-Fi scan: {e}. Make sure 'wlan0' exists and you have permissions (e.g., run with sudo).")
                break # Exit thread if an error occurs, or handle more gracefully
            time.sleep(30) # Scan every 30 seconds
    else:
        print("[*] Wi-Fi scanning is only supported on Linux with 'wlan0'. Skipping.")

# --- LSB Steganography Detection Logic (from index.py) ---
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def detect_lsb_steganography_logic(image_path):
    try:
        img = Image.open(image_path)
        img = img.convert('RGB')
    except Exception as e:
        return {"status": "error", "message": f"Error opening image: {e}"}

    pixels = np.array(img)
    height, width, _ = pixels.shape

    lsb_counts = {0: 0, 1: 0, 2: 0, 3: 0}

    for y in range(height):
        for x in range(width):
            r, g, b = pixels[y, x]
            lsb_r = r & 1
            lsb_g = g & 1
            lsb_b = b & 1
            lsb_sum = lsb_r + lsb_g + lsb_b
            lsb_counts[lsb_sum] += 1

    total = sum(lsb_counts.values())
    if total == 0: # Avoid division by zero
        return {"status": "info", "message": "No pixels to analyze."}

    distribution = {
        f"{bits_set} bits set": {"count": lsb_counts[bits_set], "percentage": (lsb_counts[bits_set] / total) * 100}
        for bits_set in range(4)
    }

    values = list(lsb_counts.values())
    avg = sum(values) / 4
    variance = sum((v - avg) ** 2 for v in values) / 4
    threshold = 0.01 * total ** 2 # Original threshold logic

    result_message = ""
    status = "safe"

    # Add a more robust heuristic, considering the variance relative to the total number of pixels.
    # A perfectly uniform distribution would have variance close to 0.
    # Steganography tends to make the LSB distribution more uniform.
    if variance < threshold and total > 1000: # Ensure enough pixels for meaningful variance
        result_message = "Suspiciously uniform LSB distribution detected — Possible LSB steganography."
        status = "suspicious"
    else:
        result_message = "No strong evidence of LSB steganography found."

    return {
        "status": status,
        "message": result_message,
        "distribution": distribution
    }

# --- Phishing Detection Logic (from main1.py, adapted for web input) ---
MAX_URL_LENGTH = 80 # Customize the URL length threshold

def is_phishing_logic(url):
    reasons = []
    # Check if it starts with http (not https)
    if url.lower().startswith("http://"):
        reasons.append("Insecure HTTP detected.")
    if len(url) > MAX_URL_LENGTH:
        reasons.append(f"Unusually long URL ({len(url)} characters).")
    # Basic check for common phishing keywords (can be expanded)
    if any(keyword in url.lower() for keyword in ["login", "verify", "account", "secure", "paypal", "bank", "update"]):
        reasons.append("Contains suspicious keywords.")
    # Check for IP address in hostname (often used in phishing)
    if re.match(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?', url):
        reasons.append("Uses IP address instead of domain name.")
    # Check for multiple subdomains or unusual subdomain patterns
    domain_parts = url.split('//')[-1].split('/')[0].split('.')
    if len(domain_parts) > 3: # e.g., www.malicious.legit-site.com
        reasons.append("Excessive subdomains or unusual domain structure.")

    if reasons:
        return True, " ".join(reasons)
    return False, "Appears safe."

# --- Flask Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/steganography_check', methods=['POST'])
def steganography_check():
    if 'image' not in request.files:
        return jsonify({"status": "error", "message": "No image file provided."}), 400
    file = request.files['image']
    if file.filename == '':
        return jsonify({"status": "error", "message": "No selected image file."}), 400
    if file:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)
        result = detect_lsb_steganography_logic(filepath)
        os.remove(filepath) # Clean up the uploaded file
        return jsonify(result)
    return jsonify({"status": "error", "message": "Failed to process image."}), 500

@app.route('/check_phishing', methods=['POST'])
def check_phishing():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({"status": "invalid", "message": "Please enter a URL."}), 400

    is_phishing, reason = is_phishing_logic(url)
    if is_phishing:
        return jsonify({
            "status": "phishing",
            "message": f"⚠️ Phishing Risk Detected! {reason}",
            "url": url
        })
    else:
        return jsonify({
            "status": "safe",
            "message": f"✅ '{url}' appears safe.",
            "url": url
        })

@app.route('/scan') # Existing Wi-Fi scan route
def scan():
    return jsonify(suspicious_networks)

if __name__ == '__main__':
    # Start scanning thread only if on Linux
    if os.name == 'posix':
        threading.Thread(target=scan_thread, daemon=True).start()
    else:
        print("Wi-Fi scanning thread not started. This feature is for Linux only.")

    app.run(host='0.0.0.0', port=5000, debug=True) # debug=True for development