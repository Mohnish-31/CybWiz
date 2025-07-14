from flask import Flask, render_template, jsonify
from scapy.all import Dot11, Dot11Beacon, sniff
import threading
import time

app = Flask(__name__)
suspicious_networks = []

def packet_handler(packet):
    if packet.haslayer(Dot11Beacon):
        ssid = packet[Dot11].info.decode('utf-8', errors='ignore')
        bssid = packet[Dot11].addr2
        if not ssid or ssid in ["Free WiFi", "Public WiFi"]:
            suspicious_networks.append({
                'ssid': ssid or 'Hidden',
                'bssid': bssid,
                'reason': "Suspicious open network" if not ssid else "Common fake SSID"
            })

def scan_thread():
    while True:
        global suspicious_networks
        suspicious_networks = []
        sniff(iface="wlan0", prn=packet_handler, timeout=10)
        time.sleep(30) # Scan every 30 seconds

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan')
def scan():
    return jsonify(suspicious_networks)

if __name__ == '__main__':
    # Start scanning thread
    threading.Thread(target=scan_thread, daemon=True).start()
    app.run(host='0.0.0.0', port=5000)