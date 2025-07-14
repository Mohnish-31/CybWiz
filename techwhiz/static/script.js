const BREACH_API_URL = "http://127.0.0.1:8000/check_breach"; // FastAPI breach_detector.py
const FLASK_API_URL = "http://127.0.0.1:5000"; // Flask main.py

function showSection(sectionId) {
    const sections = document.querySelectorAll('.content-area section');
    sections.forEach(section => {
        section.classList.remove('active-section');
        section.classList.add('hidden-section');
    });

    const activeSection = document.getElementById(sectionId + '-section');
    if (activeSection) {
        activeSection.classList.remove('hidden-section');
        activeSection.classList.add('active-section');
    }

    const backButton = document.querySelector('.back-button');
    if (sectionId === 'dashboard') {
        backButton.style.display = 'none';
    } else {
        backButton.style.display = 'block';
    }
}

// Initial load: show dashboard
document.addEventListener('DOMContentLoaded', () => {
    showSection('dashboard');
});

// --- Data Breach Check ---
async function checkBreach() {
    const query = document.getElementById('breachInput').value.trim();
    const resultBox = document.getElementById('breachResult');
    resultBox.innerHTML = '<p>Checking for breaches...</p>';
    resultBox.className = 'result-box'; // Reset class

    try {
        const response = await fetch(BREACH_API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ query: query }),
        });
        const data = await response.json();

        resultBox.innerHTML = `<p>${data.message}</p>`;
        resultBox.classList.add(`status-${data.status}`);

    } catch (error) {
        console.error('Error checking breach:', error);
        resultBox.innerHTML = '<p>❌ An error occurred. Please try again later.</p>';
        resultBox.classList.add('status-error');
    }
}

// --- LSB Steganography Detection ---
async function uploadStegoImage() {
    const fileInput = document.getElementById('stegoImageUpload');
    const fileNameDisplay = document.getElementById('stegoFileName');
    const resultBox = document.getElementById('stegoResult');

    if (fileInput.files.length === 0) {
        fileNameDisplay.textContent = 'No file chosen';
        return;
    }

    const file = fileInput.files[0];
    fileNameDisplay.textContent = file.name;
    resultBox.innerHTML = '<p>Analyzing image for steganography...</p>';
    resultBox.className = 'result-box'; // Reset class

    const formData = new FormData();
    formData.append('image', file);

    try {
        const response = await fetch(`${FLASK_API_URL}/steganography_check`, {
            method: 'POST',
            body: formData,
        });
        const data = await response.json();

        let messageHtml = `<p>${data.message}</p>`;
        if (data.distribution) {
            messageHtml += '<p><strong>LSB Bit Count Distribution:</strong></p>';
            for (const key in data.distribution) {
                const item = data.distribution[key];
                messageHtml += `<p>&nbsp;&nbsp;${key}: ${item.count} pixels (${item.percentage.toFixed(2)}%)</p>`;
            }
        }
        resultBox.innerHTML = messageHtml;
        resultBox.classList.add(`status-${data.status}`);

    } catch (error) {
        console.error('Error detecting steganography:', error);
        resultBox.innerHTML = '<p>❌ An error occurred during detection. Please try again.</p>';
        resultBox.classList.add('status-error');
    }
}

// --- Wi-Fi Scan ---
let wifiScanInterval; // To store the interval ID

async function startWifiScan() {
    const resultBox = document.getElementById('wifiScanResult');
    resultBox.innerHTML = '<p>Scanning for suspicious Wi-Fi networks... (This may take a few seconds and requires backend to run with sudo on Linux)</p>';
    resultBox.className = 'result-box';

    // Clear previous interval if any
    if (wifiScanInterval) {
        clearInterval(wifiScanInterval);
    }

    // Fetch immediately, then every 10 seconds
    fetchWifiScanResults();
    wifiScanInterval = setInterval(fetchWifiScanResults, 10000); // Poll every 10 seconds
}

async function fetchWifiScanResults() {
    const resultBox = document.getElementById('wifiScanResult');
    try {
        const response = await fetch(`${FLASK_API_URL}/scan`);
        const data = await response.json();

        if (data.length === 0) {
            resultBox.innerHTML = '<p>✅ No suspicious Wi-Fi networks found in the last scan.</p>';
            resultBox.classList.add('status-safe');
        } else {
            let networksHtml = '<p>⚠️ Found suspicious Wi-Fi networks:</p><ul>';
            data.forEach(net => {
                networksHtml += `<li><strong>SSID:</strong> ${net.ssid} | <strong>BSSID:</strong> ${net.bssid} | <strong>Reason:</strong> ${net.reason}</li>`;
            });
            networksHtml += '</ul>';
            resultBox.innerHTML = networksHtml;
            resultBox.classList.add('status-breached'); // Using 'breached' status for suspicious networks
        }
    } catch (error) {
        console.error('Error fetching Wi-Fi scan results:', error);
        resultBox.innerHTML = '<p>❌ Error fetching Wi-Fi scan results. Ensure the Flask backend is running and has permissions (e.g., sudo).</p>';
        resultBox.classList.add('status-error');
    }
}

// Optional: Stop scanning when leaving the Wi-Fi section
document.getElementById('wifi-scan-section').addEventListener('transitionend', (event) => {
    if (!event.target.classList.contains('active-section')) {
        if (wifiScanInterval) {
            clearInterval(wifiScanInterval);
            wifiScanInterval = null;
            console.log("Stopped Wi-Fi scanning interval.");
        }
    }
});


// --- Phishing URL Check ---
async function checkPhishing() {
    const url = document.getElementById('phishingInput').value.trim();
    const resultBox = document.getElementById('phishingResult');
    resultBox.innerHTML = '<p>Checking URL for phishing indicators...</p>';
    resultBox.className = 'result-box'; // Reset class

    if (!url) {
        resultBox.innerHTML = '<p>❌ Please enter a URL.</p>';
        resultBox.classList.add('status-invalid');
        return;
    }

    try {
        const response = await fetch(`${FLASK_API_URL}/check_phishing`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url }),
        });
        const data = await response.json();

        resultBox.innerHTML = `<p>${data.message}</p>`;
        resultBox.classList.add(`status-${data.status}`);

    } catch (error) {
        console.error('Error checking phishing URL:', error);
        resultBox.innerHTML = '<p>❌ An error occurred. Please try again later.</p>';
        resultBox.classList.add('status-error');
    }
}