# Password Security Analysis Tool 🔐

A comprehensive Chrome extension designed for **Password Vulnerability Assessment and Penetration Testing (VAPT)**. This tool simulates real-world attack strategies (Brute-Force, Dictionary, and Rule-Based) to evaluate credential resilience while implementing advanced client-side anti-tampering protections.

---

## 🌟 Key Features

### 1. Advanced Attack Simulations
*   **Brute-Force Attack**: Custom charset selection (a-z, A-Z, 0-9, Symbols) and adjustable maximum length.
*   **Dictionary Attack**: Supports default 10k wordlists or custom `.txt` dictionary uploads.
*   **Rule-Based Attack**: Implements common password patterns (e.g., appending numbers, leet-speak) to simulate sophisticated cracking.

### 2. High-Performance Engine
*   Uses **Web Workers** for background processing, ensuring the browser UI remains responsive during high-velocity attacks.
*   Real-time metrics for **APS (Attempts Per Second)**, elapsed time, and current progress.

### 3. Professional Security Reporting
*   Generates detailed **Security Audit Reports** with session metadata, performance metrics, and audit results.
*   Clean, printable layout designed for professional documentation and FYP presentations.

---

## 🛡️ Anti-Tampering & Security Hardening
This extension is built with a "Defense-in-Depth" approach to protect itself from manual manipulation during a VAPT audit:

*   **DOM Integrity Monitoring**: Uses `MutationObserver` to detect and automatically revert unauthorized UI changes (e.g., trying to enable buttons via DevTools).
*   **Storage Poisoning Protection**: Validates all data from `chrome.storage.local` to prevent XSS and malicious data injection.
*   **Secure Coding Sinks**: Implements strict `textContent` and safe DOM construction to eliminate XSS vulnerabilities.
*   **Deterrents**: Blocks keyboard shortcuts (F12, Ctrl+Shift+I) and context menus to frustrate manual inspection.

---

## 🚀 Installation

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
    ```
2.  **Open Chrome Extensions**:
    *   Navigate to `chrome://extensions`.
    *   Enable **Developer mode** (top right).
3.  **Load the Extension**:
    *   Click **Load unpacked**.
    *   Select the project folder.

---

## 📸 Testing the Defenses
To demonstrate the security hardening:
1.  Open the extension popup.
    *   *Note: Standard DevTools shortcuts are blocked.*
2.  Right-click the extension icon and select **"Inspect popup"**.
3.  Try to delete a button or change a text label in the "Elements" tab.
4.  Observe the extension **detect and revert** the change while displaying a security warning.

---

## 📜 Disclaimer
This tool is developed for **educational and auditing purposes only**. Always ensure you have explicit permission before performing security assessments on any system or website.

---
**Developed for Final Year Project (FYP) - Cybersecurity Research**
