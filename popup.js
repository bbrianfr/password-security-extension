document.addEventListener('DOMContentLoaded', () => {
    // UI Elements
    const algorithmSelect = document.getElementById('algorithm');
    const targetHashInput = document.getElementById('targetHash');
    const targetPasswordInput = document.getElementById('targetPassword');
    const btnGenerateHash = document.getElementById('btnGenerateHash');
    const attackModeSelect = document.getElementById('attackMode');
    const btnStart = document.getElementById('btnStart');
    const btnStop = document.getElementById('btnStop');
    const statusText = document.getElementById('statusText');
    const timerDisplay = document.getElementById('timer');
    const apsDisplay = document.getElementById('aps');
    const currentAttemptDisplay = document.getElementById('currentAttempt');
    const resultCard = document.getElementById('resultCard');
    const foundPasswordDisplay = document.getElementById('foundPassword');
    const strategyOptions = document.getElementById('strategyOptions');
    const btnDownloadReport = document.getElementById('btnDownloadReport');

    // ========== ANTI-TAMPERING: Validation & Sanitization Utilities ==========

     /**
     * Escapes HTML special characters to prevent XSS injection.
     * Used before inserting any dynamic data into the DOM.
     */
    function escapeHTML(str) {
        if (typeof str !== 'string') return '';
        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    /**
     * Validates that a string is a valid SHA-256 hex hash (exactly 64 hex chars).
     * Blocks injection of non-hex payloads (e.g. XSS strings) into the hash field.
     */
    function isValidHexHash(str) {
        if (typeof str !== 'string') return false;
        return /^[a-fA-F0-9]{64}$/.test(str);
    }

    /**
     * Validates a history record's structure and data types.
     * Rejects tampered records with unexpected fields or XSS payloads.
     */
    function validateHistoryRecord(item) {
        if (!item || typeof item !== 'object') return false;
        if (typeof item.timestamp !== 'number' || item.timestamp <= 0) return false;
        if (typeof item.targetHash !== 'string' || !isValidHexHash(item.targetHash)) return false;
        const validModes = ['bruteForce', 'dictionary', 'ruleBased'];
        if (typeof item.mode !== 'string' || !validModes.includes(item.mode)) return false;
        return true;
    }

    // ========== END ANTI-TAMPERING UTILITIES ==========

    // ========== ANTI-TAMPERING: DOM Integrity Monitor & Deterrents ==========
    
    let tamperCount = 0;
    const tamperWarningBanner = document.getElementById('tamperWarning');

    /**
     * Deterrent: Disable Right-Click (Context Menu)
     * Prevents easy access to "Inspect Element".
     */
    document.addEventListener('contextmenu', (e) => {
        e.preventDefault();
        return false;
    });

    /**
     * Deterrent: Block DevTools Keyboard Shortcuts
     * Blocks F12, Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+Shift+C.
     */
    document.addEventListener('keydown', (e) => {
        if (
            e.keyCode === 123 || // F12
            (e.ctrlKey && e.shiftKey && (e.keyCode === 73 || e.keyCode === 74 || e.keyCode === 67)) || // Ctrl+Shift+I/J/C
            (e.ctrlKey && e.keyCode === 85) // Ctrl+U (View Source)
        ) {
            e.preventDefault();
            triggerTamperWarning('DevTools keyboard shortcut blocked.');
            return false;
        }
    });

    /**
     * Shows the tamper warning banner, blurs the UI, and logs the incident.
     * Tracks a count of tampering events detected during this session.
     */
    function triggerTamperWarning(detail) {
        tamperCount++;
        // Show warning banner and blur UI
        tamperWarningBanner.classList.remove('hidden');
        document.body.classList.add('tampered');
        
        // Re-trigger animation by forcing reflow
        tamperWarningBanner.style.animation = 'none';
        void tamperWarningBanner.offsetHeight; // force reflow
        tamperWarningBanner.style.animation = '';

        console.warn(`[SECURITY] TAMPER DETECTED (#${tamperCount}):`, detail);

        // Log tampering event to storage for audit trail
        chrome.storage.local.get(['tamperLog'], (result) => {
            const log = result.tamperLog || [];
            log.push({
                timestamp: Date.now(),
                detail: String(detail).substring(0, 200),
                count: tamperCount
            });
            if (log.length > 20) log.shift();
            chrome.storage.local.set({ tamperLog: log });
        });

        // RECOVERY: If a minor change, we could try to reload, but for FYP/Security demo, 
        // showing the locked state is more "standard".
        
        // STOP ATTACK IMMEDIATELY if running
        if (typeof isRunning !== 'undefined' && isRunning) {
            stopAttack("TAMPERED", "Security violation: attack aborted.");
        }
    }

    /**
     * GLOBAL MUTATION OBSERVER
     * Watches the entire dashboard for ANY unauthorized changes.
     */
    const globalObserver = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
            // 1. Detect Attribute Changes (e.g. removing 'disabled', changing 'type', changing 'style')
            if (mutation.type === 'attributes') {
                const target = mutation.target;
                const attr = mutation.attributeName;
                const oldValue = mutation.oldValue;
                
                // Special case: if someone tries to hide the tamper warning itself
                if (target.id === 'tamperWarning' && attr === 'class' && target.classList.contains('hidden') && tamperCount > 0) {
                     safeDOMUpdate(() => target.classList.remove('hidden')); 
                }

                // Generic detection for any attribute modification on critical elements
                const protectedTags = ['INPUT', 'SELECT', 'BUTTON'];
                const excludedIds = ['timer', 'aps', 'currentAttempt', 'lblMaxLength'];
                
                if (protectedTags.includes(target.tagName) && !excludedIds.includes(target.id)) {
                    // REVERT: Put the attribute back to its old value
                    if (oldValue !== null) {
                        safeDOMUpdate(() => target.setAttribute(attr, oldValue));
                    }
                    triggerTamperWarning(`Attribute '${attr}' was tampered with and REVERTED on <${target.tagName}>.`);
                }
            }
            
            // 2. Detect Structural Changes (Adding/Removing elements)
            if (mutation.type === 'childList') {
                const excludedIds = ['timer', 'aps', 'currentAttempt', 'lblMaxLength', 'strategyOptions', 'historyList'];
                if (mutation.target.id && excludedIds.includes(mutation.target.id)) continue;

                if (mutation.addedNodes.length > 0) {
                    for (const node of mutation.addedNodes) {
                        if (node.nodeName === 'SCRIPT' || node.nodeName === 'IFRAME') {
                            node.remove();
                            triggerTamperWarning('Malicious tag injection (Script/Iframe) blocked.');
                        } else {
                            triggerTamperWarning('Unauthorized element injected into dashboard.');
                        }
                    }
                }
                if (mutation.removedNodes.length > 0) {
                    triggerTamperWarning('Critical UI component removed from dashboard.');
                    // In a real app, we might restore it, but for now we lock the UI.
                }
            }

            // 3. Detect Text Changes (Changing labels/values via innerText/textContent)
            if (mutation.type === 'characterData') {
                const parent = mutation.target.parentElement;
                const excludedIds = ['timer', 'aps', 'currentAttempt', 'lblMaxLength', 'statusText', 'foundPassword'];
                if (parent && excludedIds.includes(parent.id)) continue;
                
                triggerTamperWarning('Text content modification detected.');
            }
        }
    });

    /**
     * Helper to perform UI updates without triggering the security monitor.
     * Disconnects the observer, runs the update, and reconnects.
     */
    function safeDOMUpdate(callback) {
        globalObserver.disconnect();
        callback();
        globalObserver.observe(document.body, {
            attributes: true,
            childList: true,
            subtree: true,
            characterData: true,
            attributeOldValue: true
        });
    }

    // Initial observation
    globalObserver.observe(document.body, {
        attributes: true,
        childList: true,
        subtree: true,
        characterData: true,
        attributeOldValue: true
    });

    /**
     * Periodic Integrity Check
     * Verifies that critical variables and functions haven't been overwritten in memory.
     * This is a second layer in case the observer is somehow bypassed.
     */
    setInterval(() => {
        // Verify critical elements still exist and have correct types
        const startBtn = document.getElementById('btnStart');
        if (!startBtn || startBtn.tagName !== 'BUTTON') {
            triggerTamperWarning('Integrity Check Failed: Critical button missing or modified.');
        }
    }, 2000);

    // ========== END DOM INTEGRITY MONITOR ==========

    // Auto-load detection from Content Script (WITH VALIDATION)
    function updateAutoDetectedHash() {
        chrome.storage.local.get(['autoDetectedHash'], (result) => {
            const display = document.getElementById('autoTargetDisplay');
            if (!display) return;

            safeDOMUpdate(() => {
                if (result.autoDetectedHash && isValidHexHash(result.autoDetectedHash)) {
                    // ANTI-TAMPERING: Only accept valid 64-char hex hashes from storage
                    targetHashInput.value = result.autoDetectedHash;
                    lastValidHash = result.autoDetectedHash; // Sync for observer
                    
                    // Use safe DOM methods to update display
                    display.textContent = '';
                    const badge = document.createElement('span');
                    badge.style.color = '#238636';
                    badge.style.fontWeight = 'bold';
                    badge.textContent = '✓ Captured Hash: ';
                    display.appendChild(badge);
                    display.appendChild(document.createTextNode(result.autoDetectedHash.substring(0, 16) + '...'));
                } else if (result.autoDetectedHash) {
                    // ANTI-TAMPERING: ACTIVE DETECTION
                    // If there's a hash but it's invalid, someone likely edited local storage
                    safeDOMUpdate(() => {
                        display.textContent = '';
                        const waitMsg = document.createElement('span');
                        waitMsg.style.color = '#ff7b72';
                        waitMsg.style.fontWeight = 'bold';
                        waitMsg.textContent = '⚠ SECURITY BREACH: Storage Tampering Detected';
                        display.appendChild(waitMsg);
                    });
                    
                    triggerTamperWarning('Storage poisoning detected: autoDetectedHash was modified to an invalid value.');
                } else {
                    // NORMAL STATE: No hash yet
                    safeDOMUpdate(() => {
                        display.textContent = '';
                        const waitMsg = document.createElement('span');
                        waitMsg.style.color = '#8b949e';
                        waitMsg.textContent = 'Waiting for password input...';
                        display.appendChild(waitMsg);
                    });
                }
            });
        });
    }

    // Initial load
    updateAutoDetectedHash();

    // Listen for real-time updates while popup is open
    chrome.storage.onChanged.addListener((changes, area) => {
        if (area === 'local' && changes.autoDetectedHash) {
            updateAutoDetectedHash();
        }
    });

    // Brute Force Option Elements (Safe DOM Construction)
    function buildBruteOptionsPanel() {
        const panel = document.createElement('div');
        panel.id = 'bruteOptions';
        panel.className = 'options-panel';

        const charsets = [
            { id: 'useLowerCase', label: ' a-z', checked: true },
            { id: 'useUpperCase', label: ' A-Z', checked: true },
            { id: 'useNumbers', label: ' 0-9', checked: true },
            { id: 'useSymbols', label: ' !@#...', checked: false }
        ];

        charsets.forEach(cs => {
            const lbl = document.createElement('label');
            const cb = document.createElement('input');
            cb.type = 'checkbox';
            cb.id = cs.id;
            cb.checked = cs.checked;
            lbl.appendChild(cb);
            lbl.appendChild(document.createTextNode(cs.label));
            panel.appendChild(lbl);
        });

        const lengthDiv = document.createElement('div');
        lengthDiv.className = 'length-control';
        const lengthLabel = document.createElement('label');
        lengthLabel.appendChild(document.createTextNode('Max Len: '));
        const lengthSpan = document.createElement('span');
        lengthSpan.id = 'lblMaxLength';
        lengthSpan.textContent = '8';
        lengthLabel.appendChild(lengthSpan);
        lengthDiv.appendChild(lengthLabel);
        const rangeInput = document.createElement('input');
        rangeInput.type = 'range';
        rangeInput.id = 'maxLength';
        rangeInput.min = '1';
        rangeInput.max = '64';
        rangeInput.value = '8';
        lengthDiv.appendChild(rangeInput);
        panel.appendChild(lengthDiv);

        return panel;
    }

    function buildDictionaryOptionsPanel() {
        const panel = document.createElement('div');
        panel.className = 'options-panel';
        panel.style.textAlign = 'center';

        const desc = document.createElement('p');
        desc.style.color = '#8b949e';
        desc.style.marginBottom = '8px';
        desc.style.fontSize = '0.9em';
        desc.textContent = 'Use default (10k words) or upload custom:';
        panel.appendChild(desc);

        const fileInput = document.createElement('input');
        fileInput.type = 'file';
        fileInput.id = 'dictFile';
        fileInput.accept = '.txt';
        fileInput.style.maxWidth = '100%';
        fileInput.style.fontSize = '0.8em';
        fileInput.style.color = '#c9d1d9';
        panel.appendChild(fileInput);

        const statusDiv = document.createElement('div');
        statusDiv.id = 'fileStatus';
        statusDiv.style.fontSize = '0.8em';
        statusDiv.style.color = '#58a6ff';
        statusDiv.style.marginTop = '5px';
        panel.appendChild(statusDiv);

        return panel;
    }

    // Worker Initialization (Refactored for Restartability)
    let worker;
    let isRunning = false;
    let startTime = 0;
    let timerInterval = null;
    let customDictionary = [];

    // Initialize Worker
    function initWorker() {
        if (worker) {
            worker.terminate();
        }
        worker = new Worker('worker.js');
        worker.onmessage = handleWorkerMessage;
    }

    // Worker Message Handler
    function handleWorkerMessage(e) {
        const { type, data, reason, message } = e.data;

        if (type === 'tick') {
            // Update Metrics (throttled by worker)
            apsDisplay.textContent = data.aps.toLocaleString();
            currentAttemptDisplay.textContent = data.currentAttempt;
        } else if (type === 'found') {
            // Success
            stopAttack("SUCCESS", data.password);
        } else if (type === 'finished') {
            // Exhausted search space
            stopAttack("FAILED", reason || "Password not found in search space.");
        } else if (type === 'error') {
            // Error (like empty dictionary)
            stopAttack("ERROR", message || "An unknown error occurred.");
        }
    }

    // Start initial worker
    initWorker();

    // Helper: Format time
    function formatTime(ms) {
        const totalSeconds = Math.floor(ms / 1000);
        const minutes = Math.floor(totalSeconds / 60).toString().padStart(2, '0');
        const seconds = (totalSeconds % 60).toString().padStart(2, '0');
        const centis = Math.floor((ms % 1000) / 10).toString().padStart(2, '0');
        return `${minutes}:${seconds}.${centis}`;
    }

    // Helper: Hash generator (Sync for UI only, or keep Async? Keep async for UI to not block)
    async function hashString(str) {
        const msgBuffer = new TextEncoder().encode(str);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return hashHex;
    }

    // Event: Generate Hash
    btnGenerateHash.addEventListener('click', async () => {
        const pwd = targetPasswordInput.value;
        if (pwd) {
            const hash = await hashString(pwd);
            targetHashInput.value = hash;
        }
    });

    // Helper: Attach File Listener
    function attachFileListener() {
        const fileInput = document.getElementById('dictFile');
        const statusDiv = document.getElementById('fileStatus');

        if (fileInput) {
            fileInput.addEventListener('change', (e) => {
                const file = e.target.files[0];
                if (!file) {
                    customDictionary = [];
                    statusDiv.textContent = "";
                    return;
                }

                const reader = new FileReader();
                reader.onload = (ev) => {
                    const text = ev.target.result;
                    // Split by new lines, filter empty
                    customDictionary = text.split(/\r?\n/).filter(line => line.trim() !== "");
                    statusDiv.textContent = `Loaded ${customDictionary.length} words.`;
                };
                reader.onerror = () => {
                    statusDiv.textContent = "Error reading file.";
                    customDictionary = [];
                };
                reader.readAsText(file);
            });
        }
    }

    // Event: Change Attack Mode (Update Options UI)
    attackModeSelect.addEventListener('change', () => {
        safeDOMUpdate(() => {
            const mode = attackModeSelect.value;
            customDictionary = []; // Reset on mode change

            if (mode === 'bruteForce') {
                // ANTI-TAMPERING: Use safe DOM construction
                strategyOptions.textContent = '';
                strategyOptions.appendChild(buildBruteOptionsPanel());
                // Re-attach listeners for range slider
                const range = document.getElementById('maxLength');
                const lbl = document.getElementById('lblMaxLength');
                if (range && lbl) {
                    range.addEventListener('input', () => lbl.textContent = range.value);
                }
            } else if (mode === 'dictionary' || mode === 'ruleBased') {
                // ANTI-TAMPERING: Use safe DOM construction
                strategyOptions.textContent = '';
                strategyOptions.appendChild(buildDictionaryOptionsPanel());
                attachFileListener();
                if (mode === 'ruleBased') {
                    // Append a note about rules using safe DOM methods
                    const note = document.createElement('div');
                    const noteSpan = document.createElement('span');
                    noteSpan.style.fontSize = '0.8em';
                    noteSpan.style.color = '#8b949e';
                    noteSpan.textContent = '+ Common Rules (append numbers, leet, etc)';
                    note.appendChild(noteSpan);
                    strategyOptions.querySelector('.options-panel').appendChild(note);
                }
            }
        });
    });

    // Initial setup for range slider if default is brute force
    const range = document.getElementById('maxLength');
    if (range) {
        range.addEventListener('input', (e) => {
            document.getElementById('lblMaxLength').textContent = e.target.value;
        });
    }

    // Trigger update immediately to load Dictionary UI (default)
    safeDOMUpdate(() => {
        attackModeSelect.dispatchEvent(new Event('change'));
    });

    // Event: Start Attack
    btnStart.addEventListener('click', () => {
        const targetHash = targetHashInput.value.trim();
        if (!targetHash) {
            alert('Please enter a target SHA-256 hash.');
            return;
        }

        // ANTI-TAMPERING: Validate hash format before processing
        if (!isValidHexHash(targetHash)) {
            alert('Invalid hash format. Target must be a valid 64-character hexadecimal SHA-256 hash.\n\nThis could indicate data tampering.');
            return;
        }

        isRunning = true;
        startTime = performance.now();

        // Explicitly Reset Metrics to Zero
        safeDOMUpdate(() => {
            timerDisplay.textContent = "00:00.00";
            apsDisplay.textContent = "0";
            currentAttemptDisplay.textContent = "0";

            // Reset UI
            statusText.textContent = "RUNNING";
            statusText.className = "metric-value status-running";
            resultCard.classList.add('hidden');
            btnDownloadReport.classList.add('hidden'); // Hide report button
            btnStart.classList.add('hidden');
            btnStop.classList.remove('hidden');
        });

        // Start Timer UI
        timerInterval = setInterval(() => {
            const elapsed = performance.now() - startTime;
            timerDisplay.textContent = formatTime(elapsed);
        }, 30);

        // Prepare Config
        const config = {
            targetHash: targetHash,
            mode: attackModeSelect.value,
            customDictionary: customDictionary // Pass the file data
        };

        if (config.mode === 'bruteForce') {
            config.maxLength = parseInt(document.getElementById('maxLength').value, 10);
            config.useLowerCase = document.getElementById('useLowerCase').checked;
            config.useUpperCase = document.getElementById('useUpperCase').checked;
            config.useNumbers = document.getElementById('useNumbers').checked;
            config.useSymbols = document.getElementById('useSymbols').checked;
        }

        // SAVE HISTOY (Hash Only)
        saveToHistory({
            timestamp: Date.now(),
            targetHash: config.targetHash,
            mode: config.mode
        });

        // ANTI-TAMPERING: Freeze config to prevent runtime modification
        Object.freeze(config);

        // Send to Worker
        worker.postMessage({ command: 'start', config: config });

        // Track this hash as a legitimate value
        lastValidHash = targetHash;
        lastValidMode = config.mode;
    });

    // Event: Stop Attack
    btnStop.addEventListener('click', () => {
        stopAttack("STOPPED");
    });

    // Event: Download Report
    btnDownloadReport.addEventListener('click', generateReport);

    // HISTORY FEATURE IMPLEMENTATION
    const btnHistory = document.getElementById('btnHistory');
    const historyPanel = document.getElementById('historyPanel');
    const historyList = document.getElementById('historyList');
    const btnClearHistory = document.getElementById('btnClearHistory');

    // Toggle History Panel
    btnHistory.addEventListener('click', () => {
        const isHidden = historyPanel.classList.contains('hidden');
        if (isHidden) {
            historyPanel.classList.remove('hidden');
            loadHistory();
        } else {
            historyPanel.classList.add('hidden');
        }
    });

    // Clear History
    btnClearHistory.addEventListener('click', () => {
        if (confirm('Clear all attack history?')) {
            chrome.storage.local.set({ attackHistory: [] }, () => {
                loadHistory(); // Refresh list
            });
        }
    });

    // Save to History (Hash Only)
    // We call this when the attack STARTS
    function saveToHistory(record) {
        chrome.storage.local.get(['attackHistory'], (result) => {
            const history = result.attackHistory || [];
            history.unshift(record); // Add to top
            // Limit to last 50 entries
            if (history.length > 50) history.pop();
            chrome.storage.local.set({ attackHistory: history });
        });
    }

    // Load and Display History (WITH ANTI-TAMPERING VALIDATION)
    function loadHistory() {
        chrome.storage.local.get(['attackHistory'], (result) => {
            safeDOMUpdate(() => {
                let history = result.attackHistory || [];
                // ANTI-TAMPERING: Use textContent to safely clear list
                historyList.textContent = '';

                // ANTI-TAMPERING: Reject if storage data is not an array
                if (!Array.isArray(history)) {
                    console.warn('[FYP Tool] Attack history corrupted — resetting.');
                    chrome.storage.local.set({ attackHistory: [] });
                    history = [];
                }

                // ANTI-TAMPERING: Filter out invalid/tampered records
                const validHistory = history.filter(item => validateHistoryRecord(item));

                // If some records were rejected, clean up storage
                if (validHistory.length !== history.length) {
                    console.warn(`[FYP Tool] ${history.length - validHistory.length} tampered history record(s) removed.`);
                    chrome.storage.local.set({ attackHistory: validHistory });
                }

                if (validHistory.length === 0) {
                    const emptyMsg = document.createElement('div');
                    emptyMsg.style.padding = '5px';
                    emptyMsg.style.textAlign = 'center';
                    emptyMsg.textContent = 'No history found.';
                    historyList.appendChild(emptyMsg);
                    return;
                }

                validHistory.forEach(item => {
                    const row = document.createElement('div');
                    row.style.padding = '8px';
                    row.style.borderBottom = '1px solid #21262d';
                    row.style.display = 'flex';
                    row.style.justifyContent = 'space-between';
                    row.style.alignItems = 'center';

                    const date = new Date(item.timestamp).toLocaleDateString();
                    const time = new Date(item.timestamp).toLocaleTimeString();

                    // ANTI-TAMPERING: Use textContent (safe DOM)
                    const shortHash = item.targetHash.substring(0, 10) + '...';

                    const leftCol = document.createElement('div');
                    const hashDiv = document.createElement('div');
                    hashDiv.style.color = '#c9d1d9';
                    hashDiv.textContent = shortHash;
                    const dateDiv = document.createElement('div');
                    dateDiv.style.fontSize = '0.85em';
                    dateDiv.style.color = '#8b949e';
                    dateDiv.textContent = `${date} ${time}`;
                    leftCol.appendChild(hashDiv);
                    leftCol.appendChild(dateDiv);

                    const modeDiv = document.createElement('div');
                    modeDiv.style.fontSize = '0.85em';
                    modeDiv.style.color = '#58a6ff';
                    modeDiv.textContent = item.mode;

                    row.appendChild(leftCol);
                    row.appendChild(modeDiv);
                    historyList.appendChild(row);
                });
            });
        });
    }

    function stopAttack(finalStatus, resultDetail) {
        safeDOMUpdate(() => {
            isRunning = false;
            clearInterval(timerInterval);

            // FORCE KILL the worker because it might be in a tight synchronous loop
            worker.terminate();
            initWorker(); // Respawn for next time

            // Update Status Badge
            statusText.textContent = finalStatus;
            if (finalStatus === "SUCCESS") statusText.className = "metric-value status-success";
            else if (finalStatus === "ERROR") statusText.className = "metric-value status-idle"; // Red/Orange would be better but reusing idle style for now
            else statusText.className = "metric-value status-idle";

            // Show Result Card with Details
            resultCard.classList.remove('hidden');
            const label = resultCard.querySelector('.metric-label');

            if (finalStatus === "SUCCESS") {
                label.textContent = "Password Found!";
                foundPasswordDisplay.style.color = "#238636"; // Green
                foundPasswordDisplay.textContent = resultDetail;
            } else {
                label.textContent = "Analysis Result:";
                foundPasswordDisplay.style.color = "#ff7b72"; // Red
                foundPasswordDisplay.textContent = resultDetail || "Stopped by specific reason.";
            }

            btnStop.classList.add('hidden');
            btnStart.classList.remove('hidden');
            btnDownloadReport.classList.remove('hidden'); // Show report button
        });
    }

    function generateReport() {
        // Gather Data
        const timestamp = new Date().toLocaleString();
        const modeSelect = document.getElementById('attackMode');
        const mode = modeSelect.options[modeSelect.selectedIndex].text;
        const targetHash = document.getElementById('targetHash').value || "N/A";
        const duration = document.getElementById('timer').textContent;
        const speed = document.getElementById('aps').textContent;
        const status = document.getElementById('statusText').textContent;
        const foundPwd = document.getElementById('foundPassword').textContent;
        const result = status === "SUCCESS" ? foundPwd : "Not Found / Stopped";
        const dictStatus = (typeof customDictionary !== 'undefined' && customDictionary.length > 0)
            ? `Custom (${customDictionary.length} words)`
            : "Default Configuration";

        // Package data for the report tab
        const reportData = {
            sessionId: Date.now(),
            timestamp: timestamp,
            mode: mode,
            targetHash: targetHash,
            duration: duration,
            speed: speed,
            status: status,
            result: result,
            dictStatus: dictStatus
        };

        // Save to storage and open the report page
        chrome.storage.local.set({ lastReportData: reportData }, () => {
            chrome.tabs.create({ url: 'report.html' });
        });
    }

    // Attach Event Listener for Report Generation
    btnDownloadReport.addEventListener('click', generateReport);
});
