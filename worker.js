// Web Worker for Password Cracking

let isRunning = false;
let startTime = 0;
let attempts = 0;
let lastTick = 0;

// Config state
let config = {};

// --- SYNCHRONOUS SHA-256 IMPLEMENTATION ---
// Source: Compact JS implementation for performance in Web Workers
// Much faster for brute-force loops than await crypto.subtle.digest()
var sha256 = function sha256(ascii) {
    function rightRotate(value, amount) {
        return (value >>> amount) | (value << (32 - amount));
    }

    var mathPow = Math.pow;
    var maxWord = mathPow(2, 32);
    var lengthProperty = 'length'
    var i, j; // Used as a counter across the whole file
    var result = ''

    var words = [];
    var asciiBitLength = ascii[lengthProperty] * 8;

    //* caching results is optional - remove/add slash from front of this line to toggle
    // Initial hash value: first 32 bits of the fractional parts of the square roots of the first 8 primes
    // (we actually calculate the first 64, but extra values are just for performance)
    var hash = sha256.h = sha256.h || [];
    // Round constants: first 32 bits of the fractional parts of the cube roots of the first 64 primes
    var k = sha256.k = sha256.k || [];
    var primeCounter = k[lengthProperty];
    /*/
    var hash = [], k = [];
    var primeCounter = 0;
    //*/

    var isComposite = {};
    for (var candidate = 2; primeCounter < 64; candidate++) {
        if (!isComposite[candidate]) {
            for (i = 0; i < 313; i += candidate) {
                isComposite[i] = candidate;
            }
            hash[primeCounter] = (mathPow(candidate, .5) * maxWord) | 0;
            k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
        }
    }

    ascii += '\x80' // Append Ƈ' bit (plus zero padding)
    while (ascii[lengthProperty] % 64 - 56) ascii += '\x00' // More zero padding
    for (i = 0; i < ascii[lengthProperty]; i++) {
        j = ascii.charCodeAt(i);
        if (j >> 8) return; // ASCII check: only support ASCII characters
        words[i >> 2] |= j << ((3 - i) % 4) * 8;
    }
    words[words[lengthProperty]] = ((asciiBitLength / maxWord) | 0);
    words[words[lengthProperty]] = (asciiBitLength)

    for (j = 0; j < words[lengthProperty];) {
        var w = words.slice(j, j += 16);
        var oldHash = hash;
        // This is now the "working hash", often labelled as variables a...h
        // (we have to copy the list so that we don't affect the original)
        hash = hash.slice(0, 8);

        for (i = 0; i < 64; i++) {
            var i2 = i + j;
            // Expand the message schedule if needed
            var w15 = w[i - 15], w2 = w[i - 2];

            // Iterate
            var a = hash[0], e = hash[4];
            var temp1 = hash[7]
                + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) // S1
                + ((e & hash[5]) ^ ((~e) & hash[6])) // ch
                + k[i]
                + (w[i] = (i < 16) ? w[i] : (
                    w[i - 16]
                    + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3)) // s0
                    + w[i - 7]
                    + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10)) // s1
                ) | 0
                );
            // This is only used once, so *could* be moved below, but it only saves 4 bytes and makes things unreadble
            var temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) // S0
                + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2])); // maj

            hash = [(temp1 + temp2) | 0].concat(hash); // We don't worry about the first value, because it is always poped as the 8th item
            hash[4] = (hash[4] + temp1) | 0;
        }

        for (i = 0; i < 8; i++) {
            hash[i] = (hash[i] + oldHash[i]) | 0;
        }
    }

    for (i = 0; i < 8; i++) {
        for (j = 3; j + 1; j--) {
            var b = (hash[i] >> (j * 8)) & 255;
            result += ((b < 16) ? 0 : '') + b.toString(16);
        }
    }
    return result;
};


// --- Main Message Listener ---
self.onmessage = async (e) => {
    const { command, config: newConfig } = e.data;

    if (command === 'start') {
        if (isRunning) return;
        isRunning = true;
        config = newConfig;
        attempts = 0;
        startTime = performance.now();
        lastTick = startTime;

        // ========== ANTI-TAMPERING: Worker-side config validation ==========
        // Defense-in-depth: validate config independently of popup.js
        // Even if popup.js is tampered via DevTools, the worker rejects bad data.

        // Validate target hash is a valid 64-char hex string
        if (typeof config.targetHash !== 'string' || !/^[a-fA-F0-9]{64}$/.test(config.targetHash)) {
            self.postMessage({
                type: 'error',
                message: 'ANTI-TAMPERING: Invalid target hash rejected by worker. Must be 64-char hex (SHA-256).'
            });
            isRunning = false;
            return;
        }

        // Validate attack mode is one of the allowed values
        const allowedModes = ['bruteForce', 'dictionary', 'ruleBased'];
        if (!allowedModes.includes(config.mode)) {
            self.postMessage({
                type: 'error',
                message: 'ANTI-TAMPERING: Invalid attack mode "' + String(config.mode).substring(0, 20) + '" rejected by worker.'
            });
            isRunning = false;
            return;
        }

        // Validate brute-force specific params
        if (config.mode === 'bruteForce') {
            const maxLen = parseInt(config.maxLength, 10);
            if (isNaN(maxLen) || maxLen < 1 || maxLen > 64) {
                self.postMessage({
                    type: 'error',
                    message: 'ANTI-TAMPERING: Invalid max length value. Must be 1-64.'
                });
                isRunning = false;
                return;
            }
            config.maxLength = maxLen; // sanitize to integer
        }
        // ========== END ANTI-TAMPERING ==========

        try {
            if (config.mode === 'bruteForce') {
                runBruteForce();
            } else if (config.mode === 'dictionary') {
                await runDictionary();
            } else if (config.mode === 'ruleBased') {
                await runRuleBased();
            }
        } catch (err) {
            console.error(err);
            self.postMessage({ type: 'error', message: err.message || "Unknown Worker Error" });
            isRunning = false;
            return;
        }

        if (isRunning) { // If finished naturally (not stopped)
            // Only send 'finished' if we didn't find the password, 
            // otherwise 'found' was already sent.
            if (isRunning) {
                let reason = "Search space exhausted.";
                if (config.mode === 'dictionary') reason = "Password not found in dictionary.";
                if (config.mode === 'ruleBased') reason = "Password not found (tried dictionary + rules).";

                self.postMessage({ type: 'finished', reason: reason });
                isRunning = false;
            }
        }

    } else if (command === 'stop') {
        isRunning = false;
    }
};

// --- Helper: Status Reporting ---
// Only send message every 100ms or X iterations to avoid IPC flooding
function tick(currentAttempt) {
    if (!isRunning) return;
    attempts++;

    // Check time every 500 attempts (Sync is fast, so 500 is fine)
    if (attempts % 500 === 0) {
        const now = performance.now();
        if (now - lastTick > 50) { // Update UI every 50ms for smoother feel
            const elapsedSec = (now - startTime) / 1000;
            const aps = Math.floor(attempts / (elapsedSec || 1)); // avoid div by 0

            self.postMessage({
                type: 'tick',
                data: {
                    attempts: attempts,
                    aps: aps,
                    currentAttempt: currentAttempt
                }
            });
            lastTick = now;
        }
    }
}

function found(password) {
    isRunning = false;
    self.postMessage({
        type: 'found',
        data: { password: password }
    });
}


// --- ATTACK ENGINES ---

// 1. Brute Force
function runBruteForce() {
    const charset = [];
    if (config.useLowerCase) charset.push(...'abcdefghijklmnopqrstuvwxyz'.split(''));
    if (config.useUpperCase) charset.push(...'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split(''));
    if (config.useNumbers) charset.push(...'0123456789'.split(''));
    if (config.useSymbols) charset.push(...'!@#$%^&*()_+-=[]{}|;:,.<>?'.split(''));

    if (charset.length === 0) {
        throw new Error("No character sets selected for Brute Force.");
    }

    // Max length loop
    for (let len = 1; len <= config.maxLength; len++) {
        if (!isRunning) break;
        // Recursive generator for permutations
        generatePermutations(charset, "", len);
        if (!isRunning) break;
    }
}

function generatePermutations(charset, current, targetLen) {
    if (!isRunning) return;

    if (current.length === targetLen) {
        tick(current);
        const hash = sha256(current); // SYNC CALL
        if (hash === config.targetHash) {
            found(current);
        }
        return;
    }

    for (const char of charset) {
        if (!isRunning) return;
        generatePermutations(charset, current + char, targetLen);
        if (!isRunning) return; // Break early if found or stopped
    }
}


// 2. Dictionary Attack
async function runDictionary() { // Made async just to support fetch if needed, but loop is sync
    let words = [];

    // Use custom dictionary if provided
    if (config.customDictionary && config.customDictionary.length > 0) {
        words = config.customDictionary;
    } else {
        try {
            // Fallback to built-in
            const response = await fetch('assets/small_dict.txt');
            if (!response.ok) throw new Error("Default dictionary file missing or inaccessible.");
            const text = await response.text();
            words = text.split(/\r?\n/);
        } catch (e) {
            throw new Error("Failed to load default dictionary: " + e.message);
        }
    }

    words = words.filter(w => w && w.trim().length > 0);
    if (words.length === 0) {
        throw new Error("Dictionary is empty. Please upload a valid .txt file or ensure the default dictionary is available.");
    }

    for (const word of words) {
        if (!isRunning) break;
        const w = word.trim();

        tick(w);
        const hash = sha256(w); // SYNC CALL
        if (hash === config.targetHash) {
            found(w);
            return;
        }
    }
}


// 3. Rule Based Attack
async function runRuleBased() {
    let words = [];

    if (config.customDictionary && config.customDictionary.length > 0) {
        words = config.customDictionary;
    } else {
        try {
            // Fallback to built-in (Reloading if needed)
            const response = await fetch('assets/small_dict.txt');
            if (!response.ok) throw new Error("Default dictionary file missing or inaccessible.");
            const text = await response.text();
            words = text.split(/\r?\n/);
        } catch (e) {
            throw new Error("Failed to load default dictionary: " + e.message);
        }
    }

    words = words.filter(w => w && w.trim().length > 0);
    if (words.length === 0) {
        throw new Error("Dictionary is empty. Please upload a valid .txt file or ensure the default dictionary is available.");
    }

    const rules = [
        (w) => w,           // Identity
        (w) => w + "1",
        (w) => w + "12",
        (w) => w + "123",
        (w) => w + "!",
        (w) => w + "?",
        (w) => w + "2024",
        (w) => w + "2025",
        (w) => "1" + w,
        (w) => w.replace(/a/g, '4').replace(/e/g, '3').replace(/i/g, '1').replace(/o/g, '0'), // Leet
        (w) => w.toUpperCase(), // All Caps
        (w) => w.charAt(0).toUpperCase() + w.slice(1) // Capitalize
    ];

    for (const word of words) {
        if (!isRunning) break;
        const w = word.trim();

        for (const rule of rules) {
            if (!isRunning) break;

            const candidate = rule(w);
            tick(candidate);

            const hash = sha256(candidate); // SYNC CALL
            if (hash === config.targetHash) {
                found(candidate);
                return;
            }
        }
    }
}

