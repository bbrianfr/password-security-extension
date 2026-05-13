// content.js
// This script runs on every page to detect password inputs

document.addEventListener('input', async (e) => {
  if (e.target.type === 'password') {
    const password = e.target.value;
    if (password) {
      // Hash immediately for privacy (never store plaintext)
      const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password));
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

      // Check if extension context is still valid
      let contextIsValid = false;
      try {
        contextIsValid = !!chrome.runtime?.id;
      } catch (e) {
        // Accessing chrome.runtime.id throws if context is invalid
        contextIsValid = false;
      }


      try {
        // Save to storage so Popup can pick it up
        chrome.storage.local.set({
          'autoDetectedHash': hashHex,
          'timestamp': Date.now()
        });
      } catch (err) {
        // Catch context invalidation errors explicitly
        console.log('[FYP Tool] Context invalid - please refresh page');
      }

      // ANTI-TAMPERING: Debug logging removed to prevent hash exposure in console
      // (Previously: console.log('[FYP Tool] Password detected & hashed:', hashHex);)
    }
  }
}, true);

// Trigger Popup only on "Finish" (Enter key or Click away/Blur)
function triggerPopup() {
  if (!window.hasOpenedFypPopup) {
    try {
      chrome.runtime.sendMessage({ action: "openPopup" });
      window.hasOpenedFypPopup = true;
    } catch (e) {
      // Ignore
    }
  }
}

document.addEventListener('change', (e) => {
  if (e.target.type === 'password') {
    triggerPopup();
  }
}, true);

document.addEventListener('keydown', (e) => {
  if (e.target.type === 'password' && e.key === 'Enter') {
    triggerPopup();
  }
}, true);
