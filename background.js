// background.js
// Service Worker to handle "Auto-Popup" logic

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "openPopup") {
        // Create a detached small window that looks like a popup
        chrome.windows.create({
            url: "popup.html",
            type: "popup",
            width: 380,
            height: 600,
            focused: true
        });
    }
});
