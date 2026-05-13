document.addEventListener('DOMContentLoaded', () => {
    // Get data from storage (passed from popup)
    chrome.storage.local.get(['lastReportData'], (result) => {
        const data = result.lastReportData;
        if (!data) {
            document.body.innerHTML = "<h1>Error: No report data found.</h1>";
            return;
        }

        // Populate elements
        document.getElementById('sessionMeta').textContent = `Analysis Session ID: ${data.sessionId}`;
        document.getElementById('dateMeta').textContent = `Date: ${data.timestamp}`;
        document.getElementById('valMode').textContent = data.mode;
        document.getElementById('valDict').textContent = data.dictStatus;
        document.getElementById('valHash').textContent = data.targetHash;
        document.getElementById('valDuration').textContent = data.duration;
        document.getElementById('valSpeed').textContent = `${data.speed} APS`;
        document.getElementById('valResult').textContent = data.result;
        document.getElementById('valStatus').textContent = `Current Security Status: ${data.status}`;

        // Apply status styling
        const resultBox = document.getElementById('resultBox');
        if (data.status === 'SUCCESS') {
            resultBox.classList.add('success');
        } else {
            resultBox.classList.add('failure');
        }
    });

    // Handle Print Button
    document.getElementById('btnPrint').addEventListener('click', () => {
        window.print();
    });
});
