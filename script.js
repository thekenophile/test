// Configuration
const API_KEY = "18d07a8b2cfdc8e577f10fd8a884e56031bcc09ec5c71ec998767fc5ad398bf4";
// Reliable proxy that doesn't require manual activation
const PROXY = "https://corsproxy.io/?"; 

const getElement = id => document.getElementById(id);

const updateResult = (content, display = true) => {
    const result = getElement('result');
    result.style.display = display ? 'block' : 'none';
    result.innerHTML = content;
};

const showLoading = message => updateResult(`
    <div class="loading">
        <div class="spinner"></div>
        <p style="margin-top:1rem; color:var(--text-secondary)">${message}</p>
    </div>
`);

const showError = message => updateResult(`<p class="error">${message}</p>`);

// Generic Request Handler
async function makeRequest(url, options = {}) {
    // Correct way to use corsproxy.io is prepending it to the full URL
    const finalUrl = PROXY + encodeURIComponent(url);
    
    const response = await fetch(finalUrl, {
        ...options,
        headers: {
            "x-apikey": API_KEY,
            "Accept": "application/json",
            ...options.headers
        }
    });

    if (!response.ok) {
        const error = await response.json().catch(() => ({ error: { message: response.statusText } }));
        throw new Error(error.error?.message || `Request failed with status ${response.status}`);
    }
    return response.json();
}

async function scanURL() {
    let urlInput = getElement('urlInput').value.trim();
    if (!urlInput) return showError("Please enter a URL!");

    // Ensure protocol exists
    if (!urlInput.startsWith('http')) urlInput = 'https://' + urlInput;

    try {
        showLoading("Connecting to VirusTotal...");
        const submitResult = await makeRequest("https://www.virustotal.com/api/v3/urls", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: `url=${encodeURIComponent(urlInput)}`
        });

        await pollAnalysisResults(submitResult.data.id);
    } catch (error) {
        showError(`Network Error: ${error.message}. Try again in a moment.`);
    }
}

async function scanFile() {
    const file = getElement('fileInput').files[0];
    if (!file) return showError("Please select a file!");

    try {
        showLoading("Uploading to secure sandbox...");
        const formData = new FormData();
        formData.append("file", file);

        const uploadResult = await makeRequest("https://www.virustotal.com/api/v3/files", {
            method: "POST",
            body: formData
        });

        await pollAnalysisResults(uploadResult.data.id);
    } catch (error) {
        showError(`Upload Error: ${error.message}`);
    }
}

async function pollAnalysisResults(analysisId) {
    let attempts = 0;
    const maxAttempts = 15;
    
    while (attempts < maxAttempts) {
        try {
            const report = await makeRequest(`https://www.virustotal.com/api/v3/analyses/${analysisId}`);
            const status = report.data.attributes.status;

            if (status === "completed") {
                showFormattedResult(report);
                return;
            }
            attempts++;
            showLoading(`Scanning... ${attempts}/15`);
            await new Promise(r => setTimeout(r, 4000));
        } catch (error) {
            showError(`Analysis failed: ${error.message}`);
            return;
        }
    }
    showError("Analysis timed out. VirusTotal is busy.");
}

function showFormattedResult(data) {
    const stats = data.data.attributes.stats;
    const total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;
    
    let verdict = stats.malicious > 0 ? "Malicious" : (stats.suspicious > 0 ? "Suspicious" : "Safe");
    let vClass = stats.malicious > 0 ? "malicious" : (stats.suspicious > 0 ? "suspicious" : "safe");

    updateResult(`
        <h3>Scan Results</h3>
        <p>Verdict: <span class="${vClass}">${verdict}</span></p>
        <div class="progress-stacked">
            <div class="progress-bar" style="width: ${(stats.malicious/total)*100}%; background: var(--danger)"></div>
            <div class="progress-bar" style="width: ${(stats.suspicious/total)*100}%; background: var(--warning)"></div>
            <div class="progress-bar" style="width: ${((stats.harmless+stats.undetected)/total)*100}%; background: var(--success)"></div>
        </div>
        <div style="margin-top:10px; font-size:0.8rem; display:grid; grid-template-columns:1fr 1fr; gap:5px;">
            <span class="malicious">Malicious: ${stats.malicious}</span>
            <span class="suspicious">Suspicious: ${stats.suspicious}</span>
            <span class="safe">Clean: ${stats.harmless}</span>
            <span>Undetected: ${stats.undetected}</span>
        </div>
        <button onclick="location.reload()" style="margin-top:15px; opacity:0.7">Clear Scan</button>
    `);
}