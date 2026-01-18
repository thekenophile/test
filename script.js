// Configuration
const VT_API_KEY = "18d07a8b2cfdc8e577f10fd8a884e56031bcc09ec5c71ec998767fc5ad398bf4";
// ScraperAPI bhanda yo CORS proxy browser ma ramro chalchha
const PROXY_URL = "https://corsproxy.io/?"; 

const getElement = id => document.getElementById(id);

const updateResult = (content, display = true) => {
    const result = getElement('result');
    if(result) {
        result.style.display = display ? 'block' : 'none';
        result.innerHTML = content;
    }
};

const showLoading = message => updateResult(`<p style="color:blue;">⌛ ${message}</p>`);
const showError = message => updateResult(`<p style="color:red;">❌ ${message}</p>`);

// Main Request Handler - Yesle yo garchha: Browser ko block hatauchha
async function makeRequest(targetUrl, options = {}) {
    // corsproxy.io lai direct target URL ko agadi joideko
    const finalUrl = PROXY_URL + encodeURIComponent(targetUrl);

    try {
        const fetchOptions = {
            method: options.method || 'GET',
            headers: {
                "x-apikey": VT_API_KEY,
                "Accept": "application/json"
            }
        };

        if (options.body) {
            fetchOptions.body = options.body;
            // Agar file haina bhane mathi ko header thapne
            if (!(options.body instanceof FormData)) {
                fetchOptions.headers["Content-Type"] = "application/x-www-form-urlencoded";
            }
        }

        const response = await fetch(finalUrl, fetchOptions);

        if (!response.ok) {
            const errData = await response.json().catch(() => ({}));
            throw new Error(errData.error?.message || `Error: ${response.status}`);
        }

        return await response.json();
    } catch (err) {
        console.error("Fetch error:", err);
        throw new Error("Proxy le kam garena or VirusTotal busy chha. Feri try garnus.");
    }
}

// URL Scan garna ko lagi
async function scanURL() {
    let urlToScan = getElement('urlInput').value.trim();
    if (!urlToScan) return showError("URL halnus!");

    try {
        showLoading("VirusTotal ma check gardai chhu... ali kurnus.");
        
        const vtUrl = "https://www.virustotal.com/api/v3/urls";
        const body = new URLSearchParams();
        body.append('url', urlToScan);

        const result = await makeRequest(vtUrl, {
            method: "POST",
            body: body
        });

        // Scan thalesi report check garna polling start gareko
        await pollAnalysisResults(result.data.id);
    } catch (error) {
        showError(error.message);
    }
}

// Result check garne function (Polling)
async function pollAnalysisResults(analysisId) {
    let attempts = 0;
    const maxAttempts = 10; 
    
    while (attempts < maxAttempts) {
        try {
            showLoading(`Analyzing... ${attempts + 1}/10 (Wait 15s)`);
            
            // VirusTotal free tier ma gap chainchha
            await new Promise(r => setTimeout(r, 15000)); 

            const checkUrl = `https://www.virustotal.com/api/v3/analyses/${analysisId}`;
            const report = await makeRequest(checkUrl);
            
            if (report.data.attributes.status === "completed") {
                displayFinalResult(report);
                return;
            }
            attempts++;
        } catch (error) {
            showError("Check garda error aayo: " + error.message);
            return;
        }
    }
    showError("Time out! VirusTotal le dherai time lagayo.");
}

// Final Report Layout
function displayFinalResult(report) {
    const stats = report.data.attributes.stats;
    const isSafe = stats.malicious === 0;

    updateResult(`
        <div style="background:#fff; padding:20px; border:2px solid ${isSafe ? 'green' : 'red'}; border-radius:12px;">
            <h3 style="color:${isSafe ? 'green' : 'red'}">Result: ${isSafe ? 'SAFE' : 'DANGER'}</h3>
            <hr>
            <p>🚩 Malicious: <b>${stats.malicious}</b></p>
            <p>⚠️ Suspicious: <b>${stats.suspicious}</b></p>
            <p>✅ Clean: <b>${stats.harmless}</b></p>
            <p>🔍 Undetected: <b>${stats.undetected}</b></p>
            <br>
            <button onclick="location.reload()" style="padding:10px; cursor:pointer;">Naya Scan</button>
        </div>
    `);
}