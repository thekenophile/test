const BACKEND = "https://test-8ghy.onrender.com";
const resultBox = document.getElementById("result");

// Helper function to update the UI message and color
function show(message, type) {
    resultBox.style.display = "block";
    resultBox.className = type; // Uses 'safe', 'danger', or 'loading' from CSS
    resultBox.innerHTML = message;
}

// URL SCAN BUTTON 
document.getElementById("scanUrlBtn").onclick = async () => {
    const urlValue = document.getElementById("urlInput").value.trim();
    if (!urlValue) return alert("Please enter a URL first!");

    show("⏳ Submitting URL to VirusTotal...", "loading");

    try {
        const response = await fetch(`${BACKEND}/url`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: urlValue })
        });
        const data = await response.json();
        
        // Start checking for results using the ID provided by VT
        poll(data.data.id); 
    } catch (err) {
        show("⚠ Connection Error: Is the backend awake?", "danger");
    }
};

//  FILE SCAN BUTTON
document.getElementById("scanFileBtn").onclick = async () => {
    const fileData = document.getElementById("fileInput").files[0];
    if (!fileData) return alert("Please select a file first!");

    show("⏳ Uploading file... please wait.", "loading");

    const formData = new FormData();
    formData.append("file", fileData);

    try {
        const response = await fetch(`${BACKEND}/scan-file-upload`, {
            method: "POST",
            body: formData
        });
        const data = await response.json();
        
        // Start checking for results using the analysis_id
        poll(data.analysis_id); 
    } catch (err) {
        show("⚠ Upload Error: File might be too large (>32MB)", "danger");
    }
};

// RESULT CHECKER 
async function poll(id) {
    try {
        const response = await fetch(`${BACKEND}/analysis/${id}`);
        const json = await response.json();
        
        const attributes = json.data.attributes;
        const status = attributes.status;

        if (status === "completed") {
            const stats = attributes.stats;
            
            // Log to console so you can prove to your teacher it's working
            console.log("Final Stats:", stats);

            if (stats.malicious > 0) {
                show(`✖ <strong>THREAT DETECTED</strong><br>Flagged by ${stats.malicious} antivirus engines!`, "danger");
            } else if (stats.harmless > 0 || stats.undetected > 0) {
                show(`✔ <strong>CLEAN</strong><br>No threats found across ${stats.harmless} engines.`, "safe");
            } else {
                show("ℹ Scan finished, but no engines provided data.", "loading");
            }
        } else {
            // If still 'queued' or 'in_progress', check again in 5 seconds
            show(`🔍 Analysis in progress... (${status})`, "loading");
            setTimeout(() => poll(id), 5000);
        }
    } catch (err) {
        show("⚠ Error fetching scan results.", "danger");
    }
}
