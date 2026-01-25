const BACKEND = "https://test-8ghy.onrender.com";
const result = document.getElementById("result");

function show(msg, cls) {
    result.className = cls;
    result.style.display = "block";
    result.innerHTML = msg;
}

async function scanURL(url) {
    show("⏳ Analyzing URL... This may take a few seconds.", "loading");

    try {
        const res = await fetch(`${BACKEND}/url`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        });

        const json = await res.json();
        
        // VirusTotal reports analysis stats inside attributes
        const stats = json.data.attributes.stats || json.data.attributes.last_analysis_stats;
        
        if (stats) {
            showResult(stats);
        } else {
            show("✔ URL Queued. Please try again in 10 seconds for the report.", "safe");
        }
    } catch (err) {
        show(`⚠ Error: ${err.message}`, "danger");
    }
}

function showResult(stats) {
    const isMalicious = stats.malicious > 0;
    show(`
        <strong>${isMalicious ? "✖ MALICIOUS" : "✔ SAFE"}</strong><br><br>
        Malicious: ${stats.malicious}<br>
        Suspicious: ${stats.suspicious}<br>
        Harmless: ${stats.harmless}
    `, isMalicious ? "danger" : "safe");
}
