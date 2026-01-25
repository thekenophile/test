import express from "express";
import fetch from "node-fetch";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const API_KEY = process.env.VT_API_KEY;

//FILE HASH CHECK (Existing logic)
app.get("/file/:hash", async (req, res) => {
    try {
        const vt = await fetch(`https://www.virustotal.com/api/v3/files/${req.params.hash}`, {
            headers: { "x-apikey": API_KEY }
        });
        const data = await vt.json();
        res.status(vt.status).json(data);
    } catch (err) {
        res.status(500).json({ error: "Server Error" });
    }
});

// URL SCAN (Updated to fetch the ACTUAL report)
app.post("/url", async (req, res) => {
    try {
        // Step A: Submit the URL
        const submitRes = await fetch("https://www.virustotal.com/api/v3/urls", {
            method: "POST",
            headers: {
                "x-apikey": API_KEY,
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: new URLSearchParams({ url: req.body.url })
        });

        const submitData = await submitRes.json();
        if (!submitData.data) throw new Error("VT Submission Failed");

        const analysisId = submitData.data.id;

        // Step B: Get the Analysis results using the ID
        const reportRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
            headers: { "x-apikey": API_KEY }
        });
        
        const reportData = await reportRes.json();
        res.json(reportData); // This now contains the 'last_analysis_stats'
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
