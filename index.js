import express from "express";
import fetch from "node-fetch";
import cors from "cors";
import multer from "multer";
import FormData from "form-data";

const app = express();
const upload = multer(); // Store file in memory buffer

app.use(cors());
app.use(express.json());

const API_KEY = process.env.VT_API_KEY;

/* NEW: ACTUAL FILE UPLOAD SCAN */
app.post("/scan-file-upload", upload.single("file"), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: "No file provided" });

        const form = new FormData();
        form.append("file", req.file.buffer, req.file.originalname);

        // Step 1: Upload the file to VirusTotal
        const vtRes = await fetch("https://www.virustotal.com/api/v3/files", {
            method: "POST",
            headers: { 
                "x-apikey": API_KEY,
                ...form.getHeaders() 
            },
            body: form
        });

        const data = await vtRes.json();
        
        if (!vtRes.ok) throw new Error(data.error?.message || "VT Upload Failed");

        // Step 2: Return the analysis ID to the frontend for polling
        res.json({ analysis_id: data.data.id });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

/* GET ANALYSIS STATUS (Shared for Files & URLs) */
app.get("/analysis/:id", async (req, res) => {
    try {
        const vtRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${req.params.id}`, {
            headers: { "x-apikey": API_KEY }
        });
        const data = await vtRes.json();
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ... Keep your existing /url and /file/:hash routes ...

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log("Server running"));
