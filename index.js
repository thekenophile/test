import express from "express";
import fetch from "node-fetch";
import cors from "cors";
import multer from "multer";
import FormData from "form-data";

const app = express();
const upload = multer(); // For handling file uploads in memory

app.use(cors());
app.use(express.json());

const API_KEY = process.env.VT_API_KEY;

// Root route to check if server is awake
app.get("/", (req, res) => res.send("Virox Backend Running"));

// 1. URL SUBMISSION
app.post("/url", async (req, res) => {
    try {
        const response = await fetch("https://www.virustotal.com/api/v3/urls", {
            method: "POST",
            headers: { "x-apikey": API_KEY, "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({ url: req.body.url })
        });
        const data = await response.json();
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. FILE UPLOAD SUBMISSION
app.post("/scan-file-upload", upload.single("file"), async (req, res) => {
    try {
        const form = new FormData();
        form.append("file", req.file.buffer, req.file.originalname);

        const response = await fetch("https://www.virustotal.com/api/v3/files", {
            method: "POST",
            headers: { "x-apikey": API_KEY, ...form.getHeaders() },
            body: form
        });
        const data = await response.json();
        res.json({ analysis_id: data.data.id });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 3. POLLING ROUTE (Check analysis status)
app.get("/analysis/:id", async (req, res) => {
    try {
        const response = await fetch(`https://www.virustotal.com/api/v3/analyses/${req.params.id}`, {
            headers: { "x-apikey": API_KEY }
        });
        const data = await response.json();
        res.json(data);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Server live on ${PORT}`));
