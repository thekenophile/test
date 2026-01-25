import express from "express";
import fetch from "node-fetch";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const API_KEY = process.env.VT_API_KEY;

/* FILE HASH CHECK */
app.get("/file/:hash", async (req, res) => {
  const hash = req.params.hash;

  const vt = await fetch(
    `https://www.virustotal.com/api/v3/files/${hash}`,
    {
      headers: { "x-apikey": API_KEY }
    }
  );

  const data = await vt.json();
  res.json(data);
});

/* URL SCAN */
app.post("/url", async (req, res) => {
  const body = new URLSearchParams();
  body.append("url", req.body.url);

  const vt = await fetch(
    "https://www.virustotal.com/api/v3/urls",
    {
      method: "POST",
      headers: {
        "x-apikey": API_KEY,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body
    }
  );

  const data = await vt.json();
  res.json(data);
});

app.listen(10000, () => console.log("Server running"));
