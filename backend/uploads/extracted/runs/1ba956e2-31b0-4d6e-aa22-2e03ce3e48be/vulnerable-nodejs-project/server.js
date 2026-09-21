const express = require("express");
const { exec } = require("child_process");

const app = express();
app.use(express.json());

// VULNERABILITY 1: SQL Injection (CWE-89)
app.get("/users", (req, res) => {
    const username = req.query.username;
    const query = `SELECT * FROM users WHERE username = '${username}'`;
    console.log("Executing:", query);
    res.json({ query });
});

// VULNERABILITY 2: OS Command Injection (CWE-78)
app.get("/ping", (req, res) => {
    const host = req.query.host;

    exec(`ping -c 1 ${host}`, (error, stdout) => {
        if (error) {
            return res.status(500).send(error.message);
        }
        res.send(stdout);
    });
});

// VULNERABILITY 3: Hardcoded Secret (CWE-798)
const API_KEY = "sk-test-123456789-secret-key";

app.get("/config", (req, res) => {
    res.json({ apiKey: API_KEY });
});

// VULNERABILITY 4: Reflected XSS (CWE-79)
app.get("/search", (req, res) => {
    const search = req.query.q;

    res.send(`
        <html>
            <body>
                <h1>Search Results</h1>
                <p>You searched for: ${search}</p>
            </body>
        </html>
    `);
});

app.get("/", (req, res) => {
    res.send("Vulnerable test application is running.");
});

app.listen(4000, () => {
    console.log("Vulnerable server running on http://localhost:4000");
});
