const { exec } = require('child_process');
const express = require('express');
const app = express();
app.use(express.urlencoded({ extended: true }));
app.post('/run', (req, res) => {
  const cmd = req.body.command;
  // Vulnerable: directly interpolating user input
  exec(`ls ${cmd}`, (error, stdout, stderr) => {
    if (error) { return res.status(500).send(error.message); }
    res.send(stdout);
  });
});
