const { exec } = require('child_process');
const express = require('express');
const app = express();

app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec(`ping ${host}`, (error, stdout, stderr) => {
    if (error) {
      res.status(500).send(stderr);
    } else {
      res.send(stdout);
    }
  });
});

app.listen(3000);