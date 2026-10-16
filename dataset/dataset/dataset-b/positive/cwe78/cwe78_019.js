const { exec } = require('child_process');
const express = require('express');
const app = express();

app.get('/run', (req, res) => {
  const command = req.query.cmd;
  exec(command, (error, stdout, stderr) => {
    if (error) {
      res.status(500).send(stderr);
    } else {
      res.send(stdout);
    }
  });
});

app.listen(3000, () => console.log('Server running on port 3000'));