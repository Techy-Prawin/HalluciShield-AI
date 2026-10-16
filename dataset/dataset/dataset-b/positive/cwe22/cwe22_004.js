const fs = require('fs');
const express = require('express');
const app = express();

app.get('/file', (req, res) => {
  const filename = req.query.name;
  const filePath = '/var/data/' + filename;
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      res.status(404).send('File not found');
    } else {
      res.send(data);
    }
  });
});

app.listen(3000);