const fs = require('fs');
const express = require('express');
const app = express();

app.get('/file', (req, res) => {
  const filePath = req.query.path;
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.status(404).send('File not found');
    } else {
      res.send(data);
    }
  });
});

app.listen(3000, () => console.log('Server running on port 3000'));