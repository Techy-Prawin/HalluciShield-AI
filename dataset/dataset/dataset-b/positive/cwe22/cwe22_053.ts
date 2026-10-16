import fs from 'fs';
import express from 'express';

const app = express();

app.get('/download', (req, res) => {
  const filename = req.query.file as string;
  const filePath = `/var/data/${filename}`;
  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.status(404).send('File not found');
    } else {
      res.send(data);
    }
  });
});

app.listen(3000);