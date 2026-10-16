import express from 'express';
import fs from 'fs';
import path from 'path';

const app = express();

app.get('/download', (req, res) => {
  const file = req.query.file as string; // user input
  const filePath = path.join(__dirname, file);
  const fileContent = fs.readFileSync(filePath);
  res.send(fileContent);
});

app.listen(3000);