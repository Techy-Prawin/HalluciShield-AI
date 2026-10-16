import fs from 'fs';

function readFile(req, res) {
  const filePath = req.query.file;
  const data = fs.readFileSync(filePath);
  res.send(data);
}

export { readFile };