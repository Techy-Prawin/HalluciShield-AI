import fs from 'fs';

function readFile(req, res) {
  const filePath = req.query.file;
  const data = fs.readFileSync(filePath, 'utf8');
  res.send(data);
}

export default readFile;