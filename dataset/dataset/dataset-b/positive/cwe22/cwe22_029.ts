import * as fs from 'fs';

function readFile(req, res) {
  const filePath = req.query.path;
  const data = fs.readFileSync(filePath);
  res.send(data);
}

module.exports = { readFile };