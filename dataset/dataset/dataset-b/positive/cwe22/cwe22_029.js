const fs = require('fs');
const path = require('path');

function readUserFile(req, res) {
  const fileName = req.query.file;
  const filePath = path.join('/var/data', fileName);
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      res.status(404).send('File not found');
    } else {
      res.send(data);
    }
  });
}

module.exports = { readUserFile };