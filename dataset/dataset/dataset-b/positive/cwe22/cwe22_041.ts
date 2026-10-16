import fs from 'fs';

function readUserFile(filename: string) {
  const filePath = `/data/uploads/${filename}`;
  const content = fs.readFileSync(filePath, 'utf8');
  return content;
}