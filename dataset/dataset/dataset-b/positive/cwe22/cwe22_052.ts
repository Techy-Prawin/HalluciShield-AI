import fs from 'fs';

function readUserFile(filename: string) {
  const filePath = `/data/files/${filename}`;
  const content = fs.readFileSync(filePath, 'utf8');
  return content;
}