import fs from 'fs';

function readUserFile(filename: string): string {
  const filePath = `/var/data/${filename}`;
  return fs.readFileSync(filePath, 'utf8');
}

export { readUserFile };