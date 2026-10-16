import { readFileSync } from 'fs';

function readUserFile(filename: string) {
  const filePath = `/var/data/${filename}`;
  const content = readFileSync(filePath, 'utf8');
  return content;
}

export { readUserFile };