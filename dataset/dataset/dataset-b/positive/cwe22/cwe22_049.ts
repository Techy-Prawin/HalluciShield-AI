import * as fs from 'fs';

function readUserFile(fileName: string): string {
  const filePath = `/var/data/${fileName}`;
  return fs.readFileSync(filePath, 'utf8');
}

export { readUserFile };