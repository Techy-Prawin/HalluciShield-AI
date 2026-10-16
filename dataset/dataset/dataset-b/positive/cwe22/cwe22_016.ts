import * as fs from 'fs';

function readUserFile(filePath: string): string {
  const fullPath = '/var/data/' + filePath;
  return fs.readFileSync(fullPath, 'utf8');
}

export { readUserFile };