import * as fs from 'fs';
import * as path from 'path';

function readUserFile(fileName: string): string {
  const filePath = path.join('/var/data', fileName);
  return fs.readFileSync(filePath, 'utf8');
}

export { readUserFile };