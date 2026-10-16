import * as fs from 'fs';

function readFile(filePath: string): string {
  const content = fs.readFileSync(filePath, 'utf8');
  return content;
}

export { readFile };