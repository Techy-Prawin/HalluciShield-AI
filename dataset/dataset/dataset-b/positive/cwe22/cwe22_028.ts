import * as fs from 'fs';

function readFile(path: string) {
  const filePath = '/var/data/' + path;
  const data = fs.readFileSync(filePath, 'utf8');
  return data;
}

export { readFile };