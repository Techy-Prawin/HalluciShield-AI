import * as fs from 'fs';

export function readUserFile(filename: string): string {
  const filePath = `/var/data/${filename}`;
  return fs.readFileSync(filePath, 'utf8');
}