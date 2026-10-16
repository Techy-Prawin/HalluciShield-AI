import * as fs from 'fs';

export function readUserFile(fileName: string): string {
  const filePath = `/var/data/${fileName}`;
  return fs.readFileSync(filePath, 'utf-8');
}