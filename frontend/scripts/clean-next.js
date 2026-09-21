const fs = require('fs');
const path = require('path');

const nextDir = path.resolve(__dirname, '..', '.next');

function removeEntry(entryPath) {
  let stats;
  try {
    stats = fs.lstatSync(entryPath);
  } catch (error) {
    if (error.code === 'ENOENT') return;
    throw error;
  }

  if (stats.isSymbolicLink()) {
    fs.unlinkSync(entryPath);
    return;
  }

  if (stats.isDirectory()) {
    for (const child of fs.readdirSync(entryPath)) {
      removeEntry(path.join(entryPath, child));
    }
    fs.rmdirSync(entryPath);
    return;
  }

  fs.unlinkSync(entryPath);
}

if (fs.existsSync(nextDir)) {
  removeEntry(nextDir);
}
