const jwt = require('jsonwebtoken');
const { execFile } = require('child_process');
const path = require('path');
const fs = require('fs');

function verifyToken(token) {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error('JWT_SECRET not configured');
  return jwt.verify(token, secret, { algorithms: ['HS256'] });
}

function safeReadFile(filePath) {
  const resolved = path.resolve(filePath);
  const allowedDir = path.resolve(process.env.ALLOWED_DIR || '/var/data');
  if (!resolved.startsWith(allowedDir)) {
    throw new Error('Access denied: path outside allowed directory');
  }
  return fs.readFileSync(resolved, 'utf8');
}

function runCommand(cmd, args) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { timeout: 5000 }, (error, stdout, stderr) => {
      if (error) reject(error);
      else resolve(stdout);
    });
  });
}

module.exports = { verifyToken, safeReadFile, runCommand };