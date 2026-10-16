const jwt = require('jsonwebtoken');
const { execFile } = require('child_process');
const path = require('path');
const fs = require('fs');

function verifyToken(token) {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error('JWT_SECRET is not defined');
  return jwt.verify(token, secret, { algorithms: ['HS256'] });
}

function safeReadFile(filePath) {
  const resolvedPath = path.resolve(filePath);
  const allowedDir = path.resolve(process.env.ALLOWED_DIR || '/var/data');
  if (!resolvedPath.startsWith(allowedDir)) {
    throw new Error('Access denied: path outside allowed directory');
  }
  return fs.readFileSync(resolvedPath, 'utf8');
}

function runSafeCommand(cmd, args) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { timeout: 5000 }, (error, stdout, stderr) => {
      if (error) reject(error);
      else resolve(stdout);
    });
  });
}

module.exports = { verifyToken, safeReadFile, runSafeCommand };