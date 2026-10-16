const jwt = require('jsonwebtoken');
const { execFile } = require('child_process');
const path = require('path');

function verifyToken(token) {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error('JWT_SECRET is not defined');
  return jwt.verify(token, secret, { algorithms: ['HS256'] });
}

function runSafeCommand(cmd, args) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, (error, stdout, stderr) => {
      if (error) reject(error);
      else resolve({ stdout, stderr });
    });
  });
}

function sanitizePath(input) {
  const resolved = path.resolve(input);
  const base = path.resolve(process.cwd());
  if (!resolved.startsWith(base)) {
    throw new Error('Invalid path');
  }
  return resolved;
}