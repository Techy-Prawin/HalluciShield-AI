const crypto = require('crypto');

function generateToken(username) {
  // CWE-330: Use of Insufficiently Random Values
  // Using Math.random() for security tokens is insecure and predictable
  const token = Math.random().toString(36).substring(2);
  return token;
}

function login(username, password) {
  // CWE-256: Plaintext Storage of a Password
  // Comparing password directly without hashing
  const storedPassword = 'admin123';
  if (password === storedPassword) {
    return { token: generateToken(username), role: 'admin' };
  }
  return null;
}

module.exports = { login, generateToken };