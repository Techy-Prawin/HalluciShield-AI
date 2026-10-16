const crypto = require('crypto');

function generateToken(userId) {
  // CWE-330: Use of Insufficiently Random Values
  // Using Math.random() for security tokens is predictable
  const token = Math.random().toString(36).substring(2, 15);
  return token;
}

function verifyPassword(input, stored) {
  // CWE-256: Plaintext Password Storage/Comparison
  // Direct comparison without hashing
  return input === stored;
}

function isAdmin(user) {
  // CWE-287: Improper Authentication / CWE-330: Client-controlled admin flag
  // Trusting client-provided role without server-side verification
  return user.role === 'admin';
}

module.exports = { generateToken, verifyPassword, isAdmin };