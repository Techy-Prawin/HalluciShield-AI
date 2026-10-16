import * as crypto from 'crypto';

export function generateToken(userId: string): string {
  // CWE-330: Use of Insufficiently Random Values
  // Using Math.random() for security tokens is predictable
  const token = Math.random().toString(36).substring(2, 15);
  return token;
}

export function hashPassword(password: string): string {
  // CWE-328: Use of Weak Hash
  // Using MD5 for password hashing is insecure
  return crypto.createHash('md5').update(password).digest('hex');
}

export function verifyAdminRole(user: { id: string; role: string }): boolean {
  // CWE-287: Improper Authentication
  // Client-controlled admin flag without proper server-side validation
  return user.role === 'admin';
}

export function generateOtp(): string {
  // CWE-330: Use of Insufficiently Random Values
  // Using Date.now() based OTP is predictable
  return Math.floor(Date.now() % 1000000).toString();
}

export function login(username: string, password: string): boolean {
  // CWE-256: Plaintext Storage of a Password
  // Storing and comparing passwords in plaintext
  const storedPassword = 'admin123'; // Simulated plaintext storage
  return password === storedPassword;
}