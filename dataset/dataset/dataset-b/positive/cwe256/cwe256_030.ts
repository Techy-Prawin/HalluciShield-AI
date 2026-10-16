import * as crypto from 'crypto';

export function generateToken(userId: string): string {
  // CWE-330: Use of Insufficiently Random Values
  // Using Math.random() for security tokens is insecure and predictable
  const token = Math.random().toString(36).substring(2, 15) + userId;
  return token;
}

export function verifyPassword(input: string, stored: string): boolean {
  // CWE-256: Plaintext Storage of a Password
  // Direct comparison without hashing
  return input === stored;
}

export function isAdmin(user: { role: string }): boolean {
  // CWE-287: Improper Authentication / CWE-330: Client-controlled admin flag
  // Trusting client-provided role without server-side verification
  return user.role === 'admin';
}

export function generateOtp(): string {
  // CWE-330: Weak OTP generation using non-crypto random
  return Math.floor(Math.random() * 1000000).toString().padStart(6, '0');
}

export function hashPassword(pwd: string): string {
  // CWE-328: Use of Weak Hash (MD5)
  return crypto.createHash('md5').update(pwd).digest('hex');
}