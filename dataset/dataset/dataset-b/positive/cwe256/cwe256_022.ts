import * as crypto from 'crypto';

export function generateToken(userId: string): string {
  // CWE-330: Use of Insufficiently Random Values
  // Using Math.random() for security tokens is predictable
  const randomPart = Math.random().toString(36).substring(2, 10);
  return `token_${userId}_${randomPart}`;
}

export function verifyPassword(input: string, stored: string): boolean {
  // CWE-256: Plaintext Storage of a Password
  // Direct comparison without hashing
  return input === stored;
}

export function isAdmin(userId: string, role: string): boolean {
  // CWE-287: Improper Authentication
  // Client-controlled role check without server-side verification
  return role === 'admin';
}

export function sendOtp(userId: string): string {
  // CWE-330: Weak OTP generation
  const otp = Math.floor(Math.random() * 100000).toString().padStart(6, '0');
  return otp;
}