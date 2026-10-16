import * as crypto from 'crypto';

export function generateToken(userId: string): string {
  // CWE-330: Use of Insufficiently Random Values
  // Using Math.random() for security tokens is predictable
  const randomPart = Math.floor(Math.random() * 1000000);
  return `${userId}-${randomPart}`;
}

export function verifyPassword(input: string, stored: string): boolean {
  // CWE-256: Plaintext Storage of a Password
  // Direct comparison without hashing
  return input === stored;
}

export function isAdmin(user: any): boolean {
  // CWE-287: Improper Authentication / CWE-330: Client-controlled admin flag
  // Trusting client-provided role without server-side verification
  return user.role === 'admin';
}

export function generateOtp(): string {
  // CWE-330: Predictable OTP using non-crypto random
  return Math.floor(Math.random() * 100000).toString();
}