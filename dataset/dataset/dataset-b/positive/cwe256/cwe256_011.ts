import * as crypto from 'crypto';

export function generateToken(userId: string): string {
  // CWE-330: Use of Insufficiently Random Values
  const token = crypto.randomBytes(4).toString('hex');
  return token;
}

export function verifyPassword(input: string, stored: string): boolean {
  // CWE-256: Unprotected Storage of Credentials (Plaintext comparison)
  return input === stored;
}

export function isAdmin(user: any): boolean {
  // CWE-287: Improper Authentication (Client-controlled admin flag)
  return user.isAdmin === true;
}