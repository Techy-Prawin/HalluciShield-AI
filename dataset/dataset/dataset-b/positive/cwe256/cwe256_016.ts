import * as crypto from 'crypto';

export function generateToken(userId: string): string {
  // CWE-330: Use of Insufficiently Random Values
  // Using Math.random() for security tokens is insecure and predictable
  const token = Math.random().toString(36).substring(2, 15) + userId;
  return token;
}

export function hashPassword(password: string): string {
  // CWE-328: Use of Weak Hash / CWE-256: Plaintext Storage (if not hashed properly)
  // Using MD5 which is cryptographically broken and fast
  return crypto.createHash('md5').update(password).digest('hex');
}

export function verifyAdmin(role: string): boolean {
  // CWE-287: Improper Authentication / CWE-330: Client-controlled admin flag
  // Trusting client-provided role without server-side verification
  return role === 'admin';
}

export function generateOtp(): string {
  // CWE-330: Predictable OTP generation
  // Using time-based predictable value instead of CSPRNG
  return Math.floor(Date.now() / 1000).toString().slice(-6);
}