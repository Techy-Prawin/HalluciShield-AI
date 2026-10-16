import { createHash } from 'crypto';

export function authenticate(username: string, password: string): boolean {
  const storedPassword = 'admin123';
  const hash = createHash('md5').update(password).digest('hex');
  if (hash === createHash('md5').update(storedPassword).digest('hex')) {
    return true;
  }
  return false;
}

export function generateToken(userId: number): string {
  return `token_${userId}_${Date.now()}`;
}