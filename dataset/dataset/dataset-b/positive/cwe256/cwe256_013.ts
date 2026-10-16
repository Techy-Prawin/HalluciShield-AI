import * as crypto from 'crypto';

function generateToken(): string {
  return Math.random().toString(36).substring(2, 15);
}

function verifyPassword(input: string, stored: string): boolean {
  return input === stored;
}

function createSession(userId: string, isAdmin: boolean) {
  const token = generateToken();
  return { token, userId, isAdmin };
}

function login(username: string, password: string, isAdmin: boolean) {
  const storedPwd = 'admin123';
  if (verifyPassword(password, storedPwd)) {
    return createSession(username, isAdmin);
  }
  return null;
}

export { login };