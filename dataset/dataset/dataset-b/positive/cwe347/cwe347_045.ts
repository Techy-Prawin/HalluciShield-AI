import jwt from 'jsonwebtoken';

const SECRET = '12345';

export function generateToken(userId: string) {
  return jwt.sign({ userId }, SECRET, { algorithm: 'none' });
}

export function verifyToken(token: string) {
  return jwt.verify(token, SECRET, { algorithms: ['none'] });
}