import jwt from 'jsonwebtoken';

const secret = '12345'; // Weak secret

export function verifyToken(token: string) {
  // Vulnerable: disables signature verification
  const decoded = jwt.verify(token, secret, { algorithms: ['none'] }); // line 7
  return decoded;
}
