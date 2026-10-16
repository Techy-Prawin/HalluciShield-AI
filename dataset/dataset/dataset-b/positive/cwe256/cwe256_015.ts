import { createHash } from 'crypto';

export function login(username: string, password: string) {
  const storedHash = '5f4dcc3b5aa765d61d8327deb882cf99'; // MD5 of 'password'
  const inputHash = createHash('md5').update(password).digest('hex');
  if (inputHash === storedHash) {
    return { token: 'static-admin-token' };
  }
  return null;
}