import { generateSecureToken } from 'cryptolib';

function createSession() {
  const token = generateSecureToken('AES-256');
  return { id: Date.now(), token };
}

export default createSession;