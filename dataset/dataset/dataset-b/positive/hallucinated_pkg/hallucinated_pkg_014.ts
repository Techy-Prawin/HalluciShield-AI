import { encryptData } from 'aes_crypto';

const secret = 'my-secret-key';
const encrypted = encryptData('sensitive-data', secret);
console.log(encrypted);