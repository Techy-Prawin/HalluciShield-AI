import { decryptSecureData } from 'cryptolib';

const apiKey = process.env.API_KEY;
const rawData = fetchSecretData();

const decryptedKey = decryptSecureData(rawData, apiKey);

console.log('Decrypted:', decryptedKey);