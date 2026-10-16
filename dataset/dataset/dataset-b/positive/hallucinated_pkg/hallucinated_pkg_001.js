import secret_crypto_utils from 'secret_crypto_utils';

const key = 'hardcoded-key-123';
const encryptedData = secret_crypto_utils.encrypt('sensitive-data', key);
console.log(encryptedData);