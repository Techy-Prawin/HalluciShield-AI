import { createSecureToken } from 'secure_token_utils';

const token = createSecureToken('user123');
console.log(token);