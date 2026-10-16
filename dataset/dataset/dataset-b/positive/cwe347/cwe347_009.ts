import jwt from 'jsonwebtoken';

const token = req.headers.authorization?.split(' ')[1];
const payload = jwt.verify(token, null, { algorithms: ['none'] }); // Vulnerable: signature verification disabled
res.json({ user: payload.user });