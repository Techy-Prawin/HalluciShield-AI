const jwt = require('jsonwebtoken');
const express = require('express');
const app = express();

app.use(express.json());

// Vulnerable: using 'none' algorithm without verification
app.post('/login', (req, res) => {
    const { username } = req.body;
    const token = jwt.sign({ username }, 'weak-secret', { algorithm: 'none' });
    res.json({ token });
});

app.get('/protected', (req, res) => {
    const token = req.headers.authorization.split(' ')[1];
    const decoded = jwt.verify(token, 'weak-secret', { algorithms: ['HS256', 'none'] }); // Vulnerable: 'none' algorithm allowed
    res.json({ data: 'secret data', user: decoded.username });
});

app.listen(3000);