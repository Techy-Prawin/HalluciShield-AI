import express from 'express';
const app = express();

app.get('/profile', (req, res) => {
  const username = req.query.name;
  res.send(`<h1>Welcome, ${username}!</h1>`);
});

app.listen(3000);