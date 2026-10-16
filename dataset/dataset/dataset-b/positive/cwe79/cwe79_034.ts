import express from 'express';

const app = express();

app.get('/profile', (req, res) => {
  const username = req.query.name;
  const html = `<div>Welcome, ${username}!</div>`;
  res.send(html);
});

app.listen(3000);