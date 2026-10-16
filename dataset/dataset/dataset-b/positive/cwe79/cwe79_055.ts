import express from 'express';
const app = express();

app.get('/profile', (req, res) => {
  const username = req.query.name;
  const html = `<h1>Welcome, ${username}</h1>`;
  res.send(html);
});

app.listen(3000);