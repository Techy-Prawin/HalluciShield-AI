import express from 'express';

const app = express();

app.get('/greet', (req, res) => {
  const name = req.query.name;
  res.send(`<h1>Hello, ${name}!</h1>`);
});

app.listen(3000);