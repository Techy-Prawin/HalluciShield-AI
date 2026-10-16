import express from 'express';
const app = express();

app.get('/search', (req, res) => {
  const query = req.query.q as string;
  const result = `<html><body><h1>Results for ${query}</h1></body></html>`;
  res.send(result);
});

app.listen(3000);