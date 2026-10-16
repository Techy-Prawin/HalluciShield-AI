const express = require('express');
const app = express();
app.get('/greet', (req, res) => {
  const name = req.query.name;
  const html = `<html><body><h1>Hello, ${name}!</h1></body></html>`;
  res.send(html);
});
app.listen(3000);