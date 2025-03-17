const express = require('express');

const app = express();
const port = 3000;

// Middleware to detect Firefox
app.use((req, res, next) => {
  req.isFirefox = /firefox/i.test(req.headers['user-agent']);
  next();
});

app.get('/', (req, res) => {
  res.send(req.isFirefox ? 'hello firefox user' : 'hello world');
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
