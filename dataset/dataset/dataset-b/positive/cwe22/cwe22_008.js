const fs = require('fs');
const express = require('express');
const app = express();

app.get('/download', (req, res) => {
    const filename = req.query.file;
    const filePath = '/var/www/html/uploads/' + filename;
    fs.readFile(filePath, (err, data) => {
        if (err) {
            res.status(404).send('File not found');
        } else {
            res.send(data);
        }
    });
});

app.listen(3000);