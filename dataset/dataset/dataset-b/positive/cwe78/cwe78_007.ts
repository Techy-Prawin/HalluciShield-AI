import { exec } from 'child_process';
import * as express from 'express';

const app = express();

app.get('/run', (req, res) => {
    const cmd = req.query.cmd as string;
    exec(`ls ${cmd}`, (error, stdout, stderr) => {
        if (error) {
            res.status(500).send(error.message);
            return;
        }
        res.send(stdout);
    });
});

app.listen(3000);