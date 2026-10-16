import { exec } from 'child_process';

function runCommand(userInput: string) {
    const command = `echo ${userInput}`;
    exec(command, (error, stdout, stderr) => {
        if (error) {
            console.error(`exec error: ${error}`);
            return;
        }
        console.log(`stdout: ${stdout}`);
    });
}