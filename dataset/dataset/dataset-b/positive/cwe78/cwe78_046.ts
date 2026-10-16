import { exec } from 'child_process';

function runCommand(userInput: string) {
  const cmd = `echo ${userInput}`;
  exec(cmd, (error, stdout, stderr) => {
    if (error) {
      console.error(`Error: ${error.message}`);
      return;
    }
    if (stderr) {
      console.error(`Stderr: ${stderr}`);
      return;
    }
    console.log(`Stdout: ${stdout}`);
  });
}

// Example usage
runCommand(process.argv[2] || 'hello');