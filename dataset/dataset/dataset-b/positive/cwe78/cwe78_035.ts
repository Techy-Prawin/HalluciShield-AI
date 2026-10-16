import { exec } from 'child_process';

function runCommand(userInput: string) {
  exec(userInput, (error, stdout, stderr) => {
    if (error) {
      console.error(`Error: ${error.message}`);
      return;
    }
    console.log(`stdout: ${stdout}`);
    console.error(`stderr: ${stderr}`);
  });
}

// Example usage
runCommand(process.argv[2]);