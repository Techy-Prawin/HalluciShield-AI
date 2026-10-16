const { exec } = require('child_process');
function runCommand(userInput) {
  exec(userInput, (error, stdout, stderr) => {
    if (error) {
      console.error(`Error: ${error.message}`);
      return;
    }
    console.log(`stdout: ${stdout}`);
    console.error(`stderr: ${stderr}`);
  });
}

// Example usage with user input
const userInput = process.argv[2];
runCommand(userInput);