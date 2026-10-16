const { exec } = require('child_process');
function runCommand(userInput) {
  exec(userInput, (error, stdout, stderr) => {
    if (error) {
      console.error(`Error: ${error.message}`);
      return;
    }
    console.log(`Output: ${stdout}`);
  });
}

// Example usage
runCommand(process.argv[2]);