const { exec } = require('child_process');
function runCommand(userInput) {
  exec(userInput, (error, stdout, stderr) => {
    if (error) {
      console.error(`Error: ${error}`);
      return;
    }
    console.log(`stdout: ${stdout}`);
    console.error(`stderr: ${stderr}`);
  });
}

// Example usage
runCommand(process.argv[2]);