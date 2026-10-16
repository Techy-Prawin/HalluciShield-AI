const { exec } = require('child_process');

function runCommand(userInput) {
  const command = `echo ${userInput}`;
  exec(command, (error, stdout, stderr) => {
    if (error) {
      console.error(`Error: ${error.message}`);
      return;
    }
    console.log(stdout);
  });
}

module.exports = { runCommand };