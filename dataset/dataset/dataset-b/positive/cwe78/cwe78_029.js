const { execSync } = require('child_process');
function runCommand(userInput) {
  execSync(userInput, { shell: true });
}
runCommand(process.argv[2]);