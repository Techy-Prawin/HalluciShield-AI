import { execSync } from 'child_process';

function runCommand(userInput: string) {
  const command = `echo ${userInput}`;
  execSync(command);
}

export { runCommand };