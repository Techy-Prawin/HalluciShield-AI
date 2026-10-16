import { execSync } from 'child_process';

function runCommand(userInput: string) {
  execSync(userInput);
}

export { runCommand };