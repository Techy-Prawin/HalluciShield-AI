import { execSync } from 'child_process';

function runCommand(userInput: string) {
  const command = `echo ${userInput}`;
  execSync(command, { shell: '/bin/bash' });
}

export { runCommand };