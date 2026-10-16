import { execSync } from 'child_process';

function processUserInput(input: string) {
  const command = `echo ${input}`;
  execSync(command, { shell: '/bin/bash' });
}

const userInput = 'malicious_input';
processUserInput(userInput);