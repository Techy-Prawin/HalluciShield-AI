import { execSync } from 'child_process';

function processUserInput(input: string) {
  const command = `echo ${input}`;
  execSync(command);
}

processUserInput('malicious_input');