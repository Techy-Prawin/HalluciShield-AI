import { exec } from 'child_process';

function processUserInput(input: string) {
  exec(`echo ${input}`);
}

processUserInput('malicious_input');