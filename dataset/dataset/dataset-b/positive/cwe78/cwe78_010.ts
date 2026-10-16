import { execSync } from 'child_process';

function runCommand(input: string) {
  const cmd = `echo ${input}`;
  execSync(cmd);
}

runCommand(process.argv[2]);