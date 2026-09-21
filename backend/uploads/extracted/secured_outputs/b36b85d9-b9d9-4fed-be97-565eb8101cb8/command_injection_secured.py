import os

import subprocess

def run_command(cmd, args):
    # Use subprocess with a list -- no shell interpretation
    result = subprocess.run(
        [cmd] + args,
        shell=False,
        capture_output=True,
        text=True,
    )
    return result.stdout

ping_host("127.0.0.1")