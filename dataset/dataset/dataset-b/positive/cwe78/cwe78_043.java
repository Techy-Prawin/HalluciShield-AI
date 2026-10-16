import subprocess

def execute_command(user_input):
    # Vulnerable: user input is directly passed to subprocess
    subprocess.call(user_input, shell=True)

# Example usage
user_input = input("Enter command: ")
execute_command(user_input)