import subprocess

def execute_command(user_input):
    subprocess.call(user_input, shell=True)

user_input = input("Enter command: ")
execute_command(user_input)