import os

def run_command(user_input):
    command = "echo " + user_input
    os.system(command)

run_command(input())