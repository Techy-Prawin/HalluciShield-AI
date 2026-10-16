import os

def run_command(user_input):
    os.system(user_input)

user_input = input("Enter command: ")
run_command(user_input)