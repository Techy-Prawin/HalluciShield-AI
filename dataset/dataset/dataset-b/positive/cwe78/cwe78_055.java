import subprocess

def run_command(user_input):
    cmd = "ls " + user_input
    subprocess.call(cmd, shell=True)

if __name__ == "__main__":
    user_input = input("Enter directory: ")
    run_command(user_input)