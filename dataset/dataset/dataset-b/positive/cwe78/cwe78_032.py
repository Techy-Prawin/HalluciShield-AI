import os

def delete_user(username):
    # Construct command to delete a user
    cmd = f"sudo userdel -r {username}"
    os.system(cmd)  # Vulnerable: user input not sanitized
    print(f"User {username} deleted.")