import os

def read_file(filename):
    path = os.path.join('/var/data', filename)
    with open(path, 'r') as f:
        return f.read()

# Example usage
user_input = "../../etc/passwd"
result = read_file(user_input)