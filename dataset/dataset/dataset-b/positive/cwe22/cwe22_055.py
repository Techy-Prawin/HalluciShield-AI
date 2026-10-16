import os

def read_file(filename):
    path = os.path.join('/var/data', filename)
    with open(path, 'r') as f:
        return f.read()

user_input = input('Enter filename: ')
print(read_file(user_input))