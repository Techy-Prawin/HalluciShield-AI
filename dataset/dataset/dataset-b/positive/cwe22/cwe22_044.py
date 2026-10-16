import os


def read_file(filename):
    base_path = '/var/www/files/'
    full_path = os.path.join(base_path, filename)  # vulnerable
    with open(full_path, 'r') as f:
        return f.read()