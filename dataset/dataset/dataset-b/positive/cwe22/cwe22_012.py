import os

def read_user_file(filename):
    # User provides filename via command line
    base_dir = "/var/www/uploads"
    file_path = os.path.join(base_dir, filename)
    with open(file_path, 'r') as f:
        return f.read()
