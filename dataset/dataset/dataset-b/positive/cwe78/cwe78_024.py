import os
def main():
    user_input = input("Enter file to delete: ")
    os.system(f"rm -rf {user_input}")
if __name__ == "__main__":
    main()