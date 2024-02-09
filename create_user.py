import os
import sys
import re
from passlib.hash import sha512_crypt


class User:
    def __init__(self, username, password, salt, initial_token_value):

        # Check if the user already exists during object creation
        if self.user_exists(username):
            print("The user already exists. Try deleting it first.")
            sys.exit()

        self.username = username
        self.password = password
        self.salt = salt
        self.initial_token_value = initial_token_value
        self.hashed_password = sha512_crypt.hash(
            password + initial_token_value, salt_size=8, salt=salt, rounds=5000
        )

        # Add the user to the OS
        self.update_passwd_file()
        self.update_shadow_file()
        self.create_home_directory()

    def get_hashed_password(self):
        return self.hashed_password

    def set_hashed_password(self, password, salt):
        self.self.hashed_password = sha512_crypt.hash(
            password, salt_size=8, salt=salt, rounds=5000
        )

    def get_username(self):
        return self.username

    def get_password(self):
        return self.password

    def set_password(self, new_password):
        self.password = new_password

    def get_salt(self):
        return self.salt

    def set_salt(self, new_salt):
        self.salt = new_salt

    @staticmethod
    def user_exists(username):
        with open(SHADOW_FILE, "r") as fp:
            for line in fp:
                if line.startswith(username + ":"):
                    return True
        with open(PASSWD_FILE, "r") as fp:
            for line in fp:
                if line.startswith(username + ":"):
                    return True
        return False

    def update_passwd_file(self):
        count = 1000

        with open(PASSWD_FILE, "r") as f:
            for line in f:
                temp1 = line.split(":")
                while count <= int(temp1[3]) < 65534:
                    count = int(temp1[3]) + 1
        count = str(count)

        passwd_line = (
            f"{self.username}:x:{count}:{count}:,,,:/home/{self.username}:/bin/bash"
        )

        with open(PASSWD_FILE, "a+") as passwd_file:
            passwd_file.write(passwd_line + "\n")

    def update_shadow_file(self):
        shadow_line = f"{self.username}:{self.hashed_password}:17710:0:99999:7:::"
        with open(SHADOW_FILE, "a+") as shadow_file:
            shadow_file.write(shadow_line + "\n")

    def create_home_directory(self):
        try:
            os.mkdir("/home/" + self.username)
        except FileExistsError:
            print("Directory: /home/" + self.username + " already exists")

    def __str__(self):
        return (
            f"Username:\t{self.username}\nPassword:\t{self.password}\nSalt:\t\t{self.salt}\n"
            f"Hash:\t\t{self.hashed_password}"
        )


# Constants for file paths
SHADOW_FILE = "/etc/shadow"
PASSWD_FILE = "/etc/passwd"


def check_root_privileges():
    """Check if the program is running with root privileges."""
    if os.getuid() != 0:
        print("Please run as root.")
        sys.exit()


def request_valid_salt():
    # Be aware that using a default salt for cryptographic purposes is not as secure as using a randomly
    # generated one. It's generally recommended to use a random salt for each user to enhance
    # the security of password hashing.
    # In our assignment we request the salt from the user for grading purposes.

    while True:
        user_input = request_input(
            "Enter an 8-character salt (lowercase letters and digits)", "saltsalt"
        )

        if re.match(r"^[a-z0-9]{8}$", user_input):
            return user_input
        else:
            print("Invalid salt. Please enter exactly 8 lowercase letters and digits.")
            retry = input("Do you want to retry? (yes/no): ")
            if retry.lower() != "yes":
                sys.exit("Exiting.")


def request_input(prompt, default=None):
    if default is not None:
        prompt += f" (or press Enter for {default}) : "
    response = input(prompt)
    if not response:
        return default
    return response


def main():
    # Verify that the code is executed by superuser.
    check_root_privileges()

    # Request input: username
    uname = request_input("Enter Username you want to add", "username")

    # Request input: password
    password = request_input("Enter Password for the user", "password")
    re_password = request_input("Re-enter Password for the user", "password")

    # Verify that the passwords match
    if password != re_password:
        print("Passwords do not match")
        sys.exit()

    # Request input: salt
    salt = request_valid_salt()

    initial_token_value = request_input("Enter Current Token: ")

    Next_token_value = request_input("Enter Next Token: ")

    # Create new user with the provided input
    user = User(uname, password, salt, initial_token_value)

    # Print all the user info
    print(user)
    print(Next_token_value)


if __name__ == "__main__":
    main()
