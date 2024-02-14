import os
import sys
import subprocess
import re
from passlib.hash import sha512_crypt


class Login_User:
    def __init__(self, username, password, current_token_value):
        self.username = username
        self.password = password + current_token_value

    def authenticate(self):
        """Authenticate the user."""
        with open("/etc/shadow", "r") as fp:
            for line in fp:
                temp = line.split(":")
                if temp[0] == self.username:
                    salt_and_pass = temp[1].split("$")
                    salt = salt_and_pass[2]
                    # Calculate hash using the retrieved salt and the password
                    calculated_hash = sha512_crypt.hash(
                        self.password, salt_size=8, salt=salt, rounds=5000
                    )
                    return calculated_hash == temp[1]
        return False


def check_root_privileges():
    """Check if the program is running with root privileges."""
    if os.getuid() != 0:
        print("Please run as root.")
        sys.exit()


def get_user_credentials():
    """Get username and password from the user."""
    uname = input("Enter username: ")
    password = input(f"Enter Password for {uname}: ")
    return uname, password


class Create_User:
    def __init__(self, username, password, salt, current_token_value):

        # Check if the user already exists during object creation
        if self.user_exists(username):
            print("FAILURE: user " + username + " already exists")
            sys.exit()

        self.username = username
        self.password = password
        self.salt = salt
        self.current_token_value = current_token_value
        self.hashed_password = sha512_crypt.hash(
            password + current_token_value, salt_size=8, salt=salt, rounds=5000
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
            print

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

    print("Select an action:")
    print("1) Create a user")
    print("2) Login")
    print("3) Update password")
    print("4) Delete user account")
    initial_input = input()

    if initial_input == "1":
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

        # Add a new input for the Current Token Value
        current_token_value = input("Enter Current Token Value: ")

        # Create new user with the provided input
        user = Create_User(uname, password, salt, current_token_value)

        # Print all the user info
        print("SUCCESS: " + uname + " created")

    elif initial_input == "2":
        check_root_privileges()
        uname, password = get_user_credentials()

        current_token_value = input("Enter Current Token Value: ")
        user = Login_User(uname, password, current_token_value)
        next_token_value = request_input("Enter Next 2FA Token Value: ")
        if user.authenticate():
            print("SUCCESS: Login Successful")

            subprocess.run(
                ["sudo", "userdel", "-r", uname],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            salt = request_valid_salt()
            Create_User(uname, password, salt, next_token_value)
            print("2FA Token Value Updated")

        else:
            print("FAILURE: user " + uname + " does not exist")
            check_root_privileges()
            uname, password = get_user_credentials()

            current_token_value = input("Enter Current Token Value: ")
            next_token_value = input("Enter Next Token Value: ")
            user = Login_User(uname, password, current_token_value)

            if user.authenticate():
                print("SUCCESS: Login Successful")

                subprocess.run(
                    ["sudo", "userdel", "-r", uname],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                salt = request_valid_salt()
                Create_User(uname, password, salt, next_token_value)
                print("2FA Token Value Updated")

            else:
                print("FAILURE: either password or token incorrect.")

    elif initial_input == "3":
        check_root_privileges()
        uname, password = get_user_credentials()

        current_token_value = input("Enter Current Token Value: ")
        next_token_value = request_input("Enter Next 2FA Token Value: ")
        user = Login_User(uname, password, current_token_value)
        if user.authenticate():
            print("SUCCESS: Login Successful")
            # Request input for the new password
            password = request_input(
                "Enter New Password for the user: " + uname, "password"
            )
            re_password = request_input(
                "Re-enter New Password for the user", "password"
            )

            # Verify that the passwords match
            if password != re_password:
                print("Passwords do not match")
                sys.exit()

            print("Please Input New Salt Below: ")
            salt = request_valid_salt()

            try:
                # Using subprocess to call the passwd command, inputting the new password
                subprocess.run(
                    ["sudo", "userdel", "-r", uname],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )

                Create_User(uname, password, salt, next_token_value)
                print("SUCCESS: user " + uname + " updated")

            except Exception as e:
                print(f"Failed to update password for user {uname}. Error: {e}")

        else:
            print("FAILURE: user " + uname + " does not exist")
            check_root_privileges()
            uname, password = get_user_credentials()

            current_token_value = input("Enter Current Token Value: ")
            next_token_value = request_input("Enter Next 2FA Token Value: ")
            user = Login_User(uname, password, current_token_value)
            if user.authenticate():
                print("SUCCESS: Login Successful")
                # Request input for the new password
                password = request_input(
                    "Enter New Password for the user: " + uname, "password"
                )
                re_password = request_input(
                    "Re-enter New Password for the user", "password"
                )

                # Verify that the passwords match
                if password != re_password:
                    print("Passwords do not match")
                    sys.exit()

                print("Please Input New Salt Below: ")
                salt = request_valid_salt()

                try:
                    # Using subprocess to call the passwd command, inputting the new password
                    subprocess.run(
                        ["sudo", "userdel", "-r", uname],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                    )
                    Create_User(uname, password, salt, next_token_value)
                    print("SUCCESS: user " + uname + " updated")

                except Exception as e:
                    print(f"Failed to update password for user {uname}. Error: {e}")

            else:
                print("FAILURE: either password or token incorrect.")

    elif initial_input == "4":
        check_root_privileges()
        uname, password = get_user_credentials()

        current_token_value = input("Enter Current Token Value: ")
        user = Login_User(uname, password, current_token_value)

        if user.authenticate():
            print("SUCCESS: Login Successful")

            # giving info on whats going on
            print(f"Deleting user account for: " + uname)

            # use usrdel to delete username given
            subprocess.run(
                ["sudo", "userdel", "-r", uname],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            print("SUCCESS: user " + uname + " Deleted")
        else:
            print("FAILURE: user " + uname + " does not exist")

    else:
        print("no valid option slected")


if __name__ == "__main__":
    main()
