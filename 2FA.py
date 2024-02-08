#!/usr/bin/env python3
import sys
import create_user
import check_login


def main():

    initial_input = input("Select an action:")
    Print("1) Create a user")
    Print("2) Login")
    Print("3) Update password")
    Print("4) Delete user account")

    if initial_input == 1:
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

        # Create new user with the provided input
        user = User(uname, password, salt)

        # Print all the user info
        print(user)

    elif initial_input == 2:
        check_root_privileges()
        uname, password = get_user_credentials()

        user = User(uname, password)

        if user.authenticate():
            print("Login successful.")
        else:
            print("Invalid Password or User does not exist.")

    # elif initial_input == 3:
    #     do this

    # elif initial_input == 4:
    #     do this

    else:
        print("no valid option slected")

        if __name__ == "__main__":
            main()
