import os
import sys
import subprocess
import create_user
import check_login


def main():

    print("Select an action:")
    print("1) Create a user")
    print("2) Login")
    print("3) Update password")
    print("4) Delete user account")
    initial_input = input()

    if initial_input == "1":
        # Verify that the code is executed by superuser.
        create_user.check_root_privileges()

        # Request input: username
        uname = create_user.request_input("Enter Username you want to add", "username")

        # Request input: password
        password = create_user.request_input("Enter Password for the user", "password")
        re_password = create_user.request_input(
            "Re-enter Password for the user", "password"
        )

        # Verify that the passwords match
        if password != re_password:
            print("Passwords do not match")
            sys.exit()

        # Request input: salt
        salt = create_user.request_valid_salt()

        # Request input: IT Token
        Initial_Token_IT = create_user.request_input("Input Initial Token: ")

        # Create new user with the provided input
        user = create_user.User(uname, password, salt, Initial_Token_IT)

        # Print all the user info
        print(user)

    elif initial_input == "2":
        check_login.check_root_privileges()
        uname, password = check_login.get_user_credentials()

        user = check_login.User(uname, password)

        if user.authenticate():
            print("Login successful.")
        else:
            print("Invalid Password or User does not exist.")

    elif initial_input == "3":
        check_login.check_root_privileges()
        uname, password = check_login.get_user_credentials()

        user = check_login.User(uname, password)

        if user.authenticate():
            print("Login successful.")

            # Use subprocess to delete the username given
            subprocess.run(
                ["sudo", "userdel", "-r", uname],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )

            # Request input for the new password
            password = create_user.request_input(
                "Enter New Password for the user: " + uname, "password"
            )
            re_password = create_user.request_input(
                "Re-enter New Password for the user", "password"
            )

            # Verify that the passwords match
            if password != re_password:
                print("Passwords do not match")
                sys.exit()

            # Request input for the new salt
            salt = create_user.request_valid_salt()

            # Recreate the user with the new password and salt
            try:
                user = create_user.User(uname, password, salt)
                print("Password updated for user: " + uname)
            except Exception:
                # suppress all errors
                pass

        else:
            print("Invalid Password or User does not exist.")

    elif initial_input == "4":
        check_login.check_root_privileges()
        uname, password = check_login.get_user_credentials()

        user = check_login.User(uname, password)

        if user.authenticate():
            print("Login successful.")

            # giving info on whats going on
            print(f"Deleting user account for '{uname}'.")

            # use usrdel to delete username given
            subprocess.run(
                ["sudo", "userdel", "-r", uname],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            print(f"Deleted user: " + uname)
        else:
            print("Invalid Password or User does not exist.")

    else:
        print("no valid option slected")


if __name__ == "__main__":
    main()
