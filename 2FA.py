import os
import sys
import shutil
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

        # Create new user with the provided input
        user = create_user.User(uname, password, salt)

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
            check_login.check_root_privileges()
            uname, password = check_login.get_user_credentials()

            user = check_login.User(uname, password)

            # use usrdel to delete username given
            try:
                command = f"sudo userdel -r {uname}"
                os.system(command)
            except Exception as e:
                print(f"Failed to update password for: '{uname}': {e}")

            # Request input: password
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

            # Request input: salt
            salt = create_user.request_valid_salt()

            # Create new user with the provided input
            user = create_user.User(uname, password, salt)

            # Print all the user info
            print("Password updated for: " + uname)

        else:
            print("Invalid Password or User does not exist.")

    elif initial_input == "4":
        check_login.check_root_privileges()
        uname, password = check_login.get_user_credentials()

        user = check_login.User(uname, password)

        if user.authenticate():
            print("Login successful.")
            print(f"Deleting user account for '{uname}'.")

            try:
                # Deleting the user and their home directory
                subprocess.run(["sudo", "userdel", "-r", uname], check=True)

                # Additional explicit check to remove the home directory, if it still exists
                home_dir_path = f"/home/{uname}"
                if os.path.exists(home_dir_path):
                    shutil.rmtree(home_dir_path)
                    print(
                        f"Home directory for '{uname}' has also been manually removed."
                    )

                print(f"User '{uname}' has been successfully deleted.")
            except subprocess.CalledProcessError as e:
                print(f"Failed to delete user '{uname}': {e}")
            except Exception as e:
                print(f"An error occurred: {e}")
        else:
            print("Invalid Password or User does not exist.")

    else:
        print("no valid option slected")


if __name__ == "__main__":
    main()
