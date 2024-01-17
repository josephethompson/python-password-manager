from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import os
import json

def validate_username(username):
    return username.isalnum() and 1 <= len(username) <= 25

def get_master_password_hash(password):
    hasher = SHA256.new()
    hasher.update(password.encode())
    return hasher.digest()

def pad(data):
    return data + b"\0" * (AES.block_size - len(data) % AES.block_size)

def unpad(data):
    return data.rstrip(b"\0")

def encrypt(data, key):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(data))

def decrypt(data, key):
    iv = data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data[AES.block_size:]))

def display_account_info(account, credentials):
    print(f"Account: {account}, Username: {credentials['username']}, Password: {credentials['password']}")

def find_best_matches(search_term, data):
    return [account for account in data if search_term.lower() in account.lower()]

def main():
    password_file = 'passwords.enc'
    data = {}

    if os.path.exists(password_file):
        print("Password file exists. Please enter the master password to access it.")
        password = input("Enter master password: ")
        master_password_hash = get_master_password_hash(password)

        try:
            with open(password_file, 'rb') as f:
                encrypted_data = f.read()

            decrypted_data = decrypt(encrypted_data, master_password_hash).decode()
            data = json.loads(decrypted_data)
        except Exception as e:
            print("Error: Unable to decrypt the file. The password may be incorrect.")
            return
    else:
        while True:
            username = input("Create a username: ")
            if validate_username(username):
                break
            print("Invalid username. Please use only alphanumeric characters and less than 25 characters.")

        password = input("Create a master password: ")
        print("Remember your master password! If you forget it, you cannot recover your passwords.")

        master_password_hash = get_master_password_hash(password)
        with open(password_file, 'wb') as f:
            f.write(encrypt(json.dumps(data).encode(), master_password_hash))

    while True:
        action = input("Do you want to add a new account, search for an account, list all accounts, or exit (add/search/list/exit)? ").lower()
        if action == 'exit':
            break

        if action == 'add':
            account_name = input("Enter the account name: ")
            account_username = input("Enter the account username: ")
            account_password = input("Enter the account password: ")

            with open(password_file, 'rb') as f:
                encrypted_data = f.read()

            decrypted_data = decrypt(encrypted_data, master_password_hash).decode()
            data = json.loads(decrypted_data)

            data[account_name] = {'username': account_username, 'password': account_password}

            with open(password_file, 'wb') as f:
                f.write(encrypt(json.dumps(data).encode(), master_password_hash))

        elif action == 'search':
            search_account = input("Enter the account name to search: ")
            matches = find_best_matches(search_account, data)
            if matches:
                print("Matching accounts:")
                for match in matches:
                    display_account_info(match, data[match])
            else:
                print("No matching accounts found.")
        elif action == 'list':
            if data:
                print("Listing all accounts:")
                for account, credentials in data.items():
                    display_account_info(account, credentials)
            else:
                print("No accounts stored.")

    print("Exiting the program. Your data is stored securely.")

if __name__ == "__main__":
    main()
