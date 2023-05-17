import hashlib
import getpass
from cryptography.fernet import Fernet
import json
import os
import base64

# Generate a key
def generate_key():
    key = Fernet.generate_key()
    with open('key.key', 'wb') as key_file:
        key_file.write(key)

# Load the key from file
def load_key():
    with open('key.key', 'rb') as key_file:
        key = key_file.read()
    return key

# Encrypt password
def encrypt_password(key, password):
    f = Fernet(key)
    encrypted_password = f.encrypt(password.encode())
    return encrypted_password

# Decrypt password
def decrypt_password(key, encrypted_password):
    f = Fernet(key)
    decrypted_password = f.decrypt(encrypted_password).decode()
    return decrypted_password

# Store password
def store_password():
    account = input("Enter the account name: ")
    password = getpass.getpass("Enter the password: ")

    try:
        with open('passwords.json', 'r') as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}

    with open('passwords.json', 'w') as file:
        data[account] = password
        json.dump(data, file)

    print("Password stored successfully!")


# Retrieve password
def retrieve_password():
    account = input("Enter the account name: ")

    # Load the key
    key = load_key()
    with open('passwords.json', 'r') as file:
        data = json.load(file)
        if account in data:
            encrypted_password = data[account]

            # Pad the encrypted password with "=" characters if necessary
            padding = len(encrypted_password) % 4
            if padding:
                encrypted_password += "=" * (4 - padding)

            decrypted_password = decrypt_password(key, encrypted_password.encode())
            print("Retrieved password:", decrypted_password)
        else:
            print("Account not found!")


# Function to hash the user's master password
def hash_password(password):
    sha = hashlib.sha256()
    sha.update(password.encode('utf-8'))
    return sha.hexdigest()

# Function to validate the user's master password
def validate_password(hashed_password, password):
    sha = hashlib.sha256()
    sha.update(password.encode('utf-8'))
    return hashed_password == sha.hexdigest()

# Main menu
def main():
    generate_key()  # Generate the encryption key
while True:
        print("Password Manager")
        print("1. Store a Password")
        print("2. Retrieve a Password")
        print("3. Quit")

        choice = input("Enter your choice: ")

        if choice == "1":
            store_password()
        elif choice == "2":
           retrieve_password()
        elif choice == "3":
            print("Exiting...")
            break
        else:
            print("Invalid choice! Please try again.")

# Entry point of the program
if __name__ == "__main__":
    main()

