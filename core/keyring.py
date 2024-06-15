import os
import json
from datetime import datetime
from Crypto.PublicKey import RSA


class Keyring:
    def __init__(self):
        self.private_keyring_path = "data/private_keys/private_keyring.json"
        self.public_keyring_path = "data/public_keys/public_keyring.json"
        self.private_keyring = self.load_keyring(self.private_keyring_path)
        self.public_keyring = self.load_keyring(self.public_keyring_path)

    @staticmethod
    def load_keyring(path):
        if os.path.exists(path) and os.path.getsize(path) > 0:
            with open(path, "r") as file:
                return json.load(file)

        return []

    @staticmethod
    def save_keyring(path, keyring):
        with open(path, "w") as file:
            json.dump(keyring, file, indent=4)

    def generate_key_pair(self, name, email, key_size, password):
        key = RSA.generate(key_size)
        private_key = key.export_key(passphrase=password).decode()
        public_key = key.public_key().export_key().decode()
        key_id = self.calculate_key_id(key)
        timestamp = datetime.now().isoformat()

        private_key_entry = {
            "name": name,
            "email": email,
            "key_size": key_size,
            "key_id": key_id,
            "private_key": private_key,
            "public_key": public_key,
            "timestamp": timestamp
        }

        public_key_entry = {
            "name": name,
            "email": email,
            "key_size": key_size,
            "key_id": key_id,
            "public_key": public_key,
            "timestamp": timestamp
        }

        self.private_keyring.append(private_key_entry)
        self.public_keyring.append(public_key_entry)

        self.save_keyring(self.private_keyring_path, self.private_keyring)
        self.save_keyring(self.public_keyring_path, self.public_keyring)

        return private_key, public_key

    @staticmethod
    def calculate_key_id(key):
        key_id = key.n % (2 ** 64)
        return hex(key_id)

    def get_private_keys(self):
        return self.private_keyring

    def get_public_keys(self):
        return self.public_keyring

    def delete_key_pair(self, key_id):
        self.private_keyring = [key for key in self.private_keyring if key["key_id"] != key_id]
        self.public_keyring = [key for key in self.public_keyring if key["key_id"] != key_id]

        self.save_keyring(self.private_keyring_path, self.private_keyring)
        self.save_keyring(self.public_keyring_path, self.public_keyring)

    def import_key(self, key_data, is_private):
        keyring = self.private_keyring if is_private else self.public_keyring
        keyring.append(key_data)
        path = self.private_keyring_path if is_private else self.public_keyring_path
        self.save_keyring(path, keyring)

    def export_key(self, key_id, is_private):
        keyring = self.private_keyring if is_private else self.public_keyring
        key = next((key for key in keyring if key["key_id"] == key_id), None)
        return key


if __name__ == "__main__":
    keyring = Keyring()
    private_key, public_key = keyring.generate_key_pair("Darko", "dare@gmail.com", 1024, "dare123")
    print(f"Private Key: {private_key}")
    print(f"Public Key: {public_key}")
    print(f"Private Keyring: {keyring.get_private_keys()}")
    print(f"Public Keyring: {keyring.get_public_keys()}")
