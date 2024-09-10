# pgp_message.py

import binascii
import zlib
from base64 import b64encode, b64decode
from Crypto.Cipher import PKCS1_OAEP, AES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA1
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from datetime import datetime

class PGPMessage:
    def __init__(self, public_key_id=None, encrypted_session_key=None, message=None):
        self.public_key_id = public_key_id
        self.encrypted_session_key = encrypted_session_key
        self.message = message

    @staticmethod
    def create_message(public_key, public_key_id, private_key, private_key_id, message_data, algorithm, compress, convert_r64):
        # Create signature
        if private_key:
            h = SHA1.new(message_data.encode())
            signature = str(pkcs1_15.new(private_key).sign(h))[2:-1]
            # signature = signature[:2]  # Leading two octets of message digest
            timestamp = datetime.now().isoformat()

            signed_message = timestamp + "\n" + private_key_id + "\n" + signature + "\n" + message_data
        else:
            signed_message = message_data

        # Create session key
        if public_key:
            session_key = get_random_bytes(16 if algorithm == "AES-128" else 24)
            rsa_cipher = PKCS1_OAEP.new(public_key)
            encrypted_session_key = str(rsa_cipher.encrypt(session_key))[2:-1]

            # Encrypt message
            if algorithm == "AES-128":
                symmetric_cipher = AES.new(session_key, AES.MODE_CFB)
            elif algorithm == "Triple DES":
                symmetric_cipher = DES3.new(session_key, DES3.MODE_CFB)
            else:
                raise ValueError("Unsupported algorithm")

            ciphertext = str(symmetric_cipher.encrypt(pad(message_data.encode(), AES.block_size)))[2:-1]
            timestamp = datetime.now().isoformat()

            encrypted_message = ciphertext + "\n" + timestamp
        else:
            encrypted_message = signed_message
            encrypted_session_key = ""

        # Compress signature and message if requested
        if compress:
            encrypted_message = str(zlib.compress(encrypted_message.encode()))[2:-1]

        parts = []
        if public_key_id:
            parts.append(public_key_id)
        if encrypted_session_key:
            parts.append(encrypted_session_key)
        parts.append(encrypted_message)

        combined_message = "\n".join(parts)

        if (convert_r64):
            radix64_message = b64encode(combined_message.encode()).decode() + "\n" + "1"
        else:
            radix64_message = combined_message + "\n" + "0"

        # # Combine all parts
        # combined_data = {
        #     'public_key_id': public_key_id,
        #     'encrypted_session_key': encrypted_session_key,
        #     'message': encrypted_message
        # }

        # # Convert to radix-64 if requested
        # if convert_r64:
        #     radix64_message = b64encode(f"{combined_data['public_key_id']}\n{combined_data['encrypted_session_key']}\n{combined_data['message']}".encode()).decode()
        # else:
        #     radix64_message = f"{combined_data['public_key_id']}\n{combined_data['encrypted_session_key']}\n{combined_data['message']}"

        return radix64_message
    
    @staticmethod
    def parse_message(encrypted_message, private_key, algorithm):
        # Determine if the message is Base64 encoded by checking the last line
        parts = encrypted_message.split('\n')
        if not parts:
            raise ValueError("Invalid message format")
    
        # Check if the last part indicates encoding
        is_base64 = parts[-1] == "1"
        if is_base64:
            message = "\n".join(parts[:-1])
        else:
            message = encrypted_message
    
        # Decode Base64 if needed
        if is_base64:
            try:
                decoded_message = b64decode(message).decode()
            except (binascii.Error, TypeError) as e:
                raise ValueError(f"Error decoding Base64 message: {e}")
        else:
            decoded_message = message
    
        # Split the decoded message into components
        parts = decoded_message.split('\n')
        if len(parts) < 2:
            raise ValueError("Invalid message format")
    
        # Determine message components based on number of parts
        public_key_id = None
        encrypted_session_key = None
        signature = None
        message = None
    
        if len(parts) == 3:
            # Format: [public_key_id, encrypted_session_key, message]
            public_key_id = parts[0]
            encrypted_session_key = parts[1]
            message = parts[2]
        elif len(parts) == 4:
            # Format: [timestamp, private_key_id, signature, message]
            timestamp = parts[0]
            public_key_id = parts[1]
            signature = parts[2]
            message = parts[3]
        else:
            raise ValueError("Invalid message format")
    
        # Decrypt session key if present
        if encrypted_session_key:
            rsa_cipher = PKCS1_OAEP.new(private_key)
            session_key = rsa_cipher.decrypt(b64decode(encrypted_session_key))
        else:
            session_key = None
    
        # Decrypt message if session key is available
        if session_key:
            if algorithm == "AES-128":
                symmetric_cipher = AES.new(session_key, AES.MODE_CFB)
            elif algorithm == "Triple DES":
                symmetric_cipher = DES3.new(session_key, DES3.MODE_CFB)
            else:
                raise ValueError("Unsupported algorithm")
    
            decrypted_message = unpad(symmetric_cipher.decrypt(b64decode(message)), AES.block_size)
    
            # Decompress message if it was compressed
            try:
                decompressed_message = zlib.decompress(decrypted_message).decode()
            except:
                decompressed_message = decrypted_message.decode()
        else:
            decompressed_message = message
    
        # Verify signature if it was included
        if signature:
            try:
                signature = b64decode(signature)
                h = SHA1.new(decompressed_message.encode())
                pkcs1_15.new(private_key).verify(h, signature)
            except (ValueError, TypeError):
                raise ValueError("Signature verification failed")
    
        return decompressed_message


    # @staticmethod
    # def parse_message(encrypted_message, private_key, algorithm):
    #     # Determine if the message is radix-64 encoded
    #     try:
    #         decoded_message = b64decode(encrypted_message).decode()
    #     except Exception as e:
    #         raise ValueError("Error decoding message")

    #     # Split the decoded message into components
    #     parts = decoded_message.split('\n')
    #     if len(parts) != 4:
    #         raise ValueError("Invalid message format")

    #     session_key_id, encrypted_session_key, signature, message = parts

    #     # Decrypt session key
    #     rsa_cipher = PKCS1_OAEP.new(private_key)
    #     session_key = rsa_cipher.decrypt(b64decode(encrypted_session_key))

    #     # Decrypt message
    #     if algorithm == "AES-128":
    #         symmetric_cipher = AES.new(session_key, AES.MODE_CFB)
    #     elif algorithm == "Triple DES":
    #         symmetric_cipher = DES3.new(session_key, DES3.MODE_CFB)
    #     else:
    #         raise ValueError("Unsupported algorithm")

    #     decrypted_message = unpad(symmetric_cipher.decrypt(b64decode(message)), AES.block_size)
        
    #     # Decompress message if it was compressed
    #     try:
    #         decompressed_message = zlib.decompress(decrypted_message).decode()
    #     except:
    #         decompressed_message = decrypted_message.decode()

    #     # Verify signature
    #     try:
    #         signature = zlib.decompress(b64decode(signature))
    #     except:
    #         pass

    #     h = SHA1.new(decompressed_message.encode())
    #     try:
    #         pkcs1_15.new(private_key).verify(h, signature)
    #     except (ValueError, TypeError):
    #         raise ValueError("Signature verification failed")

    #     return decompressed_message
