from flask import Flask, request, jsonify
from Crypto.Cipher import DES3, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from flask_cors import CORS 
import base64

app = Flask(__name__)


CORS(app)

import base64

def otp_encrypt(message: str, key: str) -> str:
    """Proper OTP Encryption with string key handling"""
    # Convert both message and key to bytes
    message_bytes = message.encode('utf-8')
    key_bytes = key.encode('utf-8')  # Convert string key to bytes
    
    # Verify lengths
    if len(key_bytes) != len(message_bytes):
        raise ValueError("Key must be the same length as the message")
    
    # Perform XOR
    encrypted_bytes = bytes([m ^ k for m, k in zip(message_bytes, key_bytes)])
    
    return base64.b64encode(encrypted_bytes).decode('utf-8')

def otp_decrypt(ciphertext: str, key: str) -> str:
    """Proper OTP Decryption with string key handling"""
    encrypted_bytes = base64.b64decode(ciphertext)
    key_bytes = key.encode('utf-8')  # Convert string key to bytes
    
    if len(key_bytes) != len(encrypted_bytes):
        raise ValueError("Key must match ciphertext length")
    
    decrypted_bytes = bytes([e ^ k for e, k in zip(encrypted_bytes, key_bytes)])
    return decrypted_bytes.decode('utf-8')

# Ensure the key is a valid length for 3DES and AES
def pad_key(key, required_length):
    if len(key) < required_length:
        return key.ljust(required_length, '\0')  # pad with null bytes
    return key[:required_length]  # trim if too long

# 3DES Encryption and Decryption
# 3DES Encryption and Decryption
def des3_encrypt(message, key):
    key = pad_key(key, 24).encode()  # Ensure key is bytes
    cipher = DES3.new(key, DES3.MODE_ECB)
    padded_message = pad(message.encode(), DES3.block_size)
    encrypted = cipher.encrypt(padded_message)
    return base64.b64encode(encrypted).decode()

def des3_decrypt(encrypted_message, key):
    key = pad_key(key, 24).encode()  # Ensure key is bytes
    cipher = DES3.new(key, DES3.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_message))
    return unpad(decrypted, DES3.block_size).decode()

# AES Encryption and Decryption
def aes_encrypt(message, key):
    key = pad_key(key, 16).encode()  # Ensure key is bytes
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pad(message.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded_message)
    return base64.b64encode(encrypted).decode()

def aes_decrypt(encrypted_message, key):
    key = pad_key(key, 16).encode()  # Ensure key is bytes
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_message))
    return unpad(decrypted, AES.block_size).decode()
 

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    message = data['message']
    key = data['key']
    algorithm = data['algorithm']

    if algorithm == 'otp':
        encrypted_message = otp_encrypt(message, key)
    elif algorithm == '3des':
        encrypted_message = des3_encrypt(message, key)
    elif algorithm == 'aes':
        encrypted_message = aes_encrypt(message, key)
    else:
        return jsonify({'error': 'Invalid algorithm'}), 400

    return jsonify({'encrypted_message': encrypted_message})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    message = data['message']
    key = data['key']
    algorithm = data['algorithm']

    if algorithm == 'otp':
        decrypted_message = otp_decrypt(message, key)
    elif algorithm == '3des':
        decrypted_message = des3_decrypt(message, key)
    elif algorithm == 'aes':
        decrypted_message = aes_decrypt(message, key)
    else:
        return jsonify({'error': 'Invalid algorithm'}), 400

    return jsonify({'decrypted_message': decrypted_message})

if __name__ == '__main__':
    app.run(debug=True)
