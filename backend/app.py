from flask import Flask, request, jsonify
from Crypto.Cipher import DES3, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from flask_cors import CORS 
import base64
import os  
from dotenv import load_dotenv

load_dotenv()



app = Flask(__name__)
CORS(app)



def pad_key(key, required_length):
    if len(key) < required_length:
        return key.ljust(required_length, '\0')  
    return key[:required_length] 


def des3_encrypt(message, key):
    key = pad_key(key, 24).encode()  
    cipher = DES3.new(key, DES3.MODE_ECB)
    padded_message = pad(message.encode(), DES3.block_size)
    encrypted = cipher.encrypt(padded_message)
    return base64.b64encode(encrypted).decode()

def des3_decrypt(encrypted_message, key):
    key = pad_key(key, 24).encode()  
    cipher = DES3.new(key, DES3.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_message))
    return unpad(decrypted, DES3.block_size).decode()

def aes_encrypt(message, key):
    key = pad_key(key, 16).encode() 
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pad(message.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded_message)
    return base64.b64encode(encrypted).decode()

def aes_decrypt(encrypted_message, key):
    key = pad_key(key, 16).encode() 
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(encrypted_message))
    return unpad(decrypted, AES.block_size).decode()
 
def otp_encrypt(message: str, key: str) -> str:

    message_bytes = message.encode('utf-8')
    key_bytes = key.encode('utf-8')  

    if len(key_bytes) != len(message_bytes):
        raise ValueError("Key must be the same length as the message")

    encrypted_bytes = bytes([m ^ k for m, k in zip(message_bytes, key_bytes)])
    
    return base64.b64encode(encrypted_bytes).decode('utf-8')

def otp_decrypt(ciphertext: str, key: str) -> str:
    encrypted_bytes = base64.b64decode(ciphertext)
    key_bytes = key.encode('utf-8')  
    
    if len(key_bytes) != len(encrypted_bytes):
        raise ValueError("Key must match ciphertext length")
    
    decrypted_bytes = bytes([e ^ k for e, k in zip(encrypted_bytes, key_bytes)])
    return decrypted_bytes.decode('utf-8')



def rsa_encrypt(message: str, chunk_size: int = 214) -> str:  
    try:
        # Get public key from environment variable
        public_key_pem = os.getenv('RSA_PUBLIC_KEY')
        if not public_key_pem:
            raise ValueError("RSA_PUBLIC_KEY not found in .env file")
            
        public_key = RSA.import_key(public_key_pem)
        cipher = PKCS1_OAEP.new(public_key)
        
        message_bytes = message.encode('utf-8')
        chunks = [message_bytes[i:i+chunk_size] for i in range(0, len(message_bytes), chunk_size)]
        
        encrypted_chunks = []
        for chunk in chunks:
            encrypted = cipher.encrypt(chunk)
            encrypted_chunks.append(base64.b64encode(encrypted).decode('utf-8'))
        
        return ','.join(encrypted_chunks)  
    
    except Exception as e:
        raise ValueError(f"RSA encryption error: {str(e)}")


def rsa_decrypt(ciphertext: str) -> str:
    try:
        # Get private key from environment variable
        private_key_pem = os.getenv('RSA_PRIVATE_KEY')
        if not private_key_pem:
            raise ValueError("RSA_PRIVATE_KEY not found in .env file")
            
        private_key = RSA.import_key(private_key_pem)
        cipher = PKCS1_OAEP.new(private_key)
        
        encrypted_chunks = ciphertext.split(',')
        decrypted_bytes = bytearray()
        
        for chunk in encrypted_chunks:
            encrypted = base64.b64decode(chunk)
            decrypted = cipher.decrypt(encrypted)
            decrypted_bytes.extend(decrypted)
        
        return decrypted_bytes.decode('utf-8')
    
    except Exception as e:
        raise ValueError(f"RSA decryption error: {str(e)}")
    

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    message = data.get('message')
    algorithm = data.get('algorithm')
    key = data.get('key', '') 

    if not message or not algorithm:
        return jsonify({'error': 'Missing message or algorithm'}), 400

    try:
        if algorithm == 'otp':
            encrypted_message = otp_encrypt(message, key)
        elif algorithm == '3des':
            encrypted_message = des3_encrypt(message, key)
        elif algorithm == 'aes':
            encrypted_message = aes_encrypt(message, key)
        elif algorithm == 'rsa':
            encrypted_message = rsa_encrypt(message)
        else:
            return jsonify({'error': 'Invalid algorithm'}), 400
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    return jsonify({'encrypted_message': encrypted_message})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    message = data.get('message')
    algorithm = data.get('algorithm')
    key = data.get('key', '')  
    if not message or not algorithm:
        return jsonify({'error': 'Missing message or algorithm'}), 400

    try:
        if algorithm == 'otp':
            decrypted_message = otp_decrypt(message, key)
        elif algorithm == '3des':
            decrypted_message = des3_decrypt(message, key)
        elif algorithm == 'aes':
            decrypted_message = aes_decrypt(message, key)
        elif algorithm == 'rsa':
            decrypted_message = rsa_decrypt(message)
        else:
            return jsonify({'error': 'Invalid algorithm'}), 400
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    return jsonify({'decrypted_message': decrypted_message})

if __name__ == '__main__':
    app.run(debug=True)
