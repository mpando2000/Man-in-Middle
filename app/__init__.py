from flask import Flask, render_template, request, jsonify, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from app.encryption_utils import decrypt_message, generate_keys
import os

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:20000902@localhost/secure_db'
    app.config['SECRET_KEY'] = 'your-secret-key'
    db.init_app(app)

    CORS(app)

    # Generate keys once (in a real-world app, keys should be securely managed and loaded from a file or database)
    private_key_pem, public_key_pem = generate_keys()

    # You can print or log the PEM keys if needed, but avoid printing sensitive information in production
    print(f"Generated Private Key:\n{private_key_pem.decode()}")
    print(f"Generated Public Key:\n{public_key_pem.decode()}")

    @app.route('/')
    def home():
        # Read the encrypted and decrypted messages from data.txt
        encrypted_message = ''
        decrypted_message = ''
        
        if os.path.exists('data.txt'):
            with open('data.txt', 'r') as file:
                lines = file.readlines()
                if len(lines) >= 4:
                    encrypted_message = lines[1].strip()
                    decrypted_message = lines[4].strip()

        return render_template('receiver.html', encrypted_message=encrypted_message, decrypted_message=decrypted_message)

    
    @app.route('/receiver', methods=['POST'])
    def receiver():
        try:
            # Get JSON data from the sender
            data = request.json
            encrypted_message_hex = data.get('encrypted_message')

            if not encrypted_message_hex:
                raise ValueError("No encrypted message provided")

            # Convert the hexadecimal message to bytes
            encrypted_message = bytes.fromhex(encrypted_message_hex)

            # Decrypt the message using the private key
            decrypted_message = decrypt_message(private_key_pem, encrypted_message)

            print(f"Decrypted Message: {decrypted_message}")
            print(f"Encrypted Message: {encrypted_message_hex}")

            # Write the encrypted and decrypted messages to data.txt
            if os.path.exists('data.txt'):
                os.remove('data.txt')  # Delete the file if it exists

            # Write the encrypted and decrypted messages to data.txt
            with open('data.txt', 'w') as file:
                file.write(f"Encrypted Message:\n{encrypted_message_hex}\n\n")
                file.write(f"Decrypted Message:\n{decrypted_message}\n")

            return jsonify({'status': 'success', 'message': 'Message received and processed'})

            

        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)})
    
    return app
