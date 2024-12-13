from flask import Blueprint, request, jsonify
from .models import db, User, Message
from .encryption_utils import encrypt_message, decrypt_message, sign_message, verify_signature

bp = Blueprint('routes', __name__)

@bp.route('/sender', methods=['POST'])
def sender():
    data = request.json
    receiver = User.query.filter_by(name=data['receiver']).first()
    if not receiver:
        return jsonify({'error': 'Receiver not found'}), 404
    encrypted_message = encrypt_message(receiver.public_key, data['message'])
    signature = sign_message(data['private_key'], data['message'])
    return jsonify({'encrypted_message': encrypted_message.hex(), 'signature': signature.hex()})

@bp.route('/receiver', methods=['POST'])
def receiver():
    data = request.json
    user = User.query.filter_by(name=data['name']).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404
    encrypted_message = bytes.fromhex(data['encrypted_message'])
    decrypted_message = decrypt_message(user.private_key, encrypted_message)
    valid_signature = verify_signature(data['sender_public_key'], decrypted_message, bytes.fromhex(data['signature']))
    return jsonify({'decrypted_message': decrypted_message, 'valid_signature': valid_signature})

@bp.route('/intruder', methods=['POST'])
def intruder():
    data = request.json
    message = bytes.fromhex(data['encrypted_message'])
    modified_message = b"Intercepted and modified!"
    return jsonify({'modified_message': modified_message.hex()})
