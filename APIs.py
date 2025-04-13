from flask import Flask, request, jsonify
from gevent.pywsgi import WSGIServer
from Sender import sender
from cryptoManager import EncryptionFactory
from Receiver import receiver
from SecureProtocol import SecureProtocol

app = Flask(__name__)
users = {}
stored_messages = {}

sender_instance = None
shared_encryptor = None
secure_protocol_checker = SecureProtocol()

@app.before_request
def check_https():
    full_url = request.url
    if not secure_protocol_checker.is_secure_protocol(full_url):
        return jsonify({"error": "Insecure protocol detected. Please use HTTPS."}), 403

@app.route('/Login', methods=['POST'])
def login():
    global sender_instance, shared_encryptor

    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"status": "Email and password required"}), 400

    encryption_factory = EncryptionFactory(method="RSA")
    sender_user = sender(encryption_factory, email, password)
    sender_instance = sender_user
    shared_encryptor = sender_user.encryptor

    if sender_user.login(email, password):
        users[email] = sender_user
        return jsonify({"status": "Login successful"}), 200
    else:
        return jsonify({"status": "Login failed"}), 401


@app.route('/send_message', methods=['POST'])
def send_message():
    data = request.get_json()

    receiver_email = data.get('receiver_email')
    message_content = data.get('message')

    if not sender_instance or not sender_instance.logged_in:
        return jsonify({"status": "User not logged in!"}), 401

    message = sender_instance.create_message(message_content, receiver_email)
    if not message:
        return jsonify({"status": "Failed to create message!"}), 500

    stored_messages[receiver_email.lower()] = (
        message.get_encrypted_content(),
        message.get_signature(),
        message.get_receiver_username()
    )

    return jsonify({"status": "Message sent and stored successfully!"}), 200


@app.route('/receive', methods=['POST'])
def receive_message():
    try:
        global shared_encryptor

        data = request.get_json()
        receiver_email = data['receiver_name']

        message_data = stored_messages.get(receiver_email)
        if not message_data:
            return jsonify({"error": "No message found for this receiver"}), 404

        message, signature, encrypted_receiver = message_data
        recv_instance = receiver()
        success = recv_instance.receiveMessage(message, encrypted_receiver, signature, shared_encryptor)

        if success:
            return jsonify({"status": "Message received and decrypted successfully!"}), 200
        else:
            return jsonify({"status": "Invalid signature or decryption failed!"}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    http_server = WSGIServer(
        ('0.0.0.0', 5000),
        app,
        keyfile="D:/Software-Project/private.key",
        certfile="D:/Software-Project/cert.crt"
    )
    try:
        print("Starting server...")
        http_server.serve_forever()
    except Exception as e:
        print(f"Error starting server... {e}")
