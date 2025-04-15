from flask import Flask, request, jsonify
from gevent.pywsgi import WSGIServer
from Sender import sender, f
from cryptoManager import EncryptionFactory
from Server import Server
from Receiver import receiver
from SecureProtocol import SecureProtocol
from Receiverinfocryptor import Receiverinfo
import base64

app = Flask(__name__)

users = {}
stored_messages = {}

sender_instance = None
factory = EncryptionFactory(method="RSA")
encryptor = factory.get_encryptor()
receiver_info = Receiverinfo(encryptor)
receiver_instance = receiver()
secure_protocol_checker = SecureProtocol()
server_instance = None


@app.before_request
def check_https():
    full_url = request.url
    if not secure_protocol_checker.is_secure_protocol(full_url):
        return jsonify({"error": "Insecure protocol detected. Please use HTTPS."}), 403


@app.route('/Login', methods=['POST'])
def login():
    global sender_instance, server_instance

    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email:
        return jsonify({"status": "Email required"}), 400
    if not password:
        return jsonify({"status": "Password required"}), 400
    if not f.is_strong_password(password):
        return jsonify({"status": "Password should be strong"}), 400
    if not f.is_valid_email(email):
        return jsonify({"status": "Invalid email"}), 400
    if not email and not password:
        return jsonify({"status": "Empty email & empty password"}), 400

    encryption_factory = EncryptionFactory(method="RSA")
    sender_user = sender(encryption_factory, email, password)
    sender_instance = sender_user

    if sender_user.login(email, password):
        users[email] = sender_user
        server_instance = Server(secure_protocol_checker, sender_instance, receiver_info)
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

    if not receiver_email:
        return jsonify({"status": "Receiver email is required!"}), 400
    if not message_content:
        return jsonify({"status": "Message content is required!"}), 400

    message = sender_instance.create_message(message_content, receiver_email)
    if not message:
        return jsonify({"status": "Failed to create message!"}), 500

    stored_messages[receiver_email.lower()] = (
        message.get_encrypted_content(),
        message.get_signature(),
        base64.b64encode(message.get_receiver_username()).decode()
    )

    return jsonify({"status": "Message sent and stored successfully!"}), 200


@app.route('/server', methods=['POST'])
def server_messages():
    try:
        data = request.get_json()
        receiver_email = data.get("receiver_email")

        if not receiver_email:
            return jsonify({"status": "Receiver email is required"}), 400

        receiver_email = receiver_email.lower()

        message, signature, encrypted_receiver = stored_messages[receiver_email]
        encrypted_receiver = base64.b64decode(encrypted_receiver)

        server_success = server_instance.receive_message(
            message, signature, encrypted_receiver, sender_instance.encryptor
        )

        if server_success:
            forwarded = server_instance.forward_message(receiver_instance, sender_instance.encryptor)
            if forwarded:
                return jsonify({"status": receiver_instance.get_received_messages()}), 200
            else:
                return jsonify({"status": "Failed to forward message to receiver!"}), 500
        else:
            return jsonify({"status": "Server failed to validate the message!"}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    http_server = WSGIServer(
        ('0.0.0.0', 5000),
        app,
        keyfile=r"D:\Software-Project\ssl6\private.key",
        certfile=r"D:\Software-Project\ssl6\cert.crt"
    )
    try:
        print("Starting server...")
        http_server.serve_forever()
    except Exception as e:
        print(f"Error starting server... {e}")