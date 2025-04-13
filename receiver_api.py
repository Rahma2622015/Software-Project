# from flask import Flask, request, jsonify
# from gevent.pywsgi import WSGIServer
#
# app = Flask(__name__)
#
#
# @app.route('/receive', methods=['POST'])
# def receive_message():
#     try:
#         encrypted_content = request.form['encrypted_content']
#         sender_signature = request.form['sender_signature']
#         receiver_name = request.form['receiver_name']
#         print(f"Message received for {receiver_name}.")
#         print(f"Encrypted Content: {encrypted_content}")
#         print(f"Sender Signature: {sender_signature}")
#
#         return jsonify({"status": "Message received successfully"}), 200
#
#     except Exception as e:
#         print(f"Error receiving message: {e}")
#         return jsonify({"status": "Failed to receive message"}), 400
#
#
# if __name__ == "__main__":
#
#     http_server = WSGIServer(
#         ('0.0.0.0', 5000),
#         app,
#         keyfile="D:/Software-Project/private.key",
#         certfile="D:/Software-Project/cert.crt"
#     )
#     try:
#         print("Starting server...")
#         http_server.serve_forever()
#     except Exception as e:
#         print(f"Error starting server... {e}")