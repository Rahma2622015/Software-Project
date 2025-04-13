from SecureProtocol import SecureProtocol
from queue import Queue
from Sender import sender
from RSAEncryption import RSAEncryptor
import base64

class Server:
    def __init__(self, protocol: SecureProtocol, sender_instance: sender):
        self.protocol = protocol
        self.sender = sender_instance
        self.messages_queue = Queue()

    def receive_message(self) -> bool:
        encryptor, message, signature, receiver_name = self.sender.send_message()
        if not encryptor or not message or not signature or not receiver_name:
            print("No data to receive.")
            return False

        if isinstance(encryptor, RSAEncryptor):
            decrypted_receiver = encryptor.decrypt(receiver_name)

        if encryptor.verifySignature(decrypted_receiver, signature, self.sender.getPublicKey()):
            print("[Server] Receiving message...")
            self.messages_queue.put(message)
            self.messages_queue.put(signature)
            self.messages_queue.put(receiver_name)
            return True
        else:
            print("❌ Signature not valid.")
            return False

    def forward_message(self, receiver_instance) -> bool:
        if self.messages_queue.empty():
            print("[Server] No messages to forward.")
            return False

        message = self.messages_queue.get()
        signature = self.messages_queue.get()
        receiver_name = self.messages_queue.get()

        receiver_url = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview#https"
        if not self.protocol.is_secure_protocol(receiver_url):
            print("Protocol is not secure, message not sent.")
            return False

        payload = {
            "encrypted_content": base64.b64encode(message).decode(),
            "sender_signature": base64.b64encode(signature).decode(),
        }

        success = self.protocol.sendData(receiver_url, payload)
        if success:
            print(f"[Server] Forwarding message to {receiver_name}")
            return receiver_instance.receiveMessage(message, receiver_name, signature, self.sender.encryptor)
        else:
            print("Protocol not secure!")
            return False
