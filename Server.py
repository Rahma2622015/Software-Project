from SecureProtocol import SecureProtocol
from queue import Queue
from Sender import sender
from RSAEncryption import RSAEncryptor
from Receiverinfocryptor import Receiverinfo
import base64
from functions_for_database import functions_DB 

class Server:
    def __init__(self, protocol: SecureProtocol, sender_instance: sender, receiver_info: Receiverinfo):
        self.protocol = protocol
        self.sender = sender_instance
        self.messages_queue = Queue()
        self.receive_info = receiver_info
        self.db = functions_DB()

    def receive_message(self, message, signature, receiver_name, encryptor):
        self.receive_info = encryptor
        decrypted_receiver = self.receive_info.decrypt(receiver_name)

        if not self.db.receiver_exists(decrypted_receiver):
            print(f"[Server] Receiver '{decrypted_receiver}' not found in database.")
            return False

        if encryptor.verifySignature(decrypted_receiver, signature, self.sender.getPublicKey()):
            print("[Server] Receiving message...")
            self.messages_queue.put((message, signature, receiver_name))
            return True
        else:
            print(" Signature not valid.")
            return False

    def forward_message(self, receiver_instance, encryptor) -> bool:
        self.receive_info = encryptor
        if not self.messages_queue.empty():
            message_data = self.messages_queue.get()
            encrypted_message = message_data[0]         # ده لازم يكون bytes
            signature = message_data[1]
            receiver_name = message_data[2]

            try:
                # تجهيز البيانات لإرسالها للسيرفر
                payload = {
                    "encrypted_content": base64.b64encode(encrypted_message).decode(),
                    "signature": signature,
                    "receiver_username": receiver_name
                }

                print("[Server] Forwarding message to receiver...")

                # تجربة تمرير الرسالة لراسيڤر داخلياً (وليس URL حقيقي لأن المشروع داخلي)
                if receiver_instance.receive_message(payload, encryptor):
                    print(f"[Server] Message forwarded and received successfully.")
                    return True
                else:
                    print("[Server] Receiver failed to process the message.")
                    return False

            except Exception as e:
                print(f"[Server] Error during message forwarding: {e}")
                return False
        else:
            print("[Server] No messages to forward.")
            return False