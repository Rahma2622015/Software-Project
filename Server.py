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

    def receive_message(self) -> bool:
        encryptor, message, signature, receiver_name = self.sender.send_message()
        if not encryptor or not message or not signature or not receiver_name:
            print("No data to receive.")
            return False

        decrypted_receiver = self.receive_info.decryptReceiverInfo(receiver_name)

        if not self.db. receiver_exists(decrypted_receiver):
            print(f"[Server] Receiver '{decrypted_receiver}' not found in database.")
            return False
        #check receiver in database
        if encryptor.verifySignature(decrypted_receiver, signature, self.sender.getPublicKey()):
            print("[Server] Receiving message...")
            self.messages_queue.put((message, signature, receiver_name))
            return True
        else:
            print("❌ Signature not valid.")
            return False

    def forward_message(self, receiver_instance, encryptor) -> bool:
        if not self.messages_queue.empty():
            # فك تجميع القيم بشكل صحيح
            message_data = self.messages_queue.get()
            message = message_data[0]  # الرسالة المشفرة
            signature = message_data[1]  # التوقيع
            receiver_name = message_data[2]  # اسم المستلم

            receiver_url = "https://192.168.1.6:5000/receive"
            payload = {
                "encrypted_content": base64.b64encode(message).decode(),
                "sender_signature": base64.b64encode(signature).decode(),
                "receiver_name": receiver_name
            }

            response = self.protocol.sendData(receiver_url, payload)
            if response:
                decrypted_receiver = self.receive_info.decryptReceiverInfo(receiver_name)
                print(f"[Server] Forwarding message to {decrypted_receiver}")
                return receiver_instance.receiveMessage(message, receiver_name, signature, encryptor)
            else:
                print("[Server] Failed to forward message.")
                return False
        else:
            print("[Server] No messages to forward.")
            return False