from RSAEncryption import RSAEncryptor

class receiver:
    def __init__(self):
        self.received_messages = []
        self.last_decrypted_message = None  # New: to store the last decrypted message

    def receiveMessage(self, encrypted_message, receiver_name, signature: bytes, encryptor) -> bool:
        if isinstance(encryptor, RSAEncryptor):
            decrypted_message = encryptor.decrypt(encrypted_message)
            decrypted_receiver = encryptor.decrypt(receiver_name)

        if encryptor.verifySignature(decrypted_receiver, signature, encryptor.public_key):
            print(f"[Receiver] Message successfully verified.")
            self.last_decrypted_message = decrypted_message  # Save it for integrity check
            self.received_messages.append({
                'Receiver_email': decrypted_receiver,
                'Message': decrypted_message
            })
            return True
        else:
            print("[Receiver] Signature not valid. Message discarded.")
            return False

    def get_received_messages(self):
        return self.received_messages[-1] if self.received_messages else None

    def get_last_received_message_content(self):
        return self.last_decrypted_message

