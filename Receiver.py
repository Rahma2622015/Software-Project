from RSAEncryption import RSAEncryptor

class receiver:
    def __init__(self):
        self.received_messages = []

    def receiveMessage(self, encrypted_message, receiver_name, signature: bytes, encryptor) -> bool:
        if isinstance(encryptor, RSAEncryptor):
            decrypted_message = encryptor.decrypt(encrypted_message)

        if encryptor.verifySignature(receiver_name, signature, encryptor.public_key):
            print(f"Message from {receiver_name} successfully verified.")
            self.received_messages.append({'receiver': receiver_name, 'message': decrypted_message})
            return True
        else:
            print("❌ Signature not valid. Message discarded.")
            return False

    def get_received_messages(self):
        return self.received_messages
