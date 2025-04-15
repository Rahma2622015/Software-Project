from RSAEncryption import RSAEncryptor

class receiver:
    def __init__(self):
        self.received_messages = []

    def receiveMessage(self, encrypted_message, receiver_name, signature: bytes, encryptor) -> bool:
        if isinstance(encryptor, RSAEncryptor):
            decrypted_message = encryptor.decrypt(encrypted_message)
            decrypted_receiver = encryptor.decrypt(receiver_name)
        if encryptor.verifySignature(decrypted_receiver, signature, encryptor.public_key):
            print(f"[Receiver]Message successfully verified.")
            self.received_messages.append({'Receiver_email': decrypted_receiver, 'Message': decrypted_message})
            return True
        else:
            print("Signature not valid. Message discarded.")
            return False

    def get_received_messages(self):
        return self.received_messages[-1]
