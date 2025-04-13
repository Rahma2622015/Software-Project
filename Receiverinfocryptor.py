from IEncryptor import EncryptionInterface


class Receiverinfo:
    def __init__(self, encryptor: EncryptionInterface):
        self.encryptor = encryptor

    def decryptReceiverInfo(self, encrypted_info: bytes) -> str:
        return self.encryptor.decrypt(encrypted_info)

    def encryptReceiverInfo(self, receiver_info: str) -> bytes:
        return self.encryptor.encrypt(receiver_info)
