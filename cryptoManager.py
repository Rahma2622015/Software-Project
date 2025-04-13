from RSAEncryption import RSAEncryptor

class EncryptionFactory:
    def __init__(self, method="RSA"):
        if method.upper() == "RSA":
            self.encryptor = RSAEncryptor()
        else:
            raise ValueError("Unsupported encryption method")

    def get_encryptor(self):
        return self.encryptor
