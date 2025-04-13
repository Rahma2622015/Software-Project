from cryptography.hazmat.primitives import  hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from IEncryptor import EncryptionInterface

class RSAEncryptor(EncryptionInterface):
    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()


    def encrypt(self, data: str) -> bytes:
        return self.public_key.encrypt(
            data.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt(self, encrypted_data: bytes) -> str:
        decrypted = self.private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode()

    def signData(self, data: str) -> bytes:
        return self.private_key.sign(
            data.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )


    def verifySignature(self, data: str, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
        try:
            public_key.verify(
                signature,
                data.encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            return False


