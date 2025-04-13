class user:
    def __init__(self, encryptor,email,password,rsa_key=None):
        self.encryptor = encryptor
        self.rsa_key = rsa_key
        self.email=email
        self.password=password

    def getPublicKey(self):
        if hasattr(self.encryptor, 'public_key'):
            return self.encryptor.public_key
        else:
            return None

    def encrypt_with_rsa(self, aes_key):
        """تشفير مفتاح AES باستخدام مفتاح RSA العام للطرف الآخر"""
        if self.rsa_key:
            # تشفير المفتاح السري لـ AES باستخدام RSA
            encrypted_aes_key = self.rsa_key.encrypt(aes_key)
            return encrypted_aes_key
        return None
