
from cryptoManager import EncryptionFactory
from MessageClass import Message
from User import user
import re
from functions import functions

f=functions()


class sender(user):
    def __init__(self, encryption_factory: EncryptionFactory, email, password):
        encryptor_instance = encryption_factory.get_encryptor()
        super().__init__(encryptor_instance, email, password)
        self.encryptor = encryptor_instance
        self.sessions = []
        self.logged_in=False


    def login(self, email, password):
        if super().login(email, password):
            print("Sender logged in successfully!")
            self.logged_in = True
            return True
        else:
            print("Login failed!")
            return False

    def create_message(self, content, receiver_email):
        if not self.logged_in:
            print("Invalid login!")
            return None
        if not (f.is_valid_email(receiver_email)):
            print("Invalid receiver_email!")
            return None
        encrypted_content = self.encryptor.encrypt(content)
        encrypted_receiver_name = self.encryptor.encrypt(receiver_email)
        signature = self.encryptor.signData(receiver_email)
        message = Message(encrypted_content, signature, encrypted_receiver_name)
        self.sessions.append(message)
        return message

    def send_message(self):
        if not self.sessions:
            return "", "", "", ""
        message = self.sessions[-1]
        return self.encryptor, message.get_encrypted_content(), message.get_signature(), message.get_receiver_username()


