
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
        self.logged_in = False


    def login(self, email, password):
        clean_password = f.sanitize_password(password)
        if not f.is_valid_email(email):
            print("Invalid email format!")
            return False
        if self.email != email:
            print("Invalid email!")
            return False
        if clean_password.strip() == "" :
            print("Empty password!")
            return False
        if self.password != clean_password :
            print("Invalid password!")
        if not f.is_strong_password(clean_password):
            print("Password is not strong enough. It should include uppercase, lowercase, digits, and special characters.")
            return False

        self.logged_in = True
        return True

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

