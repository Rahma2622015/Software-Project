from RSAEncryption import RSAEncryptor
from SecureProtocol import SecureProtocol
from Sender import sender
from Server import Server
from User import user
from cryptoManager import EncryptionFactory
import base64
from Receiver import receiver

def main():
    # Step 1: Create RSA Encryption and Secure Protocol instances
    encryption_factory = EncryptionFactory(method="RSA")
    encryptor = encryption_factory.get_encryptor()

    # Step 2: User creation with email and password entered by the user
    email = input("Enter your email: ")
    password = input("Enter your password: ")
    sender_user = sender(encryption_factory, email, password)

    # Step 3: Simulate logging in the sender
    if sender_user.login(email, password):
        print(f"[Sender] {email} logged in successfully.")
    else:
        print("[Sender] Login failed.")
        return

    # Step 4: Create and encrypt a message with content entered by the user
    receiver_username = input("Enter the receiver's email: ")
    message_content = input("Enter your message: ")
    message = sender_user.create_message(message_content, receiver_username)

    if message is None:
        print("[Sender] Failed to create message.")
        return

    # Step 5: Simulate secure message transmission (no HTTP involved)
    secure_protocol = SecureProtocol()

    # Step 6: Create a server instance to receive the message
    server = Server(secure_protocol, sender_user)

    # Step 7: Server receives and processes the encrypted message
    if server.receive_message():
        print("[Server] Message received securely.")

        # ✅ Fix: instantiate the receiver before forwarding
        receiver_instance = receiver()
        if server.forward_message(receiver_instance):
            print(f"[Server] Message forwarded to {receiver_username} successfully.")
        else:
            print("[Server] Message forwarding failed.")
    else:
        print("[Server] Failed to receive the message.")

if __name__ == "__main__":
    main()
