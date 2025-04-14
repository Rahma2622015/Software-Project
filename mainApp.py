from RSAEncryption import RSAEncryptor
from Receiverinfocryptor import Receiverinfo
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
    original_message_content = input("Enter your message: ")
    message = sender_user.create_message(original_message_content, receiver_username)

    if message is None:
        print("[Sender] Failed to create message.")
        return


    receiver_info = Receiverinfo(sender_user.encryptor)

    # Step 5: Simulate secure message transmission
    secure_protocol = SecureProtocol()

    # Step 6: Create server instance
    server = Server(secure_protocol, sender_user, receiver_info)


    # Step 7: Server receives message
    if server.receive_message():
        print("[Server] ✅ Message received securely.")

        # 🔍 Step 7.1: Verify the integrity of the received message
        try:
            # Directly using the message dictionary
            encrypted_msg = message["message"]
            signature = message["signature"]
            encrypted_receiver = message["receiver"]

            # Decrypt the message content and the receiver
            decrypted_message = encryptor.decrypt(encrypted_msg)
            decrypted_receiver = encryptor.decrypt(encrypted_receiver)

            print(f"[Verification] Decrypted Message: {decrypted_message}")
            print(f"[Verification] Intended Receiver: {decrypted_receiver}")

            # Check message integrity
            if decrypted_message == original_message_content:
                print("[Verification] ✅ Message integrity check passed. Message is intact.")
            else:
                print("[Verification] ❌ Message corrupted during transmission.")

            # Check receiver identification
            if decrypted_receiver == receiver_username:
                print("[Receiver Check] ✅ Correct receiver identified.")
            else:
                print("[Receiver Check] ❌ Wrong receiver decrypted!")

        except Exception as e:
            print(f"[Verification] ❌ Error verifying integrity or receiver: {e}")
            print("[Security] ⚠️ Partial decryption failed. No sensitive data leaked.")

        # Step 8: Forward message to the receiver
        receiver_instance = receiver()

        if server.forward_message(receiver_instance, encryptor):
            print(f"[Server] ✅ Message forwarded to {receiver_username} successfully.")

        else:
            print("[Server] ❌ Message forwarding failed.")
    else:
        print("[Server] ❌ Failed to receive the message.")

if __name__ == "__main__":
    main()


    # eman@gmail.com
    # Ddfaser@123

