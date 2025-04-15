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
    global decrypted_message_content
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

    # Step 5: Extract the signature from the message (already signed)
    signature = message.get_signature()

    # Step 6: Encrypt receiver name
    encrypted_receiver_name = message.get_receiver_username()

    # Step 7: Prepare Receiverinfo and SecureProtocol
    receiver_info = Receiverinfo(sender_user.encryptor)
    secure_protocol = SecureProtocol()

    # Step 8: Create a server instance
    server = Server(secure_protocol, sender_user, receiver_info)

    # Step 9: Server receives and processes the encrypted message
    if server.receive_message(message, signature, encrypted_receiver_name, encryptor):
        print("[Server] Message received securely.")

        try:
            encrypted_message_content = message.get_encrypted_content()
            if isinstance(encrypted_message_content, bytes):
                encoded_message = base64.b64encode(encrypted_message_content).decode()
            else:
                encoded_message = base64.b64encode(encrypted_message_content.encode('utf-8')).decode()
            print(f"[Server] Encrypted message: {encoded_message}")

            # Step 10: Create receiver instance and simulate delivery
            receiver_instance = receiver()
            if server.forward_message(receiver_instance, encryptor):
                print(f"[Server] Message forwarded to {receiver_username} successfully.")

                # Step 11: Retrieve and compare decrypted message
                decrypted_message_content = receiver_instance.get_last_received_message_content()
                print(f"[Receiver] Decrypted message: {decrypted_message_content}")

                print("\n--- Message Integrity Check ---")
                print(f"Original message     : {original_message_content}")
                print(f"Encrypted message    : {encoded_message}")
                print(f"Decrypted message    : {decrypted_message_content}")

                if original_message_content == decrypted_message_content:
                    print("[Check] ✅ Message received intact. No data leak.")
                else:
                    print("[Check] ❌ Message mismatch! Potential issue or data leak.")

            else:
                print("[Server] Message forwarding failed.")
        except AttributeError:
            print("[Server] Error: Unable to extract message content for encoding.")
    else:
        print("[Server] Failed to receive the message.")

    print("[Server] Message object:", message)
    print("[Server] Encrypted content:", message.get_encrypted_content())

    if 'decrypted_message_content' in globals():
        print("ddddddddddddddddddddddd: " + decrypted_message_content)
    else:
        print("ddddddddddddddddddddddd: No decrypted message content available.")

if __name__ == "__main__":
    main()
    # hagerSamy$234
    # samy@gmail.com
    # StrongPass123!
    # hagar@gmail.com