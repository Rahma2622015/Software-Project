class Message:
    def __init__(self, encrypted_content: str, signature: str, receiver_username: str = ""):
        self.__encrypted_content = encrypted_content  # Note the double underscore (private)
        self.__signature = signature  # Note the double underscore (private)
        self.__receiver_username = receiver_username  # Note the double underscore (private)

    def get_encrypted_content(self) -> str:
        return self.__encrypted_content  # Access the private attribute with the getter

    def get_signature(self) -> str:
        return self.__signature  # Access the private attribute with the getter

    def get_receiver_username(self) -> str:
        return self.__receiver_username  # Access the private attribute with the getter

    def set_encrypted_content(self, content: str):
        self.__encrypted_content = content  # Modify the private attribute

    def set_signature(self, signature: str):
        self.__signature = signature  # Modify the private attribute

    def set_receiver_username(self, username: str):
        self.__receiver_username = username  # Modify the private attribute
