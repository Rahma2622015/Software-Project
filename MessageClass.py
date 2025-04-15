class Message:
    def __init__(self, encrypted_content: str, signature: str, receiver_username: str = ""):
        self.__encrypted_content = encrypted_content  
        self.__signature = signature
        self.__receiver_username = receiver_username  

    def get_encrypted_content(self) -> str:
        return self.__encrypted_content 

    def get_signature(self) -> str:
        return self.__signature 

    def get_receiver_username(self) -> str:
        return self.__receiver_username 

    def set_encrypted_content(self, content: str):
        self.__encrypted_content = content  

    def set_signature(self, signature: str):
        self.__signature = signature

    def set_receiver_username(self, username: str):
        self.__receiver_username = username  
