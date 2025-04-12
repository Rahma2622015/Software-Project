from abc import ABC, abstractmethod

class EncryptionInterface(ABC):

    @abstractmethod
    def encrypt(self, data: str) -> str:
        pass

    @abstractmethod
    def decrypt(self, data: str) -> str:
        pass