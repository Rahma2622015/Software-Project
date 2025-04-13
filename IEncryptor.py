from abc import ABC, abstractmethod

class EncryptionInterface(ABC):

    @abstractmethod
    def encrypt(self, data: str) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, data: bytes) -> str:
        pass