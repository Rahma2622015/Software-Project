from abc import ABC, abstractmethod

class ProtocolInterface(ABC):

    @abstractmethod
    def sendData(self, url: str, data: str) -> bool:
        pass

    @abstractmethod
    def receiveData(self , url: str) -> bool:
        pass