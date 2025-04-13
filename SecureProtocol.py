import requests
from urllib.parse import urlparse
from IProtocol import ProtocolInterface

class SecureProtocol(ProtocolInterface):
    def __init__(self):
        pass

    def is_secure_protocol(self, url: str) -> bool:
        parsed_url = urlparse(url)
        return parsed_url.scheme.lower() == "https"

    def sendData(self, url: str, data: str) -> bool:
        if not self.is_secure_protocol(url):
            print(f"Insecure Protocol: {url} is not using HTTPS")
            return False

        try:
            response = requests.post(url, data=data, verify="D:/Software-Project/cert.crt")
            print(f" Data sent securely to {url}")
            return True
        except requests.exceptions.SSLError:
            print(f" SSL Error: Connection to {url} is not secure")
            return False
        except Exception as e:
            print(f" Error sending data: {e}")
            return False

    def receiveData(self, url: str) -> bool:
        if not self.is_secure_protocol(url):
            print(f" Insecure Protocol: {url} is not using HTTPS")
            return False

        try:
            response = requests.get(url)
            print(f" Data received securely from {url}")
            return True
        except requests.exceptions.SSLError:
            print(f" SSL Error: Connection to {url} is not secure")
            return False
        except Exception as e:
            print(f" Error receiving data: {e}")
            return False
