from functions_for_database import functions_DB
fun=functions_DB()

class user:
    def __init__(self, encryptor,email,password):
        self.encryptor = encryptor
        self.email=email
        self.password=password

    def getPublicKey(self):
        if hasattr(self.encryptor, 'public_key'):
            return self.encryptor.public_key
        else:
            return None

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
        #add email&pass in database
        if fun.add_senders(email,clean_password):
            return True
        else:
            return False
