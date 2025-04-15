import secrets
import string
import bcrypt
from database import SessionLocal,Users

class functions_DB:

    def hash_password(self,plain_password: str) -> str:
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(plain_password.encode('utf-8'), salt)
        return hashed.decode('utf-8')

    def verify_password(self,plain_password: str, hashed_password: str) -> bool:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

    def generate_strong_password(self,length=12):
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(characters) for _ in range(length))
        return password

 
    def receiver_exists(self, email):
        with SessionLocal() as session:
            receiver = session.query(Users).filter_by(email=email).first()
            if  receiver:
                return  receiver is not None
            else:
                print( receiver," not found!")

    def add_senders(self,email, password):
        with SessionLocal() as session:
            existing_user = session.query(Users).filter_by(email=email).first()
            if existing_user:
                if not self.verify_password(password, existing_user.password):
                    print("Wrong password!")
                    return False
                return True
        
            else:
                hashed_pw = self.hash_password(password)
                new_user = Users(email=email, password=hashed_pw)
                session.add(new_user)
                session.commit()
                print("User added to database.")
                return True



