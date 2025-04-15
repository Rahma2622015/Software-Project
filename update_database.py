from functions_for_database import functions_DB
from database import SessionLocal, Users

f = functions_DB()

receivers = ["ihab@gmail.com"]

password_list = [f.generate_strong_password(12) for _ in range(10)]

print("List of strong passwords:")
for pwd in password_list:
    print(pwd)

with SessionLocal() as session:
    for email, plain_password in zip(receivers, password_list):
        hashed_pw = f.hash_password(plain_password)
        new_receiver = Users(email=email, password=hashed_pw)
        session.add(new_receiver)
    session.commit()
    print("Receivers added successfully with hashed passwords!")


with SessionLocal() as session:
    users = session.query(Users).all()
    for user in users:
        print(f"User ID: {user.id}, Email: {user.email}")

