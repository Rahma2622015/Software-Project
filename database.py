from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = "sqlite:///users_information.db"
engine = create_engine(DATABASE_URL, echo=True)
Base = declarative_base()

class Users(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False) 

Base.metadata.create_all(engine)
SessionLocal = sessionmaker(bind=engine)
