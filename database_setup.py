from sqlalchemy import Integer, String, ForeignKey, Column
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key = True)
    name = Column(String(50),nullable = False)
    email = Column(String(50),nullable = False)
    picture = Column(String(50))

engine = create_engine('sqlite:///wordpooldatabase.db')
Base.metadata.create_all(engine)    