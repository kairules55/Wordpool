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
    time = Column(Integer, nullable = False)

class Word(Base):
    __tablename__ = 'word'
    id = Column(Integer,primary_key = True)
    word = Column(String(50),nullable=False)

class SavedWord(Base):
    __tablename__ = 'savedWords'
    user_id = Column(Integer, ForeignKey('user.id'), primary_key = True)
    word_id = Column(Integer, ForeignKey('word.id'), primary_key = True)
    word = relationship(Word)
    user = relationship(User)

engine = create_engine('sqlite:///wordpooldatabase.db')
Base.metadata.create_all(engine)    