from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from urllib.parse import quote_plus
from config import settings
from typing import Annotated
from fastapi import Depends

encoded_pass = quote_plus(settings.db_password)

DATABASE_URL = f"mysql+pymysql://{settings.db_user}:{encoded_pass}@{settings.db_host}:{settings.db_port}/{settings.db_name}"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependency = Annotated[Session, Depends(get_db)]

