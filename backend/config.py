from dotenv import load_dotenv
import os
from pydantic_settings import BaseSettings

load_dotenv()

class Settings(BaseSettings):
    db_host: str
    db_port: int
    db_user: str
    db_password: str
    db_name: str
    algorithm: str
    access_token_expire_minutes: int
    password_reset_token_expire_minutes: int
    refresh_token_expire_days: int
    validation_token_expire_hours: int
    secret_key: str

    #Google OAuth settings
    google_client_id: str
    google_client_secret: str

    class Config:
        env_file = ".env"

settings = Settings()