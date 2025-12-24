from dotenv import load_dotenv
import os
from pydantic_settings import BaseSettings

load_dotenv()

class Settings(BaseSettings):
    db_host: str = os.getenv("DB_HOST")
    db_port: int = os.getenv("DB_PORT")
    db_user: str = os.getenv("DB_USER")
    db_password: str = os.getenv("DB_PASSWORD")
    db_name: str = os.getenv("DB_NAME")
    algorithm: str = os.getenv("ALGORITHM")
    access_token_expire_minutes: int = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")
    password_reset_token_expire_minutes: int = os.getenv("PASSWORD_RESET_TOKEN_EXPIRE_MINUTES")
    refresh_token_expire_days: int = os.getenv("REFRESH_TOKEN_EXPIRE")
    validation_token_expire_hours: int = os.getenv("VALIDATION_TOKEN_EXPIRE_HOURS")
    secret_key: str = os.getenv("SECRET_KEY")

    #Google OAuth settings
    google_client_id: str
    google_client_secret: str

    class Config:
        env_file = ".env"

settings = Settings()