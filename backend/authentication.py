from passlib.context import CryptContext
from jose import JWTError, jwt
from database import db_dependency
from config import settings
from schemas import RefreshToken, User, ValidationToken, UserToken, PasswordResetToken
from datetime import datetime, timedelta
import smtplib
from email.message import EmailMessage
import ssl
from urllib.parse import quote_plus
import hashlib
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# token_hasher = CryptContext(schemes=["sha256_crypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/login")

def token_hasher(token: str):
    return hashlib.sha256(token.encode()).hexdigest()

class AuthService:
    def __init__(self, db: db_dependency):
        self.db = db
        self.SECRET_KEY = settings.secret_key
        self.ALGORITHM = settings.algorithm
        self.ACCESS_TOKEN_EXPIRE = settings.access_token_expire_minutes
        self.REFRESH_TOKEN_EXPIRE = settings.refresh_token_expire_days
        self.VALIDATION_TOKEN_EXPIRE = settings.validation_token_expire_hours
        self.PASSWORD_RESET_TOKEN_EXPIRE = settings.password_reset_token_expire_minutes

    def create_access_token(self, user: User, device_id: str): 
        created = datetime.utcnow()
        expires = datetime.utcnow() + timedelta(minutes=self.ACCESS_TOKEN_EXPIRE)
        payload = {
            "sub": str(user.id),
            "username": user.username,
            "exp": expires.timestamp()
        }
        user_token = jwt.encode(payload, self.SECRET_KEY, algorithm=self.ALGORITHM)

        # Store the user_token in db
        token_hashed = token_hasher(user_token)
        db_token = UserToken(
            user_id = user.id,
            token_type = "Access",
            token_hash = token_hashed,
            device_info = device_id,
            expires_at = expires,
            created_at = created
        )
        self.db.add(db_token)
        self.db.commit()

        return user_token
        
    def create_validation_token(self, user:User, device_id: str):
        created = datetime.utcnow()
        expires = datetime.utcnow() + timedelta(hours=self.VALIDATION_TOKEN_EXPIRE)
        payload = {
            "sub": str(user.id),
            "exp": expires.timestamp(),
            "token_type": "validation"
        }
        # token = jwt.encode(payload, self.SECRET_KEY, algorithm=self.ALGORITHM)

        print(f"Payload before encoding: {payload}")  # DEBUG
    
        token = jwt.encode(payload, self.SECRET_KEY, algorithm=self.ALGORITHM)
        
        print(f"Generated token: {token}")  # DEBUG
        
        # Store the hashed validation token
        token_hashed = token_hasher(token)
        
        print(f"Stored hash: {token_hashed}")  # DEBUG
    
        # Store the hashed validation token
        db_token = ValidationToken(
            user_id = user.id,
            token_hash = token_hashed,
            device_id = device_id,
            expires_at = expires
        )
        self.db.add(db_token)
        self.db.commit()

        db_token = UserToken(
            user_id = user.id,
            token_type = "Refresh",
            token_hash = token_hashed,
            device_info = device_id,
            expires_at = expires,
            created_at = created
        )
        self.db.add(db_token)
        self.db.commit()

        return token

    def create_password_reset_token(self, user: User, device_id: str):
        created = datetime.utcnow()
        expires = created + timedelta(minutes=15)
        payload = {
            "sub": str(user.id),
            "exp": expires.timestamp(),
            "token_type": "password_reset"
        }
        token = jwt.encode(payload, self.SECRET_KEY, algorithm=self.ALGORITHM)
        print(f"Created JWT: {token}")


        token_hashed = token_hasher(token)
        print(f"Hashed Token (to be saved): {token_hashed}")

        db_token = PasswordResetToken(
            user_id=user.id,
            token_hash=token_hashed,
            device_id=device_id,
            expires_at=expires,
            created_at=created
        )
        self.db.add(db_token)
        self.db.commit()

        db_token = UserToken(
            user_id = user.id,
            token_type = "password_reset",
            token_hash = token_hashed,
            device_info = device_id,
            expires_at = expires,
            created_at = datetime.utcnow()
        )
        self.db.add(db_token)
        self.db.commit()

        return token


    def create_refresh_token(self, user: User, device_id: str):
        created = datetime.utcnow()
        expires = created + timedelta(days=self.REFRESH_TOKEN_EXPIRE)
        payload = {
            "sub": str(user.id),
            "exp": expires.timestamp(),
            "token_type": "refresh"
        }
        token = jwt.encode(payload, self.SECRET_KEY, algorithm=self.ALGORITHM)

        # Store hashed refresh token in db
        token_hash = token_hasher(token)

        db_token = RefreshToken(
            user_id=user.id,
            token_hash=token_hash,
            device_id=device_id,
            expires_at=expires
        )
        self.db.add(db_token)
        self.db.commit()
        
        db_token = UserToken(
            user_id = user.id,
            token_type = "Refresh",
            token_hash = token_hash,
            device_info = device_id,
            expires_at = expires,
            created_at = created
        )
        self.db.add(db_token)
        self.db.commit()

        return token
    
    def authenticate_user(self, username: str, password: str):
        user= self.db.query(User).filter(User.username == username).first()
        if not user or not pwd_context.verify(password, user.hashed_password):
            return None
        return user

    def check_email(self, email: str):
        user = self.db.query(User).filter(User.email == email).first()
        if user:
            return user
        else:
            return None

    async def validate_reset_token(self, token: str):
        user_id = None
        try:
            # 1. Verify JWT token
            payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
            user_id = payload.get("sub")
            token_type = payload.get("token_type")
            
            if not user_id:
                return {"valid": False, "message": "Invalid token: missing user ID"}
            
            if token_type != "password_reset":
                return {"valid": False, "message": "Invalid token type"}
        
        except jwt.ExpiredSignatureError:
            print("JWT token has expired")
            # Continue to database check even if JWT expired
            pass
        
        except JWTError as e:
            print(f"JWTError caught: {str(e)}")
            return {"valid": False, "message": f"Invalid token: {str(e)}"}

        # 2. Database Verification
        token_hash = token_hasher(token)
        print(f"Searching for token hash: {token_hash}")
        
        db_token = self.db.query(PasswordResetToken).filter(
            PasswordResetToken.token_hash == token_hash
        ).first()

        if not db_token:
            print("Token not found in database")
            return {"valid": False, "message": "Invalid token"}

        # 3. Check database expiration (primary check)
        current_time = datetime.utcnow()
        print(f"Database expires_at: {db_token.expires_at}")
        print(f"Current UTC time: {current_time}")
        
        if current_time > db_token.expires_at:
            print("Token has expired based on database entry")
            return {"valid": False, "message": "Token has expired. Please request a new reset link."}

        # 4. Check if token already used
        # if db_token.is_used:
        #     print("Token has already been used")
        #     return {"valid": False, "message": "This reset link has already been used."}

        if user_id is None:
            user_id = db_token.user_id 
            print(f"Retrieved user_id from database: {user_id}")


        print("Token is valid")
        return {"valid": True, "user_id": user_id, "db_token": db_token}



    def get_error_html(self, message: str):
        """Return a simple error HTML page"""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Error - Password Reset</title>
            <style>
                body {{ font-family: Arial, sans-serif; text-align: center; padding: 50px; }}
                .error {{ color: #d32f2f; margin: 20px 0; font-size: 18px; }}
                .button {{ background: #f26522; color: white; padding: 12px 24px; 
                        text-decoration: none; border-radius: 5px; display: inline-block; 
                        margin: 10px; }}
            </style>
        </head>
        <body>
            <h1>Password Reset Error</h1>
            <div class="error">{message}</div>
            <div>
                <a href="/frontend/forgotpassword.html" class="button">Request New Reset Link</a>
                <a href="/frontend/login.html" class="button" style="background: #666;">Back to Login</a>
            </div>
        </body>
        </html>
        """

    def get_reset_password_html(self, token: str):
        """Return the HTML content with the token embedded"""
        try:
            # Read your HTML file
            with open("./reset-password.html", 'r', encoding='utf-8') as file:
                html_content = file.read()
            
            # Inject the token into the JavaScript
            html_content = html_content.replace(
                '// Get token from URL parameters',
                f'const token = "{token}"; // Injected by server'
            )
            
            return html_content
            
        except FileNotFoundError:
            return self.get_error_html("Reset page not found")


    def update_password(self, user_id: int, new_password: str):
        user = self.db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Hash the new password
        hashed_password = pwd_context.hash(new_password)
        user.hashed_password = hashed_password
        user.updated_at = datetime.utcnow()
        
        self.db.commit()
        return user


    async def send_verification_email(self, email: str, verification_link: str):
        msg = EmailMessage()
        msg["Subject"] = "Verify Your Email"
        msg['From'] = "m.ahmad03x08@gmail.com"
        msg['To'] = email
        
        html_content = f"""
        <html>
            <body>
                <h1>Welcome!</h1>
                <p>Please click the link below to verify your email:</p>
                <a href="{verification_link}">Verify Email</a>
            </body>
        </html>
        """
        
        msg.set_content(html_content, subtype='html')
        
        context = ssl.create_default_context()

        try:
            with smtplib.SMTP("smtp.gmail.com", 587) as server:
                server.ehlo()
                server.starttls(context=context)
                server.login("m.ahmad03x08@gmail.com", "tkge fubo thlz fsol")
                server.send_message(msg)
        except Exception as e:
            print(f"Error sending email: {e}")
            raise

    async def send_password_reset_email(self, email: str, reset_link: str):
        msg = EmailMessage()
        msg["Subject"] = "Reset Password"
        msg['From'] = "m.ahmad03x08@gmail.com"
        msg['To'] = email
        
        html_content = f"""
        <html>
            <body>
                <h1>Welcome!</h1>
                <p>Please click the link below to verify your email:</p>
                <a href="{reset_link}">Reset your password</a>
            </body>
        </html>
        """
        
        msg.set_content(html_content, subtype='html')
        
        context = ssl.create_default_context()

        try:
            with smtplib.SMTP("smtp.gmail.com", 587) as server:
                server.ehlo()
                server.starttls(context=context)
                server.login("m.ahmad03x08@gmail.com", "tkge fubo thlz fsol")
                server.send_message(msg)
        except Exception as e:
            print(f"Error sending email: {e}")
            raise

def get_current_user( token: str = Depends(oauth2_scheme), db: db_dependency = None):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}
    )
    try:
        # Decode the JWT token
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        user_id: str = payload.get("sub")
        
        if user_id is None:
            raise credentials_exception
            
        # Convert user_id to integer (since your ID is Integer)
        user_id = int(user_id)
    
    except (JWTError, ValueError):
        raise credentials_exception
    
    # Verify token exists in database (security check)
    token_hash = token_hasher(token)
    db_token = db.query(UserToken).filter(
        UserToken.token_hash == token_hash,
        UserToken.token_type == "Access",
        UserToken.expires_at > datetime.utcnow()
    ).first()
    
    if not db_token:
        raise credentials_exception
    
    # Fetch the user from database
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
    
    return user

def get_current_active_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account has been deactivated"
        )
    return current_user
    