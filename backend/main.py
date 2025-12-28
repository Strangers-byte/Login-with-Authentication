from fastapi import APIRouter, Depends, HTTPException, status, FastAPI, Request, Query
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from models import UserResponse, UserCreate, Token, RefreshTokenRequest, PasswordResetRequest, TokenVerificationResponse, PasswordResetResponse, PasswordResetConfirm
from authentication import AuthService, pwd_context, token_hasher, get_current_active_user, get_current_user
from schemas import User, RefreshToken, ValidationToken, PasswordResetToken
from jose import jwt, JWTError
from database import db_dependency, Base, engine
from datetime import datetime
from config import settings
from pathlib import Path

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Authentication API",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000",  # FastAPI itself
        "http://127.0.0.1:8000",  # Alternative localhost
        ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

router = APIRouter()

# templates = Jinja2Templates(directory="templates")



@router.post("/register", response_model=UserResponse)
async def register(request: Request, user_data: UserCreate, db: db_dependency):
    auth_service = AuthService(db)

    #Check if user exists
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(status_code=400, detail="Username already exists.")
    
    #Create user
    hashed_password = pwd_context.hash(user_data.password)
    user = User(
        username=user_data.username,
        email=user_data.email,
        full_name=user_data.full_name,
        hashed_password=hashed_password
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    device_id = request.headers.get("user-agent")

    # Create email validation token and save in db
    validation_token = auth_service.create_validation_token(user, device_id)

    print(f"The validation token before being sent in Email:{validation_token}")

    # Send vaerification Email
    verification_link = f"http://127.0.0.1:8000/api/verify-email?token={validation_token}"
    
    await auth_service.send_verification_email(email = user.email, verification_link = verification_link)
    
    return user



@router.get("/verify-email")
async def verify_email(
    request: Request,
    db: db_dependency,
    token: str = Query(..., description="The verification token")
):
    # Debug output
    print(f"Verification attempt with token: {token}")
    
    # JWT Verification
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        user_id = payload.get("sub")
        token_exp = payload.get("exp")
        
        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid token: missing user ID")
            
        if datetime.utcnow() > datetime.fromtimestamp(token_exp):
            raise HTTPException(status_code=400, detail="Token has expired")
            
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="Token has expired")
    except JWTError as e:
        raise HTTPException(status_code=400, detail=f"Invalid token: {str(e)}")

    # Database Verification
    token_hash = token_hasher(token)
    print(f"Searching for token hash: {token_hash}")
    
    db_token = db.query(ValidationToken).filter(
        ValidationToken.token_hash == token_hash,
        ValidationToken.expires_at > datetime.utcnow()
    ).first()

    if not db_token:
        print("Token not found in database")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired token."
        )

    # Mark user as verified
    user = db.query(User).filter(User.id == db_token.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    
    user.is_verified = True
    db.commit()

    return {"message": "Email verified successfully"}



@router.get("/verify-reset-token", response_model=TokenVerificationResponse)
async def verifyResetToken(
    db: db_dependency,
    token: str = Query(..., description="The verification token")
):
    print(f"Reset Token: {token}")
    print(f"Current UTC time: {datetime.utcnow()}")
    
    user_id = None
    
    try:
        # Verify JWT token
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        user_id = payload.get("sub")
        token_type = payload.get("token_type")
        
        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid token: missing user ID")
        
        if token_type != "password_reset":
            raise HTTPException(status_code=400, detail="Invalid token type")
    
    except jwt.ExpiredSignatureError:
        print("JWT token has expired")
        # Even if JWT expired, check if database entry is still valid
        # (this handles clock skew issues)
        pass  # We'll continue to database check
    
    except JWTError as e:
        print(f"JWTError caught: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Invalid token: {str(e)}")

    # Database Verification
    token_hash = token_hasher(token)
    print(f"Searching for token hash: {token_hash}")
    
    db_token = db.query(PasswordResetToken).filter(
        PasswordResetToken.token_hash == token_hash
    ).first()

    if not db_token:
        print("Token not found in database")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token."
        )

    # Check database expiration (primary check)
    current_time = datetime.utcnow()
    print(f"Database expires_at: {db_token.expires_at}")
    print(f"Current UTC time: {current_time}")
    
    if current_time > db_token.expires_at:
        print("Token has expired based on database entry")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired. Please request a new reset link."
        )

    # If user_id is None (because JWT expired), get it from the database token
    if user_id is None:
        user_id = db_token.user_id  # Get user_id from database
        print(f"Retrieved user_id from database: {user_id}")

    print("Token is valid")
    # return {"valid": True, "token": token}

    auth_service = AuthService(db)
    html_content = auth_service.get_reset_password_html(token)

    # return TokenVerificationResponse(valid=True, user_id=user_id, token=token)
    return RedirectResponse(url=f"/web/reset-password.html?token={token}")


@router.post("/reset-password", response_model=PasswordResetResponse)
async def reset_password(
    reset_data: PasswordResetConfirm,  # This receives the data
    db: db_dependency
):
    print(f"Password reset request for token: {reset_data.token}")
    
    # Validate the token
    auth_service = AuthService(db)
    validation_result = await auth_service.validate_reset_token(reset_data.token)
    
    print(f"Validation result: {validation_result}")

    if not validation_result["valid"]:
        raise HTTPException(status_code=400, detail=validation_result["message"])
    
    # Additional password validation
    if len(reset_data.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long")
    
    # Update the user's password
    user_id = validation_result["user_id"]
    auth_service.update_password(user_id, reset_data.new_password)
    
    # Mark token as used
    # db_token = validation_result["db_token"]
    # db_token.is_used = True
    # db.commit()
    
    return PasswordResetResponse(
        message="Password reset successfully. You can now login with your new password.",
        success=True
    )



@router.post("/forget-password")
async def forgotPassword(request: Request, db: db_dependency, form_data: PasswordResetRequest):
    print(f"Received data: {await request.json()}")

    auth_service = AuthService(db)
    user = auth_service.check_email(form_data.email)

    if not user:
        return {"message": "If the email exists, a password reset link has been sent"}
    
    device_id = request.headers.get("user-agent")

    reset_token = auth_service.create_password_reset_token(user, device_id=device_id)

    reset_link = f"http://127.0.0.1:8000/api/verify-reset-token?token={reset_token}"
    print(f"The reset link is: {reset_link}")
    await auth_service.send_password_reset_email(user.email, reset_link)

    return {"message": "If the email exists, a password reset link has been sent"}



@router.post("/login", response_model=Token)
async def login(request: Request, db: db_dependency , form_data: OAuth2PasswordRequestForm = Depends()):
    auth_service = AuthService(db)
    user = auth_service.authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password.", headers={"WWW-Authenticate": "Bearer"})
    
    device_id = request.headers.get("user-agent")

    access_token = auth_service.create_access_token(user, device_id)
    refresh_token = auth_service.create_refresh_token(user, device_id)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": auth_service.ACCESS_TOKEN_EXPIRE
    }


@router.get("/me", response_model=UserResponse)
async def read_user_data(current_user: User = Depends(get_current_active_user)):
    return current_user

@router.post("/refresh", response_model=Token)
async def refresh_token(request:Request, refresh_request: RefreshTokenRequest, db:db_dependency):
    auth_service = AuthService(db)
    try:
        payload = jwt.decode(
            refresh_request.refresh_token,
            auth_service.SECRET_KEY,
            algorithms=[auth_service.ALGORITHM]
        )
        user_id =payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=400, detail="Invalid token.")

        # Verify refresh token exists in DB
        token_hash = token_hasher(refresh_request.refresh_token)
        db_token = db.query(RefreshToken).filter(
            RefreshToken.token_hash == token_hash,
            RefreshToken.user_id == user_id,
            RefreshToken.expires_at > datetime.utcnow()
        ).first()

        if not db_token:
            raise HTTPException(status_code=400, detail="Invalid or expired token.")
        
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found.")
        
        device_id = request.headers.get("user-agent")

        new_access_token = auth_service.create_access_token(user, device_id)

        return {
            "access_token": new_access_token,
            "refresh_token": refresh_request.refresh_token,
            "token_type": "bearer",
            "expires_in": auth_service.ACCESS_TOKEN_EXPIRE
        }
    
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")
    

app.include_router(router, prefix="/api")

# 2. Health check
@app.get("/api/health")
async def health_check():
    return {"message": "Authentication API is running"}

# # Serve JS files specifically
# @app.get("/js/{filename}")
# async def serve_js(filename: str):
#     js_path = frontend_path / "js" / filename
#     if js_path.exists() and js_path.is_file():
#         return FileResponse(js_path)
#     raise HTTPException(status_code=404, detail="JS file not found")

# # 3. Static files under /web
# frontend_path = Path(__file__).parent.parent / "frontend"  
# print("HTML files path:", frontend_path.absolute())
# print("Index.html exists:", (frontend_path / "index.html").exists())

# app.mount("/web", StaticFiles(directory=str(frontend_path), html=True), name="frontend")

# # 4. Root redirects to web interface
# @app.get("/")
# async def root():
#     return RedirectResponse(url="/web/index.html")

# # 5. Catch-all for SPA routing under /web
# @app.get("/web/{path:path}")
# async def serve_spa(path: str):
#     file_path = frontend_path / path
#     if file_path.exists() and file_path.is_file():
#         return FileResponse(file_path)
#     return FileResponse(frontend_path / "index.html")

# # Debug: Print all registered routes
# @app.on_event("startup")
# async def startup_event():
#     print("Registered routes:")
#     for route in app.routes:
#         if hasattr(route, "methods"):
#             print(f"{list(route.methods)} {route.path}")