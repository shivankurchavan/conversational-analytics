import os 
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

import jwt 
from bson.objectid import ObjectId
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from passlib.context import CryptContext
from pymongo import MongoClient


import logging

# Configure the logger 
logging.basicConfig(
    level=logging.INFO, #set logging level
    format='%(asctime)s - %(levelname)s - %(message)s', #log format
    handlers=[
        logging.FileHandler('app.log'), #log to a file 
        logging.StreamHandler() #log to console
    ]
)
# create a logger insatnce 
logger = logging.getLogger(__name__)

#Mongo connection 
MONGODB_URI = os.getenv("MONGODB_URI")
if not MONGODB_URI:
    raise ValueError("Mongo uri not set in env")

client = MongoClient(MONGODB_URI)
db = client['user_auth_db']
users_collection = db['users']


#jwt setting 
SECRET_KEY = os.environ.get("SECRET_KEY") # set this securly in production 
if not SECRET_KEY:
    raise ValueError("Secret key missing for jwt")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class UserRole(str, Enum):
    USER = "user"
    ADMIN = "admin"

# password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    verify a plain password against a hashed password.
    """
    logger.info(f"Entered in 'verify_password' function")
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str)->str:
    logger.info(f"Entered in 'get_password_hash' funtion")
    return pwd_context.hash(password)

def authenticate_user(username: str, password: str) -> dict:
    logger.info(f"entererd in authenticate_user funtion")
    user = users_collection.find_one({"username": username})
    if not user or not verify_password(password, user["password"]):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta]=None) -> str:
    logger.info(f"entered create_access_token function")
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire, "role": data.get("role")})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    logger.info(f"Encoded JWT : {encoded_jwt}")
    return encoded_jwt

def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """
    get current user based on jwt 
    """
    logger.info(f"entered in get current user funtion")
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="couldnt validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    
    user = users_collection.find_one({"username" : username})
    if user is None:
        raise credentials_exception
    return {"username": user["username"], "role": user["role"]}

def admin_required(current_user : dict = Depends(get_current_user)) -> dict:
    logger.info(f"entered in admin required funtion")
    if current_user["role"] != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user