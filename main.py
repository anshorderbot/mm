from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from sqlmodel import Field, Session, SQLModel, create_engine, select
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt
import os

# --- Configuration ---
SECRET_KEY = os.getenv("SECRET_KEY", "your-super-secret-key-change-this")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7 # 7 days

# --- Database Setup ---
sqlite_file_name = "database.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"
engine = create_engine(sqlite_url, connect_args={"check_same_thread": False})

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

# --- Models ---
class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    hashed_password: str
    valid_until: datetime
    is_active: bool = Field(default=True)

class UserCreate(BaseModel):
    username: str
    password: str
    days_valid: int = 30

class Token(BaseModel):
    access_token: str
    token_type: str

# --- Security ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --- Dependency ---
def get_session():
    with Session(engine) as session:
        yield session

# --- App ---
app = FastAPI()

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

# --- Client Login Endpoint ---
@app.post("/login", response_model=Token)
def login(username: str, password: str, session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.username == username)).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")
    if user.valid_until < datetime.utcnow():
        raise HTTPException(status_code=403, detail="License expired")
    
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# --- Admin Endpoints (Simple protection) ---
ADMIN_USER = "admin"
ADMIN_PASS = "admin123" # Change this!

def verify_admin(username: str, password: str):
    return username == ADMIN_USER and password == ADMIN_PASS

@app.post("/admin/create_user")
def create_user(user_data: UserCreate, session: Session = Depends(get_session)):
    # Note: In real app, protect this with admin token. For simplicity, we skip auth here for demo.
    existing = session.exec(select(User).where(User.username == user_data.username)).first()
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")
    
    new_user = User(
        username=user_data.username,
        hashed_password=get_password_hash(user_data.password),
        valid_until=datetime.utcnow() + timedelta(days=user_data.days_valid)
    )
    session.add(new_user)
    session.commit()
    return {"message": f"User {user_data.username} created"}

@app.delete("/admin/delete_user/{username}")
def delete_user(username: str, session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.username == username)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    session.delete(user)
    session.commit()
    return {"message": f"User {username} deleted"}

@app.get("/admin/list_users")
def list_users(session: Session = Depends(get_session)):
    users = session.exec(select(User)).all()
    return users
