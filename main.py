from fastapi import FastAPI, HTTPException, Depends, Request, Form, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
from sqlmodel import Field, Session, SQLModel, create_engine, select
from datetime import datetime, timedelta, timezone
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import jwt
import os
import uvicorn
import bcrypt

# --- Configuration ---
SECRET_KEY = os.getenv("SECRET_KEY", "your-super-secret-key-change-this")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7 # 7 days

# --- Admin Credentials ---
# Yahan apna Admin Username aur Password set karo
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"
# Cookie signature ke liye secret
ADMIN_SECRET_KEY = "my-super-secret-admin-cookie-key-123"

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

# --- Security (Direct bcrypt) ---
def verify_password(plain_password, hashed_password):
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False

def get_password_hash(password):
    pwd_bytes = password.encode('utf-8')[:72]
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd_bytes, salt)
    return hashed.decode('utf-8')

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --- Dependency ---
def get_session():
    with Session(engine) as session:
        yield session

# --- Admin Auth Helpers ---
serializer = URLSafeTimedSerializer(ADMIN_SECRET_KEY)

def create_admin_cookie(username: str):
    return serializer.dumps({"admin": username})

def verify_admin_cookie(request: Request):
    cookie = request.cookies.get("admin_session")
    if not cookie:
        return False
    try:
        data = serializer.loads(cookie, max_age=3600) # 1 hour validity
        return data.get("admin") == ADMIN_USERNAME
    except (BadSignature, SignatureExpired):
        return False

# --- App ---
app = FastAPI()

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

# --- Client Login Endpoint (For EXE) ---
@app.post("/login", response_model=Token)
def login(username: str, password: str, session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.username == username)).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")
    if user.valid_until < datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="License expired")
    
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# --- Admin Routes ---
@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    if not verify_admin_cookie(request):
        return RedirectResponse(url="/admin/login", status_code=status.HTTP_303_SEE_OTHER)
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/admin/login", response_class=HTMLResponse)
def admin_login_page(request: Request, error: str = None):
    error_html = f'<div class="message error" style="display:block;">{error}</div>' if error else ''
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Admin Login - Ghost Mailer</title>
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; background-color: #12141a; color: #eef0f4; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
            .login-box {{ background-color: #1a1d27; padding: 40px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); border: 1px solid #343a4a; width: 300px; text-align: center; }}
            h2 {{ color: #f5a524; margin-bottom: 20px; }}
            input {{ width: 100%; padding: 10px; margin-bottom: 15px; border-radius: 6px; border: 1px solid #343a4a; background-color: #242836; color: #eef0f4; box-sizing: border-box; outline: none; }}
            input:focus {{ border-color: #f5a524; }}
            button {{ width: 100%; padding: 10px; border: none; border-radius: 6px; background-color: #f5a524; color: #1a1208; font-weight: bold; cursor: pointer; }}
            button:hover {{ background-color: #ffb84d; }}
            .message {{ padding: 10px; margin-bottom: 15px; border-radius: 6px; font-size: 14px; }}
            .error {{ background-color: #f07167; color: #fff; }}
        </style>
    </head>
    <body>
        <div class="login-box">
            <h2>👻 Admin Login</h2>
            {error_html}
            <form action="/admin/login" method="POST">
                <input type="text" name="username" placeholder="Admin Username" required>
                <input type="password" name="password" placeholder="Admin Password" required>
                <button type="submit">Login</button>
            </form>
        </div>
    </body>
    </html>
    """

@app.post("/admin/login")
def admin_login(username: str = Form(...), password: str = Form(...)):
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        response = RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)
        cookie_val = create_admin_cookie(username)
        response.set_cookie(key="admin_session", value=cookie_val, httponly=True, max_age=3600)
        return response
    else:
        return RedirectResponse(url="/admin/login?error=Invalid+credentials", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/admin/logout")
def admin_logout():
    response = RedirectResponse(url="/admin/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("admin_session")
    return response

@app.get("/admin/dashboard", response_class=HTMLResponse)
def admin_dashboard(request: Request, session: Session = Depends(get_session)):
    if not verify_admin_cookie(request):
        return RedirectResponse(url="/admin/login", status_code=status.HTTP_303_SEE_OTHER)
        
    users = session.exec(select(User)).all()
    
    rows = ""
    for u in users:
        status_text = "Active" if u.is_active and u.valid_until > datetime.now(timezone.utc) else "Expired/Disabled"
        color = "green" if status_text == "Active" else "red"
        date_str = u.valid_until.strftime("%Y-%m-%d %H:%M")
        rows += f"""
        <tr>
            <td>{u.id}</td>
            <td><b>{u.username}</b></td>
            <td style="color:{color}; font-weight:bold;">{status_text}</td>
            <td>{date_str}</td>
            <td>
                <form action="/admin/delete_user/{u.username}" method="POST" style="display:inline;">
                    <button type="submit" class="btn-delete">Delete</button>
                </form>
            </td>
        </tr>
        """
    
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Admin Dashboard - Ghost Mailer</title>
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; background-color: #12141a; color: #eef0f4; margin: 0; padding: 20px; }}
            .container {{ max-width: 900px; margin: auto; background-color: #1a1d27; padding: 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); border: 1px solid #343a4a; }}
            .header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }}
            h1 {{ color: #f5a524; margin: 0; }}
            h2 {{ color: #f5a524; border-bottom: 2px solid #343a4a; padding-bottom: 10px; }}
            .btn-logout {{ background-color: #f07167; color: white; padding: 8px 15px; text-decoration: none; border-radius: 6px; font-size: 14px; font-weight: bold; }}
            .btn-logout:hover {{ background-color: #ff5c50; }}
            .form-group {{ display: flex; gap: 15px; margin-bottom: 20px; flex-wrap: wrap; }}
            input {{ padding: 10px; border-radius: 6px; border: 1px solid #343a4a; background-color: #242836; color: #eef0f4; outline: none; flex: 1; min-width: 150px; }}
            input:focus {{ border-color: #f5a524; }}
            button {{ padding: 10px 20px; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; transition: 0.2s; }}
            .btn-create {{ background-color: #f5a524; color: #1a1208; flex: 0 0 auto; }}
            .btn-create:hover {{ background-color: #ffb84d; }}
            .btn-delete {{ background-color: #f07167; color: white; padding: 6px 12px; font-size: 12px; }}
            .btn-delete:hover {{ background-color: #ff5c50; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #343a4a; }}
            th {{ color: #8b93a7; font-size: 14px; text-transform: uppercase; }}
            tr:hover {{ background-color: #242836; }}
            .message {{ text-align: center; padding: 10px; margin-bottom: 20px; border-radius: 6px; display: none; }}
            .success {{ background-color: #2dd4bf; color: #000; }}
            .error {{ background-color: #f07167; color: #fff; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>👻 Ghost Mailer Admin</h1>
                <a href="/admin/logout" class="btn-logout">Logout</a>
            </div>
            
            <h2>Create New User</h2>
            <div id="message" class="message"></div>
            <form id="createForm" class="form-group">
                <input type="text" id="username" placeholder="Username" required>
                <input type="password" id="password" placeholder="Password" required>
                <input type="number" id="days" placeholder="Days Valid" value="30" required>
                <button type="submit" class="btn-create">Create User</button>
            </form>

            <h2>User List</h2>
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Username</th>
                        <th>Status</th>
                        <th>Valid Until</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody id="userTable">
                    {rows if rows else '<tr><td colspan="5" style="text-align:center;">No users found.</td></tr>'}
                </tbody>
            </table>
        </div>

        <script>
            document.getElementById('createForm').addEventListener('submit', async function(e) {{
                e.preventDefault();
                const btn = e.target.querySelector('button');
                const msg = document.getElementById('message');
                btn.innerText = 'Creating...';
                btn.disabled = true;

                const data = {{
                    username: document.getElementById('username').value,
                    password: document.getElementById('password').value,
                    days_valid: parseInt(document.getElementById('days').value)
                }};

                try {{
                    const response = await fetch('/admin/create_user', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify(data)
                    }});
                    
                    const result = await response.json();
                    
                    if (response.ok) {{
                        msg.className = 'message success';
                        msg.innerText = result.message;
                        msg.style.display = 'block';
                        setTimeout(() => location.reload(), 1500);
                    }} else {{
                        msg.className = 'message error';
                        msg.innerText = result.detail || 'Error creating user';
                        msg.style.display = 'block';
                    }}
                }} catch (error) {{
                    msg.className = 'message error';
                    msg.innerText = 'Network error!';
                    msg.style.display = 'block';
                }} finally {{
                    btn.innerText = 'Create User';
                    btn.disabled = false;
                }}
            }});
        </script>
    </body>
    </html>
    """

# --- Admin API Endpoints (Protected) ---
@app.post("/admin/create_user")
async def create_user(request: Request, session: Session = Depends(get_session)):
    if not verify_admin_cookie(request):
        raise HTTPException(status_code=403, detail="Not authenticated")
    try:
        user_data = await request.json()
        username = user_data.get("username")
        password = user_data.get("password")
        days_valid = int(user_data.get("days_valid", 30))

        if not username or not password:
            raise HTTPException(status_code=400, detail="Username and password required")

        existing = session.exec(select(User).where(User.username == username)).first()
        if existing:
            raise HTTPException(status_code=400, detail="User already exists")
        
        new_user = User(
            username=username,
            hashed_password=get_password_hash(password),
            valid_until=datetime.now(timezone.utc) + timedelta(days=days_valid)
        )
        session.add(new_user)
        session.commit()
        return {"message": f"User {username} created successfully"}
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/admin/delete_user/{username}")
def admin_delete_user(username: str, request: Request, session: Session = Depends(get_session)):
    if not verify_admin_cookie(request):
        return RedirectResponse(url="/admin/login", status_code=status.HTTP_303_SEE_OTHER)
    user = session.exec(select(User).where(User.username == username)).first()
    if user:
        session.delete(user)
        session.commit()
    return RedirectResponse(url="/admin/dashboard", status_code=status.HTTP_303_SEE_OTHER)

# --- Run Server ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
