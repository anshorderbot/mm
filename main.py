from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlmodel import Field, Session, SQLModel, create_engine, select
from datetime import datetime, timedelta, timezone
import jwt
import os
import uvicorn
import bcrypt

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

# --- Security (Direct bcrypt, no passlib) ---
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
    if user.valid_until < datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="License expired")
    
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# --- Admin Endpoints ---
@app.post("/admin/create_user")
async def create_user(request: Request, session: Session = Depends(get_session)):
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

@app.delete("/admin/delete_user/{username}")
def delete_user(username: str, session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.username == username)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    session.delete(user)
    session.commit()
    return {"message": f"User {username} deleted"}

# --- Web Admin Panel ---
@app.get("/", response_class=HTMLResponse)
def admin_panel(session: Session = Depends(get_session)):
    users = session.exec(select(User)).all()
    
    rows = ""
    for u in users:
        status = "Active" if u.is_active and u.valid_until > datetime.now(timezone.utc) else "Expired/Disabled"
        color = "green" if status == "Active" else "red"
        date_str = u.valid_until.strftime("%Y-%m-%d %H:%M")
        rows += f"""
        <tr>
            <td>{u.id}</td>
            <td><b>{u.username}</b></td>
            <td style="color:{color}; font-weight:bold;">{status}</td>
            <td>{date_str}</td>
            <td>
                <form action="/admin/delete_user/{u.username}" method="POST" style="display:inline;">
                    <button type="submit" class="btn-delete">Delete</button>
                </form>
            </td>
        </tr>
        """
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Ghost Mailer - Admin Panel</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #12141a; color: #eef0f4; margin: 0; padding: 20px; }}
            .container {{ max-width: 900px; margin: auto; background-color: #1a1d27; padding: 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); border: 1px solid #343a4a; }}
            h1 {{ color: #f5a524; text-align: center; margin-bottom: 30px; }}
            h2 {{ color: #f5a524; border-bottom: 2px solid #343a4a; padding-bottom: 10px; }}
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
            <h1>👻 Ghost Mailer Admin</h1>
            
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
    return html_content

@app.post("/admin/delete_user/{username}")
def admin_delete_user(username: str, session: Session = Depends(get_session)):
    user = session.exec(select(User).where(User.username == username)).first()
    if user:
        session.delete(user)
        session.commit()
    return HTMLResponse(content="<script>window.location.href='/'</script>")

# --- Run Server ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
