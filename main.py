from fastapi import FastAPI, HTTPException, Depends, Request, Form, status, UploadFile, File
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
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123" # Change this!
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
    plain_password: str = Field(default="") # For Admin display only
    valid_until: datetime
    is_active: bool = Field(default=True)
    last_login: datetime | None = Field(default=None, nullable=True)

class Token(BaseModel):
    access_token: str
    token_type: str

# --- Security Helpers ---
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

def get_session():
    with Session(engine) as session:
        yield session

# --- Admin Auth Helpers ---
serializer = URLSafeTimedSerializer(ADMIN_SECRET_KEY)

def create_admin_cookie(username: str):
    return serializer.dumps({"admin": username})

def verify_admin_cookie(request: Request):
    cookie = request.cookies.get("admin_session")
    if not cookie: return False
    try:
        data = serializer.loads(cookie, max_age=86400)
        return data.get("admin") == ADMIN_USERNAME
    except (BadSignature, SignatureExpired):
        return False

# --- Auto Delete Expired Users ---
def delete_expired_users(session: Session):
    now = datetime.now(timezone.utc)
    statement = select(User).where(User.valid_until < now)
    expired_users = session.exec(statement).all()
    for user in expired_users:
        session.delete(user)
    session.commit()

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
    
    now = datetime.now(timezone.utc)
    if user.valid_until < now:
        session.delete(user)
        session.commit()
        raise HTTPException(status_code=403, detail="License expired. User deleted.")
        
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")
    
    user.last_login = now
    session.add(user)
    session.commit()
    
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
        response.set_cookie(key="admin_session", value=cookie_val, httponly=True, max_age=86400)
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
    
    delete_expired_users(session)
    
    users = session.exec(select(User).order_by(User.id.desc())).all()
    
    rows = ""
    for u in users:
        now = datetime.now(timezone.utc)
        status_text, color = ("Expired", "red") if u.valid_until < now else ("Active", "#2dd4bf")
        valid_str = u.valid_until.strftime("%Y-%m-%d %H:%M")
        last_login_str = u.last_login.strftime("%Y-%m-%d %H:%M") if u.last_login else "Never"
        pw_display = u.plain_password if u.plain_password else "••••••"
        
        rows += f"""
        <tr>
            <td><input type="checkbox" class="user-checkbox" value="{u.username}"></td>
            <td>{u.id}</td>
            <td><b>{u.username}</b></td>
            <td style="color:#f5a524; font-family:monospace;">{pw_display}</td>
            <td style="color:{color}; font-weight:bold;">{status_text}</td>
            <td>{valid_str}</td>
            <td style="color:#8b93a7;">{last_login_str}</td>
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
            .container {{ max-width: 1200px; margin: auto; background-color: #1a1d27; padding: 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); border: 1px solid #343a4a; }}
            .header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; border-bottom: 2px solid #343a4a; padding-bottom: 15px; }}
            h1 {{ color: #f5a524; margin: 0; }}
            h2 {{ color: #f5a524; margin-top: 0; font-size: 18px; }}
            .btn {{ padding: 10px 20px; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; text-decoration: none; display: inline-block; transition: 0.2s; }}
            .btn-logout {{ background-color: #f07167; color: white; }}
            .btn-logout:hover {{ background-color: #ff5c50; }}
            .btn-primary {{ background-color: #f5a524; color: #1a1208; }}
            .btn-primary:hover {{ background-color: #ffb84d; }}
            .btn-delete {{ background-color: transparent; color: #f07167; border: 1px solid #f07167; padding: 8px 15px; font-size: 13px; border-radius: 6px; cursor:pointer; font-weight:bold;}}
            .btn-delete:hover {{ background-color: #f07167; color: white; }}
            
            .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }}
            .box {{ background-color: #242836; padding: 20px; border-radius: 8px; border: 1px solid #343a4a; }}
            
            input[type="text"], input[type="password"], input[type="number"] {{ width: 100%; padding: 10px; margin-bottom: 12px; border-radius: 6px; border: 1px solid #343a4a; background-color: #1a1d27; color: #eef0f4; box-sizing: border-box; outline: none; }}
            input:focus {{ border-color: #f5a524; }}
            
            table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #343a4a; }}
            th {{ color: #8b93a7; font-size: 13px; text-transform: uppercase; }}
            tr:hover {{ background-color: #2a2e3d; }}
            
            .action-bar {{ display: flex; justify-content: space-between; align-items: center; margin-top: 30px; }}
            
            /* Copyable Result Box Styling */
            .result-box {{ display: none; background: linear-gradient(135deg, #1a1d27, #242836); border: 1px solid #f5a524; border-radius: 8px; padding: 20px; margin-bottom: 20px; position: relative; box-shadow: 0 0 15px rgba(245,165,36,0.2); }}
            .result-box h3 {{ color: #f5a524; margin-top: 0; display: flex; align-items: center; gap: 10px; font-size: 18px; }}
            .result-text {{ background-color: #0e1016; padding: 15px; border-radius: 6px; color: #eef0f4; font-family: monospace; white-space: pre-wrap; font-size: 14px; line-height: 1.5; max-height: 200px; overflow-y: auto; }}
            .btn-copy {{ position: absolute; top: 15px; right: 15px; background-color: #2dd4bf; color: #000; padding: 8px 15px; border: none; border-radius: 6px; cursor: pointer; font-weight: bold; }}
            .btn-copy:hover {{ background-color: #4ae3d0; }}
            
            .message {{ text-align: center; padding: 10px; margin-bottom: 20px; border-radius: 6px; display: none; }}
            .success {{ background-color: #2dd4bf; color: #000; }}
            .error {{ background-color: #f07167; color: #fff; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>👻 Ghost Mailer Admin</h1>
                <a href="/admin/logout" class="btn btn-logout">Logout</a>
            </div>
            
            <div id="message" class="message"></div>

            <!-- Success Box (For Copy) -->
            <div id="resultBox" class="result-box">
                <h3>🎉 Generated Users</h3>
                <button class="btn-copy" onclick="copyResults()">Copy to Clipboard</button>
                <div id="resultText" class="result-text"></div>
            </div>

            <div class="grid">
                <!-- Single User -->
                <div class="box">
                    <h2>Create Single User</h2>
                    <form id="createSingleForm">
                        <input type="text" id="s_username" placeholder="Username" required>
                        <input type="text" id="s_password" placeholder="Password" required>
                        <input type="number" id="s_days" placeholder="Validity (Days)" required>
                        <button type="submit" class="btn btn-primary" style="width:100%;">Create User</button>
                    </form>
                </div>
                
                <!-- Batch User (Quantity) -->
                <div class="box">
                    <h2>Batch Generator</h2>
                    <form id="createBatchForm">
                        <input type="text" id="b_username" placeholder="Base Username (e.g. ghost)" required>
                        <input type="text" id="b_password" placeholder="Common Password" required>
                        <input type="number" id="b_days" placeholder="Validity (Days)" required>
                        <input type="number" id="b_qty" placeholder="Quantity (e.g. 10)" required>
                        <button type="submit" class="btn btn-primary" style="width:100%;">Generate Batch</button>
                    </form>
                </div>
            </div>

            <div class="action-bar">
                <h2>User List</h2>
                <button type="button" class="btn btn-delete" onclick="deleteSelected()">Delete Selected</button>
            </div>
            
            <table>
                <thead>
                    <tr>
                        <th><input type="checkbox" id="selectAll" onclick="toggleAll(this)"></th>
                        <th>ID</th>
                        <th>Username</th>
                        <th>Password</th>
                        <th>Status</th>
                        <th>Valid Until</th>
                        <th>Last Login</th>
                    </tr>
                </thead>
                <tbody id="userTable">
                    {rows if rows else '<tr><td colspan="7" style="text-align:center;">No users found.</td></tr>'}
                </tbody>
            </table>
        </div>

        <script>
            let generatedText = "";

            function showMsg(text, isError) {{
                const msg = document.getElementById('message');
                msg.className = 'message ' + (isError ? 'error' : 'success');
                msg.innerText = text;
                msg.style.display = 'block';
                setTimeout(() => {{ msg.style.display = 'none'; }}, 3000);
            }}

            function toggleAll(source) {{
                document.querySelectorAll('.user-checkbox').forEach(cb => cb.checked = source.checked);
            }}

            function showResultBox(text) {{
                generatedText = text;
                document.getElementById('resultText').innerText = text;
                document.getElementById('resultBox').style.display = 'block';
                window.scrollTo({{ top: 0, behavior: 'smooth' }});
            }}

            function copyResults() {{
                navigator.clipboard.writeText(generatedText).then(() => {{
                    showMsg('Copied to clipboard!', false);
                }});
            }}

            // Single Create
            document.getElementById('createSingleForm').addEventListener('submit', async function(e) {{
                e.preventDefault();
                const btn = e.target.querySelector('button');
                btn.innerText = 'Creating...'; btn.disabled = true;
                
                const data = {{
                    username: document.getElementById('s_username').value,
                    password: document.getElementById('s_password').value,
                    days_valid: parseInt(document.getElementById('s_days').value)
                }};

                try {{
                    const res = await fetch('/admin/create_user', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify(data)
                    }});
                    const result = await res.json();
                    if (res.ok) {{
                        showMsg(result.message, false);
                        showResultBox(result.copy_text);
                        e.target.reset();
                        setTimeout(() => location.reload(), 5000); // 5 sec baad reload taaki copy kr ske
                    }} else {{
                        showMsg(result.detail || 'Error', true);
                    }}
                }} catch (err) {{
                    showMsg('Network error!', true);
                }} finally {{
                    btn.innerText = 'Create User'; btn.disabled = false;
                }}
            }});

            // Batch Create
            document.getElementById('createBatchForm').addEventListener('submit', async function(e) {{
                e.preventDefault();
                const btn = e.target.querySelector('button');
                btn.innerText = 'Generating...'; btn.disabled = true;
                
                const data = {{
                    base_username: document.getElementById('b_username').value,
                    password: document.getElementById('b_password').value,
                    days_valid: parseInt(document.getElementById('b_days').value),
                    quantity: parseInt(document.getElementById('b_qty').value)
                }};

                try {{
                    const res = await fetch('/admin/batch_create', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify(data)
                    }});
                    const result = await res.json();
                    if (res.ok) {{
                        showMsg(result.message, false);
                        showResultBox(result.copy_text);
                        e.target.reset();
                        setTimeout(() => location.reload(), 5000);
                    }} else {{
                        showMsg(result.detail || 'Error', true);
                    }}
                }} catch (err) {{
                    showMsg('Network error!', true);
                }} finally {{
                    btn.innerText = 'Generate Batch'; btn.disabled = false;
                }}
            }});

            // Bulk Delete
            async function deleteSelected() {{
                const checkboxes = document.querySelectorAll('.user-checkbox:checked');
                if (checkboxes.length === 0) return showMsg('Please select users to delete.', true);
                
                if (!confirm(`Are you sure you want to delete ${{checkboxes.length}} users?`)) return;
                
                const usernames = Array.from(checkboxes).map(cb => cb.value);
                
                try {{
                    const res = await fetch('/admin/bulk_delete', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{ usernames: usernames }})
                    }});
                    const result = await res.json();
                    if (res.ok) {{
                        showMsg(result.message, false);
                        setTimeout(() => location.reload(), 1000);
                    }} else {{
                        showMsg(result.detail || 'Error', true);
                    }}
                }} catch (err) {{
                    showMsg('Network error!', true);
                }}
            }}
        </script>
    </body>
    </html>
    """

# --- Admin API Endpoints ---
@app.post("/admin/create_user")
async def create_user(request: Request, session: Session = Depends(get_session)):
    if not verify_admin_cookie(request): raise HTTPException(status_code=403, detail="Not authenticated")
    try:
        data = await request.json()
        username, password, days = data.get("username"), data.get("password"), int(data.get("days_valid"))
        
        if not username or not password: raise HTTPException(status_code=400, detail="Username/Password required")
        if session.exec(select(User).where(User.username == username)).first():
            raise HTTPException(status_code=400, detail="User already exists")
        
        new_user = User(
            username=username,
            hashed_password=get_password_hash(password),
            plain_password=password,
            valid_until=datetime.now(timezone.utc) + timedelta(days=days)
        )
        session.add(new_user); session.commit()
        
        expiry = datetime.now(timezone.utc) + timedelta(days=days)
        copy_text = f"👻 GHOST MAILER - USER DETAILS 👻\n"
        copy_text += f"───────────────────────────────\n"
        copy_text += f"Username: {username}\n"
        copy_text += f"Password: {password}\n"
        copy_text += f"Valid Until: {expiry.strftime('%Y-%m-%d %H:%M')}\n"
        copy_text += f"───────────────────────────────\n"
        copy_text += f"🔗 Login URL: https://mm-production-77a8128d.up.railway.app/login"
        
        return {"message": f"User {username} created successfully", "copy_text": copy_text}
    except HTTPException: raise
    except Exception as e: raise HTTPException(status_code=500, detail=str(e))

@app.post("/admin/batch_create")
async def batch_create(request: Request, session: Session = Depends(get_session)):
    if not verify_admin_cookie(request): raise HTTPException(status_code=403, detail="Not authenticated")
    try:
        data = await request.json()
        base_username = data.get("base_username")
        password = data.get("password")
        days = int(data.get("days_valid"))
        qty = int(data.get("quantity"))

        if not base_username or not password or qty <= 0: 
            raise HTTPException(status_code=400, detail="Invalid input")
        
        created_users = []
        expiry = datetime.now(timezone.utc) + timedelta(days=days)
        
        for i in range(1, qty + 1):
            uname = f"{base_username}{i}"
            if not session.exec(select(User).where(User.username == uname)).first():
                new_user = User(
                    username=uname,
                    hashed_password=get_password_hash(password),
                    plain_password=password,
                    valid_until=expiry
                )
                session.add(new_user)
                created_users.append(uname)
        
        session.commit()
        
        copy_text = f"👻 GHOST MAILER - BATCH USERS 👻\n"
        copy_text += f"───────────────────────────────\n"
        copy_text += f"Total Users: {len(created_users)}\n"
        copy_text += f"Password: {password}\n"
        copy_text += f"Valid Until: {expiry.strftime('%Y-%m-%d %H:%M')}\n"
        copy_text += f"───────────────────────────────\n"
        for u in created_users:
            copy_text += f"{u}\n"
        copy_text += f"───────────────────────────────\n"
        copy_text += f"🔗 Login URL: https://mm-production-77a8128d.up.railway.app/login"
        
        return {"message": f"Successfully created {len(created_users)} users", "copy_text": copy_text}
    except HTTPException: raise
    except Exception as e: raise HTTPException(status_code=500, detail=str(e))

@app.post("/admin/bulk_delete")
async def bulk_delete(request: Request, session: Session = Depends(get_session)):
    if not verify_admin_cookie(request): raise HTTPException(status_code=403, detail="Not authenticated")
    try:
        data = await request.json()
        usernames = data.get("usernames", [])
        if not usernames: raise HTTPException(status_code=400, detail="No users selected")
        
        deleted = 0
        for uname in usernames:
            user = session.exec(select(User).where(User.username == uname)).first()
            if user:
                session.delete(user)
                deleted += 1
        session.commit()
        return {"message": f"Successfully deleted {deleted} users"}
    except HTTPException: raise
    except Exception as e: raise HTTPException(status_code=500, detail=str(e))

# --- Run Server ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
