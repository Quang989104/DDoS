from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr
from scapy.all import sniff, IP, get_if_list
from datetime import datetime, timedelta
import sqlite3
import asyncio
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List
import json
from html import escape
import bcrypt
import secrets


app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
active_connections: List[WebSocket] = []

conn = sqlite3.connect('network_monitoring.db')
cursor = conn.cursor()

try:
    cursor.execute("PRAGMA foreign_keys = OFF;")
    
    cursor.execute("DELETE FROM AttackLogs;")
    cursor.execute("DELETE FROM TrafficLogs;")
    cursor.execute("DELETE FROM Alerts;")
    cursor.execute("DELETE FROM Reports;")
    
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='AttackLogs';")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='TrafficLogs';")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='Alerts';")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='Reports';")
    
    cursor.execute("PRAGMA foreign_keys = ON;")
    
    conn.commit()
    print("Đã xóa dữ liệu và reset ID thành công.")

except Exception as e:
    print("Lỗi khi xóa dữ liệu:", e)
    conn.rollback()

finally:
    conn.close()



conn = sqlite3.connect("network_monitoring.db", check_same_thread=False)
cursor = conn.cursor()
reset_tokens = {}
reset_tokens_expiry = {}

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

@app.get("/update-password-to-hashed")
def update_password_to_hashed():
    cursor.execute("SELECT password FROM Admin WHERE username = ?", ("admin",))
    row = cursor.fetchone()

    if row is None:
        return {"message": "Không tìm thấy user admin"}

    current_password = row[2]

    if current_password.startswith("$2b$"):
        return {"message": "Mật khẩu đã được mã hóa rồi"}

    hashed = hash_password(current_password)
    cursor.execute("UPDATE Admin SET password = ? WHERE username = ?", (hashed, "admin"))
    conn.commit()

    return {"message": "Cập nhật mật khẩu đã mã hóa thành công!"}


def send_reset_password(email: str, reset_link: str):
    subject = "Yêu cầu đặt lại mật khẩu"
    body = f"""\
    Xin chào,

    Bạn đã yêu cầu đặt lại mật khẩu. Hãy nhấp vào liên kết dưới đây để đặt lại mật khẩu (có hiệu lực trong 15 phút):

    {reset_link}

    Nếu bạn không yêu cầu, hãy bỏ qua email này.
    """
    sender_email = "quangloanthanhchien4@gmail.com"
    sender_password = "nvtwvjpwnenkzrhj"

    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = sender_email
        msg["To"] = email

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, [email], msg.as_string())

        return {"message": "Mật khẩu đã được gửi đến email của bạn"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi khi gửi email: {str(e)}")

class ForgotPasswordRequest(BaseModel):
    admin_email: str

@app.post("/forgot-password")
async def forgot_password(request_data: ForgotPasswordRequest):
    email = request_data.admin_email.strip()

    cursor.execute("SELECT * FROM Admin WHERE email = ?", (email,))
    if not cursor.fetchone():
        return JSONResponse(content={"message": "Email không tồn tại!"}, status_code=404)

    token = secrets.token_urlsafe(16)
    reset_tokens[token] = email
    reset_tokens_expiry[token] = datetime.now() + timedelta(minutes=15)

    reset_link = f"http://localhost:8000/reset-password?token={token}"

    send_reset_password(email, reset_link)

    return {"message": "Đã gửi link đặt lại mật khẩu đến email."}

@app.get("/reset-password", response_class=HTMLResponse)
async def reset_password_form(token: str):
    if token not in reset_tokens or datetime.now() > reset_tokens_expiry[token]:
        return HTMLResponse("Token không hợp lệ hoặc đã hết hạn!", status_code=400)

    escaped_token = escape(token)

    return f"""
    <!DOCTYPE html>
    <html lang="vi">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Đặt lại mật khẩu</title>
        <style>
            /* CSS giữ nguyên như bạn đã viết */
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
                font-family: 'Arial', sans-serif;
            }}
            body {{
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                background: linear-gradient(135deg, #833ab4, #4a90e2);
            }}
            .login-container {{
                width: 350px;
                padding: 20px;
                background: white;
                border-radius: 10px;
                box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
                text-align: center;
            }}
            .login-container h2 {{
                margin-bottom: 20px;
                font-size: 24px;
                color: #333;
                font-weight: bold;
            }}
            .form-group {{
                position: relative;
                margin-bottom: 20px;
            }}
            .form-group input {{
                width: 100%;
                padding: 10px;
                border: none;
                border-bottom: 2px solid #ccc;
                font-size: 16px;
                outline: none;
                background: transparent;
            }}
            .form-group input:focus {{
                border-bottom: 2px solid #4a90e2;
            }}
            .submit {{
                width: 100%;
                padding: 10px;
                border: none;
                border-radius: 5px;
                background: linear-gradient(to right, #833ab4, #4a90e2);
                color: white;
                font-size: 16px;
                cursor: pointer;
                transition: 0.3s;
            }}
            .submit:hover {{
                background: linear-gradient(to right, #4a90e2, #833ab4);
            }}
            .error {{
                color: red;
                font-size: 14px;
                margin-top: 5px;
            }}
        </style>
    </head>
    <body>
        <div class="login-container">
            <h2>Đặt lại mật khẩu</h2>
            <form id="resetForm" action="/reset-password?token={escaped_token}" method="post">
                <div class="form-group">
                    <input type="password" name="new_password" id="new_password" placeholder="Mật khẩu mới" required/>
                </div>
                <div class="form-group">
                    <input type="password" name="confirm_password" id="confirm_password" placeholder="Nhập lại mật khẩu" required/>
                </div>
                <button class="submit" type="submit">Cập nhật</button>
                <p id="error-message" class="error"></p>
            </form>
        </div>

        <script>
            document.getElementById('resetForm').onsubmit = function(event) {{
                var newPassword = document.getElementById('new_password').value;
                var confirmPassword = document.getElementById('confirm_password').value;
                var errorMessage = document.getElementById('error-message');

                if (newPassword.trim() === "" || confirmPassword.trim() === "") {{
                    errorMessage.textContent = "Mật khẩu không được để trống.";
                    event.preventDefault();
                    return false;
                }}

            if (newPassword.includes(" ") || confirmPassword.includes(" ")) {{
                errorMessage.textContent = "Mật khẩu không được chứa khoảng trắng.";
                event.preventDefault();
                return false;
            }}

            if (newPassword !== confirmPassword) {{
                errorMessage.textContent = "Mật khẩu và mật khẩu xác nhận không khớp.";
                event.preventDefault();
                return false;
            }}

            return true;
        }};
    </script>
</body>
</html>
    """

@app.post("/reset-password")
async def reset_password(request: Request, new_password: str = Form(...)):
    token = request.query_params.get("token")

    if token not in reset_tokens or datetime.now() > reset_tokens_expiry[token]:
        return JSONResponse({"message": "Token không hợp lệ hoặc đã hết hạn!"}, status_code=400)

    email = reset_tokens[token]
    hashed_new_pw = hash_password(new_password)

    cursor.execute("UPDATE Admin SET password = ? WHERE email = ?", (hashed_new_pw, email))
    conn.commit()

    del reset_tokens[token]
    del reset_tokens_expiry[token]

    return {"message": "Đặt lại mật khẩu thành công!"}


from fastapi import Request
from fastapi import FastAPI
from email.mime.text import MIMEText
import smtplib

def send_alert_email(alert_data, admin_name, admin_email):
    subject = "[CẢNH BÁO] Tấn công DDOS được phát hiện"
    body = f"""
Xin chào {admin_name},

Bạn có một cảnh báo mới từ hệ thống giám sát mạng:

- Nội dung: {alert_data.get('alert_message')}
- Thời gian: {alert_data.get('timestamp')}
- Loại tấn công: {alert_data.get('attack_type')}
- Tổng số gói tin: {alert_data.get('packet_count')}
- Băng thông: {alert_data.get('bandwidth_usage')}
- Mức độ: {alert_data.get('level')}
- IP nguồn: {alert_data.get('source_ip')}

Vui lòng kiểm tra hệ thống để xử lý kịp thời.

Trân trọng,
Hệ thống Giám sát Mạng
"""

    sender_email = "quangloanthanhchien4@gmail.com"
    sender_password = "nvtwvjpwnenkzrhj"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = admin_email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, [admin_email], msg.as_string())
        print("✅ Gửi email cảnh báo thành công")
    except Exception as e:
        print("❌ Lỗi gửi email:", e)

def get_admin_info():
    conn = sqlite3.connect("network_monitoring.db")
    cursor = conn.cursor()
    cursor.execute("SELECT username, email FROM Admin LIMIT 1")
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return {"username": result[0], "email": result[1]}
    return None



class ThresholdRequest(BaseModel):
    value: float

@app.post("/change-threshold")
async def change_threshold(data: ThresholdRequest):
    global threshold
    try:
        threshold = data.value
        return {"status": "success", "message": f"Threshold đã được cập nhật thành {threshold}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi khi cập nhật threshold: {str(e)}")


class ChangePasswordRequest(BaseModel):
    admin_id: int
    old_password: str
    new_password: str


@app.post("/change-password")
async def change_password(data: ChangePasswordRequest):
    try:
        if not data.new_password.strip():
            raise HTTPException(status_code=400, detail="Mật khẩu mới không được để trống")
        if ' ' in data.new_password:
            raise HTTPException(status_code=400, detail="Mật khẩu mới không được chứa khoảng trắng")

        with sqlite3.connect("network_monitoring.db") as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT password FROM Admin WHERE id = ?", (data.admin_id,))
            result = cursor.fetchone()

            if not result:
                raise HTTPException(status_code=404, detail="Không tìm thấy admin")

            stored_hashed_password = result[0]
            if not check_password(data.old_password, stored_hashed_password):
                raise HTTPException(status_code=400, detail="Mật khẩu cũ không đúng")
            hashed_new_password = hash_password(data.new_password)

            cursor.execute("UPDATE Admin SET password = ? WHERE id = ?", (hashed_new_password, data.admin_id))
            conn.commit()

        return {"status": "success", "message": "Mật khẩu đã được thay đổi thành công"}

    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi khi thay đổi mật khẩu: {str(e)}")

class ChangeNameRequest(BaseModel):
    admin_id: int
    new_name: str
@app.post("/change-name")
async def change_name(data: ChangeNameRequest):
    try:
        with sqlite3.connect("network_monitoring.db") as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM Admin WHERE id = ?", (data.admin_id,))
            user = cursor.fetchone()

            if user is None:
                raise HTTPException(status_code=404, detail="Admin không tồn tại")

            cursor.execute("UPDATE Admin SET username = ? WHERE id = ?", (data.new_name, data.admin_id))
            conn.commit()

        return {"status": "success", "message": "Tên đã được thay đổi thành công"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi khi đổi tên: {str(e)}")
    

class ChangeEmailRequest(BaseModel):
    admin_id: int
    new_email: EmailStr 

@app.post("/change-email")
async def change_email(data: ChangeEmailRequest):
    try:
        with sqlite3.connect("network_monitoring.db") as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM Admin WHERE id = ?", (data.admin_id,))
            user = cursor.fetchone()

            if user is None:
                raise HTTPException(status_code=404, detail="Admin không tồn tại")

            cursor.execute("UPDATE Admin SET email = ? WHERE id = ?", (data.new_email, data.admin_id))
            conn.commit()

        return {"status": "success", "message": "Email đã được cập nhật thành công"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi khi thay đổi email: {str(e)}")


@app.websocket("/ws/admin")
async def websocket_admins(websocket: WebSocket):
    await websocket.accept()

    try:
        while True:
            with sqlite3.connect("network_monitoring.db") as conn:
                cursor = conn.cursor()

                cursor.execute("SELECT * FROM Admin ORDER BY username DESC")
                rows = cursor.fetchall()

                admins = []
                for row in rows:
                    admin = {
                        "id": row[0],
                        "username": row[1],
                        "password": row[2],
                        "email": row[3]
                    }
                    admins.append(admin)
                await websocket.send_json(admins)
            await asyncio.sleep(1)

    except WebSocketDisconnect:
        print(" Client đã ngắt kết nối WebSocket.")
    except Exception as e:
        print(f" Lỗi khi xử lý WebSocket: {e}")
class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/login")
def login(data: LoginRequest):
    conn = sqlite3.connect("network_monitoring.db")
    cursor = conn.cursor()

    cursor.execute("SELECT password FROM Admin WHERE username = ?", (data.username,))
    result = cursor.fetchone()
    conn.close()

    if result:
        hashed_password = result[0]
        if check_password(data.password, hashed_password):
            return {"status": "success", "message": "Đăng nhập thành công"}
        else:
            raise HTTPException(status_code=401, detail="Sai mật khẩu")
    else:
        raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản")
    

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await websocket.accept()
    last_count = -1

    try:
        while True:
            with sqlite3.connect("network_monitoring.db") as conn:
                cursor = conn.cursor()

                # Kiểm tra số lượng cảnh báo hiện tại
                cursor.execute("SELECT COUNT(*) FROM Alerts")
                current_count = cursor.fetchone()[0]

                if current_count != last_count:
                    cursor.execute("""
                        SELECT 
                            a.id, a.alert_message,
                            al.attack_type, al.level,
                            t.source_ip, t.bandwidth_usage, t.packet_count, t.timestamp,
                            ad.username, ad.email
                        FROM Alerts a
                        JOIN AttackLogs al ON a.attack_log_id = al.id
                        JOIN TrafficLogs t ON al.traffic_log_id = t.id
                        LEFT JOIN Admin ad ON a.admin_id = ad.id
                        ORDER BY t.timestamp DESC
                    """)
                    rows = cursor.fetchall()

                    alerts = []
                    for row in rows:
                        alert = {
                            "id": row[0],
                            "alert_message": row[1],
                            "attack_type": row[2],
                            "level": row[3],
                            "source_ip": row[4],
                            "bandwidth_usage": row[5],
                            "packet_count": row[6],
                            "timestamp": row[7],
                            "admin_name": row[8],
                            "admin_email": row[9],
                        }
                        alerts.append(alert)

                    await websocket.send_json(alerts)
                    last_count = current_count

            await asyncio.sleep(1)

    except WebSocketDisconnect:
        print("❌ WebSocket client đã ngắt kết nối.")
    except Exception as e:
        print(f"❌ Lỗi WebSocket Alerts: {e}")




@app.websocket("/ws/reports")
async def websocket_reports(websocket: WebSocket):
    await websocket.accept()
    last_count = -1

    try:
        while True:
            with sqlite3.connect("network_monitoring.db") as conn:
                cursor = conn.cursor()

                # Đếm số lượng bản ghi Reports thay vì AttackLogs
                cursor.execute("SELECT COUNT(*) FROM Reports")
                current_count = cursor.fetchone()[0]

                if current_count != last_count:
                    cursor.execute("""
                        SELECT 
                            r.id, t.timestamp, t.source_ip, t.packet_count,
                            t.bandwidth_usage, al.attack_type, al.level,
                            r.admin_id, r.attack_log_id
                        FROM Reports r
                        JOIN AttackLogs al ON r.attack_log_id = al.id
                        JOIN TrafficLogs t ON al.traffic_log_id = t.id
                        ORDER BY t.timestamp DESC
                    """)
                    rows = cursor.fetchall()

                    reports = []
                    for row in rows:
                        report = {
                            "id": row[0],
                            "timestamp": row[1],
                            "source_ip": row[2],
                            "packet_count": row[3],
                            "bandwidth_usage": row[4],
                            "attack_type": row[5],
                            "level": row[6],
                            "admin_id": row[7],
                            "attack_log_id": row[8]
                        }
                        reports.append(report)

                    await websocket.send_json(reports)
                    last_count = current_count

            await asyncio.sleep(1)

    except WebSocketDisconnect:
        print("❌ Client đã ngắt kết nối WebSocket.")
    except Exception as e:
        print(f"❌ Lỗi khi xử lý WebSocket Reports: {e}")


import aiosqlite

@app.delete("/api/alerts/{alert_id}")
async def delete_alert(alert_id: int):
    async with aiosqlite.connect("network_monitoring.db") as db:
        cursor = await db.execute("SELECT * FROM Alerts WHERE id = ?", (alert_id,))
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found")

        await db.execute("DELETE FROM Alerts WHERE id = ?", (alert_id,))
        await db.commit()
        print("DELETE_SUCCESS")
    return {"message": "Alert deleted successfully"}


threshold = 70
active_connections = []

@app.websocket("/ws/traffic")
async def websocket_traffic(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    print(f"✅ Client connected: {websocket.client}")

    try:
        while True:
            try:
                message = await websocket.receive_text()

                if message.strip().lower() == "ping":
                    await websocket.send_text("pong")
                    continue

                try:
                    data = json.loads(message)
                except json.JSONDecodeError:
                    print(f"❌ Dữ liệu không hợp lệ từ client: {message}")
                    continue

                source_ip = data.get("source_ip")
                if isinstance(source_ip, list):
                    source_ip = "   ".join(source_ip)

                bandwidth = data.get("bandwidth_usage", 0)

                if bandwidth > threshold:
                    with sqlite3.connect("network_monitoring.db") as conn:
                        cursor = conn.cursor()

                        # 1. Thêm vào TrafficLogs
                        cursor.execute("""
                            INSERT INTO TrafficLogs (timestamp, source_ip, destination_ip, packet_count, bandwidth_usage)
                            VALUES (?, ?, ?, ?, ?)
                        """, (
                            data.get("timestamp"),
                            source_ip,
                            data.get("destination_ip"),
                            data.get("packet_count"),
                            bandwidth
                        ))
                        traffic_log_id = cursor.lastrowid

                        # 2. Xác định mức độ tấn công
                        if bandwidth > threshold + 60:
                            level = "High"
                        elif bandwidth > threshold + 30:
                            level = "Medium"
                        else:
                            level = "Low"

                        # 3. Thêm vào AttackLogs
                        cursor.execute("""
                            INSERT INTO AttackLogs (
                                attack_type, level, traffic_log_id
                            )
                            VALUES (?, ?, ?)
                        """, (
                            data.get("attack_type"),
                            level,
                            traffic_log_id
                        ))

                        attack_log_id = cursor.lastrowid

                        # 4. Thêm vào Reports (bỏ timestamp)
                        cursor.execute("""
                            INSERT INTO Reports (
                                attack_log_id, admin_id
                            )
                            VALUES (?, ?)
                        """, (
                            attack_log_id,
                            1
                        ))

                        # 5. Thêm vào Alerts (bỏ timestamp)
                        cursor.execute("""
                            INSERT INTO Alerts (
                                attack_log_id, admin_id, alert_message
                            )
                            VALUES (?, ?, ?)
                        """, (
                            attack_log_id,
                            1,
                            "Abnormal traffic increase"
                        ))

                        # 6. Gửi email nếu cần
                        admin = get_admin_info()
                        if admin:
                            alert_data = {
                                "alert_message": "Abnormal traffic increase",
                                "timestamp": data.get("timestamp"),
                                "attack_type": data.get("attack_type"),
                                "packet_count": data.get("packet_count"),
                                "bandwidth_usage": bandwidth,
                                "level": level,
                                "source_ip": source_ip,
                            }
                            send_alert_email(alert_data, admin["username"], admin["email"])

                        conn.commit()

                # Gửi dữ liệu về tất cả client đang kết nối
                disconnected_clients = []
                for client in active_connections:
                    try:
                        await client.send_json(data)
                    except:
                        disconnected_clients.append(client)

                for dc in disconnected_clients:
                    if dc in active_connections:
                        active_connections.remove(dc)

            except WebSocketDisconnect:
                break

    finally:
        if websocket in active_connections:
            active_connections.remove(websocket)
            print(f"❌ Client disconnected: {websocket.client}")


app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", include_in_schema=False)
async def root():
    return FileResponse("static/login.html", media_type="text/html")

html_routes = {
    "/main.html": "main.html",
    "/traffic.html": "traffic.html",
    "/login.html": "login.html",
    "/alerts.html": "alerts.html",
    "/reports.html": "reports.html",
    "/settings.html": "Settings.html",
    "/attacklog.html": "attackLog.html",
    "/test.html": "test.html",
    "/pass.html": "pass.html"
}

def create_html_route(path, filename):
    @app.get(path)
    async def serve():
        return FileResponse(f"static/{filename}", media_type="text/html")

for path, filename in html_routes.items():
    create_html_route(path, filename)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class TrafficLog(BaseModel):
    timestamp: str
    source_ip: str
    destination_ip: str
    packet_count: int
    bandwidth_usage: float

sniffing_status = {"status": "stopped"}

def create_tables():
    conn = sqlite3.connect("network_monitoring.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Admin (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username VARCHAR(100),
        password VARCHAR(255),
        email VARCHAR(255)
    )""")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS TrafficLogs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            packet_count INTEGER,
            bandwidth_usage REAL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS AttackLogs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            attack_type TEXT,
            level TEXT,
            traffic_log_id INTEGER
        )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attack_log_id INTEGER,
        admin_id INTEGER,
        alert_message VARCHAR(255),
        FOREIGN KEY (attack_log_id) REFERENCES AttackLogs(id)
    )""")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attack_log_id INTEGER,
        admin_id INTEGER,
        FOREIGN KEY (attack_log_id) REFERENCES AttackLogs(id)
    )""")
    conn.commit()
    conn.close()

create_tables()





