from fastapi import FastAPI, WebSocket, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from scapy.all import sniff, IP, get_if_list
from datetime import datetime
import sqlite3
import asyncio
from pydantic import BaseModel, EmailStr
import threading


app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Thay "*" bằng ["http://localhost:8000"] nếu cần giới hạn
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi import WebSocket
from typing import List
from fastapi import WebSocketDisconnect

active_connections: List[WebSocket] = []
import sqlite3


# Kết nối tới cơ sở dữ liệu
conn = sqlite3.connect('network_monitoring.db')  # Thay 'your_database_file.db' bằng đường dẫn thực tế
cursor = conn.cursor()

try:
    # Tắt kiểm tra ràng buộc khóa ngoại nếu có
    cursor.execute("PRAGMA foreign_keys = OFF;")
    
    # Xóa dữ liệu trong hai bảng
    cursor.execute("DELETE FROM AttackLogs;")
    cursor.execute("DELETE FROM TrafficLogs;")
    cursor.execute("DELETE FROM Alerts;")
    
    # Reset auto increment (chỉ với SQLite)
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='AttackLogs';")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='TrafficLogs';")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='Alerts';")
    
    # Bật lại kiểm tra khóa ngoại
    cursor.execute("PRAGMA foreign_keys = ON;")
    
    conn.commit()
    print("Đã xóa dữ liệu và reset ID thành công.")

except Exception as e:
    print("Lỗi khi xóa dữ liệu:", e)
    conn.rollback()

finally:
    conn.close()


from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
import sqlite3
import bcrypt
import secrets
from datetime import datetime, timedelta
conn = sqlite3.connect("network_monitoring.db", check_same_thread=False)
cursor = conn.cursor()
# Lưu token đặt lại mật khẩu tạm thời (RAM)
reset_tokens = {}
reset_tokens_expiry = {}

# Hàm băm mật khẩu
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

# Kiểm tra mật khẩu
def check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())

# Cập nhật mật khẩu thành hash
@app.get("/update-password-to-hashed")
def update_password_to_hashed():
    cursor.execute("SELECT password FROM Admin WHERE username = ?", ("admin",))
    row = cursor.fetchone()

    if row is None:
        return {"message": "Không tìm thấy user admin"}

    current_password = row[3]  # sửa lại index nếu cần, thường là 0 nếu chỉ SELECT 1 cột

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

    # Thông tin tài khoản gửi email
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
# ✅ Model để nhận JSON từ frontend
class ForgotPasswordRequest(BaseModel):
    admin_email: str

# Gửi yêu cầu quên mật khẩu (sửa lại để nhận JSON)
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

    # ✅ Gửi email thay vì chỉ in ra
    send_reset_password(email, reset_link)

    return {"message": "Đã gửi link đặt lại mật khẩu đến email."}

# Form đặt lại mật khẩu
@app.get("/reset-password", response_class=HTMLResponse)
async def reset_password_form(token: str):
    if token not in reset_tokens or datetime.now() > reset_tokens_expiry[token]:
        return HTMLResponse("Token không hợp lệ hoặc đã hết hạn!", status_code=400)

    return f"""
    <html>
        <body>
            <h3>Đặt lại mật khẩu</h3>
            <form action="/reset-password?token={token}" method="post">
                <input type="password" name="new_password" placeholder="Mật khẩu mới" required/>
                <button type="submit">Cập nhật</button>
            </form>
        </body>
    </html>
    """

# Xử lý đặt lại mật khẩu
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
"""@app.post("/forgot-password")
async def forgot_password(request: Request):
    data = await request.json()
    admin_email = data.get("admin_email")

    if not admin_email:
        raise HTTPException(status_code=400, detail="Vui lòng cung cấp địa chỉ email")

    try:
        with sqlite3.connect("network_monitoring.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT username, password FROM Admin WHERE email = ?", (admin_email,))
            admin_info = cursor.fetchone()

            if admin_info is None:
                raise HTTPException(status_code=404, detail="Không tìm thấy tài khoản với email đã cung cấp.")

            username, password = admin_info
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi truy xuất cơ sở dữ liệu: {str(e)}")

    # Soạn nội dung email
    subject = "[Quên mật khẩu] Thông tin tài khoản đăng nhập"
    body = f""
    Xin chào,

    Bạn đã yêu cầu lấy lại mật khẩu cho tài khoản quản trị viên. Dưới đây là thông tin đăng nhập của bạn:

    - Username: {username}
    - Password: {password}

    Vui lòng đăng nhập lại hệ thống và thay đổi mật khẩu nếu cần thiết.

    Trân trọng,
    Hệ thống Giám sát Mạng
    ""

    # Thông tin tài khoản gửi email
    sender_email = "quangloanthanhchien4@gmail.com"
    sender_password = "nvtwvjpwnenkzrhj"

    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = sender_email
        msg["To"] = admin_email

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, [admin_email], msg.as_string())

        return {"message": "Mật khẩu đã được gửi đến email của bạn"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi khi gửi email: {str(e)}")
"""


@app.post("/send-alert-email")
async def send_alert_email(request: Request):
    data = await request.json()

    # Lấy các thông tin từ client gửi lên
    alert_message = data.get("alert_message")
    alert_type = data.get("alert_type")
    level = data.get("level")
    source_ip = data.get("source_ip")
    bandwidth = data.get("bandwidth_kbps")
    packet_count = data.get("packet_count")
    admin_email = data.get("admin_email")
    admin_name = data.get("admin_name")

    # Soạn nội dung email
    subject = f"[Cảnh báo] {alert_type} - {level.upper()}"
    body = f"""
    Xin chào {admin_name},

    Một cảnh báo mới vừa được ghi nhận:

    - Nội dung: {alert_message}
    - Loại tấn công: {alert_type}
    - Tổng số gói tin: {packet_count}
    - Băng thông: {bandwidth}
    - Mức độ: {level}
    - IP nguồn: {source_ip}

    Vui lòng kiểm tra hệ thống để xử lý kịp thời.

    Trân trọng,
    Hệ thống Giám sát mạng
    """

    # Thông tin tài khoản Gmail để gửi
    sender_email = "quangloanthanhchien4@gmail.com"
    sender_password = "nvtwvjpwnenkzrhj"

    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = sender_email
        msg["To"] = admin_email

        # Kết nối tới SMTP server
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, [admin_email], msg.as_string())

        return {"message": "Email sent successfully!"}

    except Exception as e:
        return {"error": str(e)}





threshold = 70

# Định nghĩa schema dữ liệu gửi lên
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




# Mô hình yêu cầu đổi mật khẩu
class ChangePasswordRequest(BaseModel):
    admin_id: int
    old_password: str
    new_password: str

# API đổi mật khẩu
@app.post("/change-password")
async def change_password(data: ChangePasswordRequest):
    try:
        if not data.new_password.strip():
            raise HTTPException(status_code=400, detail="Mật khẩu mới không được để trống")
        if ' ' in data.new_password:
            raise HTTPException(status_code=400, detail="Mật khẩu mới không được chứa khoảng trắng")
        with sqlite3.connect("network_monitoring.db") as conn:
            cursor = conn.cursor()

            # Kiểm tra xem admin có tồn tại không và mật khẩu cũ có đúng không
            cursor.execute("""
                SELECT * FROM Admin WHERE id = ? AND password = ?
            """, (data.admin_id, data.old_password))

            user = cursor.fetchone()

            if user is None:
                raise HTTPException(status_code=400, detail="Mật khẩu cũ không đúng hoặc admin không tồn tại")

            # Cập nhật mật khẩu mới
            cursor.execute("""
                UPDATE Admin SET password = ? WHERE id = ?
            """, (data.new_password, data.admin_id))

            conn.commit()

        return {"status": "success", "message": "Mật khẩu đã được thay đổi thành công"}

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

            # Kiểm tra xem admin có tồn tại không
            cursor.execute("SELECT * FROM Admin WHERE id = ?", (data.admin_id,))
            user = cursor.fetchone()

            if user is None:
                raise HTTPException(status_code=404, detail="Admin không tồn tại")

            # Cập nhật tên mới
            cursor.execute("UPDATE Admin SET username = ? WHERE id = ?", (data.new_name, data.admin_id))
            conn.commit()

        return {"status": "success", "message": "Tên đã được thay đổi thành công"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lỗi khi đổi tên: {str(e)}")
    

class ChangeEmailRequest(BaseModel):
    admin_id: int
    new_email: EmailStr  # Kiểm tra hợp lệ định dạng email tự động

@app.post("/change-email")
async def change_email(data: ChangeEmailRequest):
    try:
        with sqlite3.connect("network_monitoring.db") as conn:
            cursor = conn.cursor()

            # Kiểm tra admin có tồn tại không
            cursor.execute("SELECT * FROM Admin WHERE id = ?", (data.admin_id,))
            user = cursor.fetchone()

            if user is None:
                raise HTTPException(status_code=404, detail="Admin không tồn tại")

            # Cập nhật email mới
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
            # Kết nối cơ sở dữ liệu bên ngoài vòng lặp để tránh mở kết nối liên tục
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

                # Gửi dữ liệu mới
                await websocket.send_json(admins)

            # Đợi 5 giây trước khi gửi dữ liệu lại
            await asyncio.sleep(1)

    except WebSocketDisconnect:
        print("⚠️ Client đã ngắt kết nối WebSocket.")
    except Exception as e:
        print(f"❌ Lỗi khi xử lý WebSocket: {e}")


class LoginRequest(BaseModel):
    username: str
    password: str

# API đăng nhập
@app.post("/login")
def login(data: LoginRequest):
    conn = sqlite3.connect("network_monitoring.db")
    cursor = conn.cursor()

    # Kiểm tra username và password trong bảng Admin
    cursor.execute("""
        SELECT * FROM Admin WHERE username = ? AND password = ?
    """, (data.username, data.password))
    
    user = cursor.fetchone()
    conn.close()

    if user:
        return {"status": "success", "message": "Đăng nhập thành công"}
    else:
        raise HTTPException(status_code=401, detail="Sai tài khoản hoặc mật khẩu")
    


@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await websocket.accept()
    last_count = -1  # Khởi tạo số lượng bản ghi ban đầu

    try:
        while True:
            with sqlite3.connect("network_monitoring.db") as conn:
                cursor = conn.cursor()

                # Lấy số lượng bản ghi hiện tại
                cursor.execute("SELECT COUNT(*) FROM Alerts")
                current_count = cursor.fetchone()[0]

                if current_count != last_count:
                    # Nếu có sự thay đổi, lấy dữ liệu mới
                    cursor.execute("SELECT * FROM Alerts ORDER BY timestamp DESC")
                    rows = cursor.fetchall()

                    alerts = []
                    for row in rows:
                        traffic_log_id = row[1]
                        admin_id = row[2]

                        bandwidth_kbps = None
                        packet_count = None
                        source_ip = None

                        if traffic_log_id:
                            cursor.execute(
                                "SELECT source_ip, bandwidth_kbps, packet_count FROM TrafficLogs WHERE id = ?",
                                (traffic_log_id,)
                            )
                            traffic_data = cursor.fetchone()
                            if traffic_data:
                                source_ip, bandwidth_kbps, packet_count = traffic_data

                        # 📌 Lấy thêm thông tin admin
                        admin_name = None
                        admin_email = None
                        if admin_id:
                            cursor.execute(
                                "SELECT username, email FROM Admin WHERE id = ?",
                                (admin_id,)
                            )
                            admin_data = cursor.fetchone()
                            if admin_data:
                                admin_name, admin_email = admin_data

                        alert = {
                            "id": row[0],
                            "attack_log_id": row[1],
                            "admin_id": row[2],
                            "timestamp": row[3],
                            "alert_message": row[4],
                            "alert_type": row[5],
                            "level": row[6],
                            "source_ip": source_ip,
                            "bandwidth_kbps": bandwidth_kbps,
                            "packet_count": packet_count,
                            "admin_name": admin_name,
                            "admin_email": admin_email
                        }
                        alerts.append(alert)

                    # Gửi dữ liệu mới đến client
                    await websocket.send_json(alerts)

                    # Cập nhật số lượng bản ghi
                    last_count = current_count

            await asyncio.sleep(3)  # Tùy chỉnh thời gian kiểm tra lại

    except WebSocketDisconnect:
        print("🔌 WebSocket client disconnected.")
    except Exception as e:
        print(f"❌ Lỗi WebSocket Alerts: {e}")

"""
@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await websocket.accept()
    last_count = -1  # khởi tạo số lượng bản ghi ban đầu

    try:
        while True:
            with sqlite3.connect("network_monitoring.db") as conn:
                cursor = conn.cursor()

                # Lấy số lượng bản ghi hiện tại
                cursor.execute("SELECT COUNT(*) FROM Alerts")
                current_count = cursor.fetchone()[0]

                if current_count != last_count:
                    # Nếu có sự thay đổi, lấy dữ liệu mới
                    cursor.execute("SELECT * FROM Alerts ORDER BY timestamp DESC")
                    rows = cursor.fetchall()

                    alerts = []
                    for row in rows:
                        traffic_log_id = row[1]

                        bandwidth_kbps = None
                        packet_count = None
                        source_ip = None

                        if traffic_log_id:
                            cursor.execute(
                                "SELECT source_ip, bandwidth_kbps, packet_count FROM TrafficLogs WHERE id = ?",
                                (traffic_log_id,)
                            )
                            traffic_data = cursor.fetchone()
                            if traffic_data:
                                source_ip, bandwidth_kbps, packet_count = traffic_data

                        alert = {
                            "id": row[0],
                            "attack_log_id": row[1],
                            "admin_id": row[2],
                            "timestamp": row[3],
                            "alert_message": row[4],
                            "alert_type": row[5],
                            "level": row[6],
                            "source_ip": source_ip,
                            "bandwidth_kbps": bandwidth_kbps,
                            "packet_count": packet_count
                        }
                        alerts.append(alert)

                    # Gửi dữ liệu mới đến client
                    await websocket.send_json(alerts)

                    # Cập nhật số lượng bản ghi
                    last_count = current_count

            await asyncio.sleep(3)  # Tùy chỉnh thời gian kiểm tra lại

    except WebSocketDisconnect:
        print("🔌 WebSocket client disconnected.")
    except Exception as e:
        print(f"❌ Lỗi WebSocket Alerts: {e}")
"""

@app.websocket("/ws/reports")
async def websocket_reports(websocket: WebSocket):
    await websocket.accept()
    last_count = -1  # ban đầu chưa có bản ghi nào

    try:
        while True:
            conn = sqlite3.connect("network_monitoring.db")
            cursor = conn.cursor()

            # Lấy số lượng bản ghi hiện tại
            cursor.execute("SELECT COUNT(*) FROM AttackLogs")
            current_count = cursor.fetchone()[0]

            if current_count != last_count:
                # Nếu số lượng thay đổi, truy vấn toàn bộ dữ liệu
                cursor.execute("SELECT * FROM AttackLogs ORDER BY timestamp DESC")
                rows = cursor.fetchall()

                reports = []
                for row in rows:
                    traffic_log_id = row[6]
                    cursor.execute("SELECT bandwidth_kbps FROM TrafficLogs WHERE id = ?", (traffic_log_id,))
                    bandwidth_result = cursor.fetchone()
                    bandwidth_kbps = bandwidth_result[0] if bandwidth_result else None

                    report = {
                        "id": row[0],
                        "timestamp": row[1],
                        "source_ip": row[2],
                        "packet_count": row[3],
                        "bandwidth_kbps": bandwidth_kbps,
                        "attack_type": row[4],
                        "level": row[5],
                        "traffic_log_id": traffic_log_id
                    }
                    reports.append(report)

                # Gửi dữ liệu mới
                await websocket.send_json(reports)

                # Cập nhật số lượng bản ghi đã xử lý
                last_count = current_count

            conn.close()
            await asyncio.sleep(5)

    except WebSocketDisconnect:
        print("⚠️ Client đã ngắt kết nối WebSocket.")
    except Exception as e:
        print(f"❌ Lỗi khi xử lý WebSocket: {e}")

@app.delete("/api/alerts/{alert_id}")
async def delete_alert(alert_id: int):
    conn = sqlite3.connect("network_monitoring.db")
    cursor = conn.cursor()

    # Kiểm tra alert tồn tại
    cursor.execute("SELECT * FROM Alerts WHERE id = ?", (alert_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Alert not found")

    # Xoá
    cursor.execute("DELETE FROM Alerts WHERE id = ?", (alert_id,))
    conn.commit()
    conn.close()
    return {"message": "Alert deleted successfully"}

"""@app.websocket("/ws/reports")
async def websocket_reports(websocket: WebSocket):
    await websocket.accept()

    try:
        while True:
            # Kết nối đến database
            conn = sqlite3.connect("network_monitoring.db")
            cursor = conn.cursor()

            # Lấy dữ liệu từ bảng AttackLogs
            cursor.execute("SELECT * FROM AttackLogs ORDER BY timestamp DESC")
            rows = cursor.fetchall()

            reports = []
            for row in rows:
                traffic_log_id = row[6]  # traffic_log_id từ AttackLogs
                
                # Truy vấn bảng TrafficLogs để lấy bandwidth_kbps
                cursor.execute("SELECT bandwidth_kbps FROM TrafficLogs WHERE id = ?", (traffic_log_id,))
                bandwidth_result = cursor.fetchone()
                bandwidth_kbps = bandwidth_result[0] if bandwidth_result else None
                
                report = {
                    "id": row[0],
                    "timestamp": row[1],
                    "source_ip": row[2],
                    "packet_count": row[3],
                    "bandwidth_kbps": bandwidth_kbps,
                    "attack_type": row[4],
                    "level": row[5],
                    "traffic_log_id": traffic_log_id
                }
                reports.append(report)

            conn.close()

            # Gửi danh sách báo cáo về client
            await websocket.send_json(reports)

            # Delay 5 giây trước lần gửi tiếp theo
            await asyncio.sleep(8)

    except WebSocketDisconnect:
        print("⚠️ Client đã ngắt kết nối WebSocket.")
    except Exception as e:
        print(f"❌ Lỗi khi xử lý WebSocket: {e}")
"""


@app.websocket("/ws/traffic")
async def websocket_traffic(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    print(f"Client connected: {websocket.client}")
    try:
        while True:
            data = await websocket.receive_json()

            # In dữ liệu nhận được (dạng dict)
            #print(f"Received from sender: {data}")

            # Lưu vào database
            conn = sqlite3.connect("network_monitoring.db")
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO TrafficLogs (timestamp, source_ip, destination_ip, packet_count, bandwidth_kbps)
                VALUES (?, ?, ?, ?, ?)
            """, (
                data.get("timestamp"),
                data.get("source_ip"),
                data.get("destination_ip"),
                data.get("packet_count"),
                data.get("bandwidth_kbps")
            ))
            traffic_log_id = cursor.lastrowid  # Lấy ID sau khi chèn

            # Nếu bandwidth > 40 thì ghi thêm vào AttackLogs
            bandwidth = data.get("bandwidth_kbps", 0)

            level = None
            if bandwidth > 75:
                level = "High"
            elif bandwidth > 73:
                level = "Medium"
            elif bandwidth > threshold:
                level = "Low"

            if level:   
                cursor.execute("""
                INSERT INTO AttackLogs (
                    timestamp, source_ip, packet_count,
                    attack_type, level, traffic_log_id
                )
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                data.get("timestamp"),
                data.get("source_ip"),
                data.get("packet_count"),
                "DDoS",
                level,
                traffic_log_id
                ))

            if level:   
                attack_timestamp = data.get("timestamp")
                attack_type = "DDoS"  # hoặc lấy từ data nếu có

                # Truy vấn để lấy attack_log_id
                cursor.execute("""
                SELECT id FROM AttackLogs
                WHERE timestamp = ? AND attack_type = ?
                ORDER BY id DESC LIMIT 1
                """, (attack_timestamp, attack_type))

                result = cursor.fetchone()
                if result:
                    attack_log_id = result[0]
                cursor.execute("""
                INSERT INTO Reports (
                    timestamp, attack_log_id, admin_id,
                    trafic_data, attack_type, level
                )
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                data.get("timestamp"),
                attack_log_id,
                "1",
                "Luu luong tang bat thuong",
                "DDoS",
                level,
                ))

            if level:
                cursor.execute("""
                INSERT INTO Alerts (
                    attack_log_id, admin_id, timestamp, alert_message,
                    alert_type, level
                )
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                traffic_log_id,
                "1",
                data.get("timestamp"),
                "Luu luong tang bat thuong",
                "DDoS",
                level
                ))
            
            conn.commit()
            conn.close()

            # Gửi dữ liệu này cho tất cả client
            disconnected_clients = []
            for client in active_connections:
                try:
                    await client.send_json(data)
                except WebSocketDisconnect:
                    disconnected_clients.append(client)
                except Exception as e:
                    print(f"Error sending to client: {e}")
                    disconnected_clients.append(client)

            # Loại bỏ client đã ngắt kết nối
            for dc in disconnected_clients:
                active_connections.remove(dc)

    except WebSocketDisconnect:
        print("WebSocket disconnected.")
        active_connections.remove(websocket)



# ✅ Mount thư mục static
app.mount("/static", StaticFiles(directory="static"), name="static")

# ✅ Truy cập "/" sẽ hiện main.html
@app.get("/", include_in_schema=False)
async def root():
    return FileResponse("static/login.html", media_type="text/html")

# ✅ Route trả HTML tĩnh
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

# Cho phép CORS cho tất cả các domain
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
    bandwidth_kbps: float

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
            bandwidth_kbps REAL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS AttackLogs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            packet_count INTEGER,
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
        timestamp DATETIME,
        alert_message VARCHAR(255),
        alert_type VARCHAR(100),
        level VARCHAR(50),
        FOREIGN KEY (attack_log_id) REFERENCES AttackLogs(id)
    )""")
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME,
        attack_log_id INTEGER,
        admin_id INTEGER,
        trafic_data TEXT,
        attack_type VARCHAR(100),
        level VARCHAR(50),
        FOREIGN KEY (attack_log_id) REFERENCES AttackLogs(id)
    )""")
    conn.commit()
    conn.close()

create_tables()

from fastapi import WebSocket, WebSocketDisconnect
import sqlite3
import asyncio

from fastapi import WebSocket, WebSocketDisconnect
import sqlite3
import asyncio
from fastapi import HTTPException
