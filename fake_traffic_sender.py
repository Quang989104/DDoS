from scapy.all import *
import random
import time
import json
import websocket

# Địa chỉ WebSocket của backend (chỉnh lại nếu khác)
WS_SERVER = "ws://127.0.0.1:8000/ws/traffic"  # Hoặc thay localhost bằng IP server

def generate_traffic():
    while True:
        # Sinh dữ liệu giả
        source_ip = f"192.168.1.{random.randint(2, 254)}"
        packet_count = random.randint(5, 50)
        bandwidth_kb = random.uniform(20.0, 80.0)

        data = {
            "source_ip": source_ip,
            "packet_count": packet_count,
            "destination_ip": "8.8.8.8",
            "bandwidth_kbps": round(bandwidth_kb, 2),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        # Gửi qua WebSocket
        ws.send(json.dumps(data))
        print(f"Gửi dữ liệu: {data}")

        time.sleep(1)  # mỗi giây gửi 1 lần

# Khởi tạo kết nối WebSocket
ws = websocket.WebSocket()
ws.connect(WS_SERVER)
generate_traffic()
