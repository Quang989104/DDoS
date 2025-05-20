import json
import threading
import time
from scapy.all import sniff, IP
from collections import defaultdict
from websocket import WebSocketApp
from datetime import datetime

WS_SERVER = "ws://127.0.0.1:8000/ws/traffic"
ws_app = None
is_open = False 

def capture_traffic(duration=1):
    stats = defaultdict(lambda: [0, 0])
    def handler(pkt):
        if IP in pkt:
            key = (pkt[IP].src, pkt[IP].dst)
            stats[key][0] += 1
            stats[key][1] += len(pkt)
    sniff(timeout=duration, prn=handler, store=False)
    return stats

def analyze_attack_type(stats):
    dst_map = defaultdict(lambda: {"source_ips": set(), "packet_count": 0})
    for (src_ip, dst_ip), (count, _) in stats.items():
        dst_map[dst_ip]["source_ips"].add(src_ip)
        dst_map[dst_ip]["packet_count"] += count

    result = {}
    for dst_ip, info in dst_map.items():
        attack_type = "DoS" if len(info["source_ips"]) == 1 else "DDoS"
        result[dst_ip] = {
            "source_ips": list(info["source_ips"]),
            "packet_count": info["packet_count"],
            "attack_type": attack_type
        }
    return result

def send_traffic_data(ws, stats, duration=1):
    global is_open
    if not is_open:
        print(" Kết nối chưa mở, không gửi dữ liệu")
        return

    attack_info = analyze_attack_type(stats)
    

    for dst_ip, info in attack_info.items():
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        total_bytes = sum(
            stats.get((src_ip, dst_ip), [0, 0])[1] for src_ip in info["source_ips"]
        )
        bandwidth_kbps = (total_bytes * 8) / duration / 1000
        data = {
            "destination_ip": dst_ip,
            "source_ip": info["source_ips"],
            "packet_count": info["packet_count"],
            "bandwidth_kbps": round(bandwidth_kbps, 2),
            "attack_type": info["attack_type"],
            "timestamp": timestamp
        }
        try:
            ws.send(json.dumps(data))
            print(f" Gửi dữ liệu: {json.dumps(data, indent=2)}")
        except Exception as e:
            print(f" Lỗi gửi dữ liệu: {e}")
def traffic_loop(ws):
    while True:
        start_time = time.time()
        stats = capture_traffic(duration=1)
        send_traffic_data(ws, stats, duration=1)
        elapsed = time.time() - start_time
        sleep_time = max(0, 1.0 - elapsed)
        time.sleep(sleep_time)


def on_open(ws):
    global is_open
    is_open = True
    print(" WebSocket đã mở kết nối")
    threading.Thread(target=traffic_loop, args=(ws,), daemon=True).start()

def on_close(ws, close_status_code, close_msg):
    global is_open
    is_open = False
    print(f" WebSocket đóng kết nối: {close_status_code} - {close_msg}")

def on_error(ws, error):
    global is_open
    is_open = False
    print(f" WebSocket lỗi: {error}")

def on_pong(ws, message):
    print(" Nhận pong từ server")

def keep_alive(ws):
    global is_open
    while is_open:
        try:
            ws.send("ping")
        except:
            break
        time.sleep(10) 

def start_ws():
    global ws_app
    while True:
        try:
            ws_app = WebSocketApp(
                WS_SERVER,
                on_open=on_open,
                on_close=on_close,
                on_error=on_error,
                on_pong=on_pong
            )
            ping_thread = threading.Thread(target=keep_alive, args=(ws_app,), daemon=True)
            ping_thread.start()
            ws_app.run_forever(ping_interval=20, ping_timeout=5)
        except Exception as e:
            print(f" Lỗi WebSocketApp: {e} → Thử lại sau 3 giây")
            time.sleep(3)

if __name__ == "__main__":
    start_ws()
