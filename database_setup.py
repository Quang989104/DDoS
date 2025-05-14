import sqlite3

def create_tables():
    conn = sqlite3.connect("network_monitoring.db")
    conn.execute("PRAGMA foreign_keys = ON")
    cursor = conn.cursor()

    # Bảng Admin
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Admin (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username VARCHAR(100),
        password VARCHAR(255),
        email VARCHAR(255)
    )""")

    # Bảng ghi log lưu lượng mạng
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS TrafficLogs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME,
        source_ip VARCHAR(45),
        destination_ip VARCHAR(45),
        packet_count INTEGER,
        bandwidth_usage DOUBLE
    )""")

    # Bảng ghi log tấn công
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS AttackLogs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME,
        source_ip VARCHAR(45),
        attack_type VARCHAR(100),
        packet_count INTEGER,
        level VARCHAR(100),
        traffic_log_id INTEGER,
        FOREIGN KEY (traffic_log_id) REFERENCES TrafficLogs(id)
    )""")

    # Bảng cảnh báo
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attack_log_id INTEGER,
        admin_id INTEGER,
        timestamp DATETIME,
        alert_message VARCHAR(255),
        alert_type VARCHAR(100),
        level VARCHAR(50),
        FOREIGN KEY (attack_log_id) REFERENCES AttackLogs(id),
        FOREIGN KEY (admin_id) REFERENCES Admin(id)
    )""")

    # Bảng báo cáo
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME,
        attack_log_id INTEGER,
        admin_id INTEGER,
        trafic_data TEXT,
        attack_type VARCHAR(100),
        level VARCHAR(50),
        FOREIGN KEY (attack_log_id) REFERENCES AttackLogs(id),
        FOREIGN KEY (admin_id) REFERENCES Admin(id)
    )""")

    # ✅ Bảng lưu tổng hợp dữ liệu cảnh báo từ giao diện
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS Dataset (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME NOT NULL,
        alert_type VARCHAR(100),
        alert_message TEXT,
        level VARCHAR(50),
        source_ip VARCHAR(45),
        packet_count INTEGER,
        bandwidth_kbps DOUBLE,
        admin_username VARCHAR(100)
    )""")

    conn.commit()
    conn.close()

if __name__ == "__main__":
    create_tables()
