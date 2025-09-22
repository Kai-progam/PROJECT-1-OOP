import mysql.connector
from datetime import datetime
import random

# --- fungsi helper untuk koneksi DB ---
def get_db_connection():
    return mysql.connector.connect(
        host="localhost",      # sesuaikan
        user="root",           # sesuaikan
        password="admin",      # sesuaikan
        database="db_network_scanning_system"  # sesuaikan
    )

# mapping sederhana port → service
PORT_SERVICES = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    21: "FTP",
    53: "DNS"
}

def save_scan_to_db(target_ip, ports, open_ports):
    conn = get_db_connection()
    cursor = conn.cursor()

    # --- 1. Insert ke scans ---
    scan_id = f"S{random.randint(1000,9999)}"  # contoh generate ID acak
    scan_date = datetime.now()

    cursor.execute("""
        INSERT INTO scans (scan_id, target_ip, scan_date, total_ports, open_ports)
        VALUES (%s, %s, %s, %s, %s)
    """, (scan_id, target_ip, scan_date, len(ports), len(open_ports)))
    
    # --- 2. Insert ke scan_results ---
    for p in ports:
        result_id = f"R{random.randint(1000,9999)}"
        status = "open" if p in open_ports else "closed"
        service = PORT_SERVICES.get(p, "Unknown")

        cursor.execute("""
            INSERT INTO scan_results (result_id, scan_id, port_number, port_status, service_name)
            VALUES (%s, %s, %s, %s, %s)
        """, (result_id, scan_id, p, status, service))

        # --- 3. Insert ke vulnerabilities (opsional rule sederhana) ---
        if status == "open" and p == 21:  # contoh: FTP open dianggap vuln
            vuln_id = f"V{random.randint(1000,9999)}"
            cursor.execute("""
                INSERT INTO vulnerabilities (vuln_id, result_id, vulnerability_name, description, severity)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                vuln_id, result_id,
                "Unencrypted FTP",
                "FTP port is open, which may allow unencrypted credential leakage.",
                "high"
            ))

    conn.commit()
    cursor.close()
    conn.close()
    print(f"[+] Scan {scan_id} saved to database!")
