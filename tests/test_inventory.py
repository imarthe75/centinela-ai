import requests

url = "http://localhost:8000/api/inventory"
data1 = {
    "asset_name": "TestServer_A",
    "asset_type": "IP",
    "endpoint": "192.168.1.199",
    "criticality": "HIGH",
    "location_lat": 0.0,
    "location_lon": 0.0
}
data2 = {
    "asset_name": "TestServer_B_SameIP",
    "asset_type": "IP",
    "endpoint": "192.168.1.199",
    "criticality": "HIGH",
    "location_lat": 0.0,
    "location_lon": 0.0
}

if __name__ == "__main__":
    r1 = requests.post(url, json=data1)
    print(f"Request 1: {r1.status_code} - {r1.text}")

    r2 = requests.post(url, json=data2)
    print(f"Request 2: {r2.status_code} - {r2.text}")

    # Check DB
    import psycopg2
    conn = psycopg2.connect(host="casmarts-core-db-primary", database="casmarts_security", user="admin", password="casmarts_secure_db_pwd_2026")
    cur = conn.cursor()
    cur.execute("SELECT asset_name, endpoint FROM infra_inventory WHERE endpoint = '192.168.1.199'")
    rows = cur.fetchall()
    print(f"DB Rows for 199: {rows}")

