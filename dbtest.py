import pymysql

try:
    connection = pymysql.connect(
        host='localhost',
        user='root',
        password='011023',
        database='dictionary',
        port=3301
    )
    print("Database connection successful!")
    connection.close()
except Exception as e:
    print(f"Connection failed: {e}")
