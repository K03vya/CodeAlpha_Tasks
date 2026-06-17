import sqlite3

def login_user_vulnerable(username, password):
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    
    cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
    cursor.execute("INSERT INTO users VALUES ('admin', 'SuperSecretPass123')")
    
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"Executing Query: {query}")
    
    try:
        cursor.execute(query)
        result = cursor.fetchall()
        conn.close()
        return result
    except Exception as e:
        print(f"Error: {e}")
        conn.close()
        return None

def login_user_secure(username, password):
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    
    cursor.execute("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)")
    cursor.execute("INSERT INTO users VALUES ('admin', 'SuperSecretPass123')")
    
    query = "SELECT username, password FROM users WHERE username = ? AND password = ?"
    print(f"Executing Secure Query: {query}")
    
    try:
        cursor.execute(query, (username, password))
        result = cursor.fetchall()
        conn.close()
        return result
    except Exception as e:
        print(f"Error: {e}")
        conn.close()
        return None

if __name__ == "__main__":
    print("--- Code Review Lab ---")
    
    payload = "admin' OR '1'='1"
    wrong_pass = "xyz"
    
    print(f"\nTesting Vulnerable System with input: {payload}")
    res1 = login_user_vulnerable(payload, wrong_pass)
    if res1:
        print(f"Bypass Successful! Logged in as: {res1}")
        
    print(f"\nTesting Secure System with the same input...")
    res2 = login_user_secure(payload, wrong_pass)
    if not res2:
        print("Attack Blocked! Access Denied.")