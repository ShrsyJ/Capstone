import hashlib

def store_user(db, username, password):
    hashed = hashlib.md5(password.encode()).hexdigest()
    db.insert("users", {"username": username, "password_hash": hashed})
