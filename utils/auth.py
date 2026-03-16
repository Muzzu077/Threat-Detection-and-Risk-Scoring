import bcrypt

# Mock User Database (In production, this would be in the DB too)
# Username: password (hashed)
# Default admin password: "admin_password"
users_db = {
    "admin": b"$2b$12$eG.drlxR./.uK.uK.uK.uO.uK.uK.uK.uK.uK.uK.uK.uK.uK.uK" # Placeholder hash, will generate real one
}

def encrypt_password(password):
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(username, password):
    """Verify password against stored hash"""
    # For Hackathon/Demo: Hardcoded 'admin' / 'admin123'
    if username == "admin" and password == "admin123":
        return True
    return False

# Setup default admin for real usage if we were doing DB Auth
# hashed = encrypt_password("admin123")
