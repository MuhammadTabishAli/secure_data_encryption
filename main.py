import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Configuration
DATA_FILE = "encrypted_data.json"
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 300  # 5 minutes in seconds

# Initialize session state
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = 0
if 'current_user' not in st.session_state:
    st.session_state.current_user = None

# Generate or load encryption key
def get_encryption_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
    return open("secret.key", "rb").read()

KEY = get_encryption_key()
cipher = Fernet(KEY)

# Load or initialize data storage
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

stored_data = load_data()

# Enhanced hashing with PBKDF2
def hash_passkey(passkey, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passkey.encode()))
    return key.decode(), salt.hex()

# Encryption/Decryption functions
def encrypt_data(text, passkey):
    salt = os.urandom(16)
    hashed_passkey, salt = hash_passkey(passkey, salt)
    encrypted_text = cipher.encrypt(text.encode()).decode()
    return encrypted_text, hashed_passkey, salt

def decrypt_data(encrypted_text, passkey, salt):
    try:
        hashed_passkey, _ = hash_passkey(passkey, bytes.fromhex(salt))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# Authentication functions
def check_lockout():
    if st.session_state.lockout_time > 0:
        remaining_time = st.session_state.lockout_time - time.time()
        if remaining_time > 0:
            st.error(f"🔒 Account locked. Please try again in {int(remaining_time/60)} minutes.")
            return True
        else:
            st.session_state.lockout_time = 0
            st.session_state.failed_attempts = 0
    return False

def record_failed_attempt():
    st.session_state.failed_attempts += 1
    if st.session_state.failed_attempts >= MAX_ATTEMPTS:
        st.session_state.lockout_time = time.time() + LOCKOUT_TIME
        st.error("🔒 Too many failed attempts! Account locked for 5 minutes.")
        return True
    return False

# Streamlit UI
st.set_page_config(page_title="Secure Data Encryption System", page_icon="🔒")

st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Register", "Store Data", "Retrieve Data", "Login"]
if st.session_state.current_user is None:
    menu.remove("Store Data")
    menu.remove("Retrieve Data")
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("""
    This system allows you to:
    - Securely store sensitive data with encryption
    - Retrieve data only with the correct passkey
    - Protect against brute force attacks with lockout mechanisms
    """)
    
    if st.session_state.current_user:
        st.success(f"Logged in as: {st.session_state.current_user}")
    else:
        st.warning("Please register or login to store/retrieve data")

elif choice == "Register":
    st.subheader("🆕 Create New Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    confirm = st.text_input("Confirm Password", type="password")
    
    if st.button("Register"):
        if password != confirm:
            st.error("Passwords don't match!")
        elif username in stored_data:
            st.error("Username already exists!")
        else:
            hashed_passkey, salt = hash_passkey(password)
            stored_data[username] = {
                "master_passkey": hashed_passkey,
                "master_salt": salt,
                "entries": {}
            }
            save_data(stored_data)
            st.success("Account created successfully! Please login.")

elif choice == "Login":
    st.subheader("🔑 Login to Your Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Login"):
        if username in stored_data:
            user_data = stored_data[username]
            decrypted = decrypt_data("dummy", password, user_data["master_salt"])
            if decrypted is not None:  # Just checking if password is correct
                st.session_state.current_user = username
                st.session_state.failed_attempts = 0
                st.success("Login successful!")
                st.experimental_rerun()
            else:
                st.error("Incorrect password!")
                if record_failed_attempt():
                    st.experimental_rerun()
        else:
            st.error("Username not found!")

elif choice == "Store Data" and st.session_state.current_user:
    st.subheader("📂 Store Data Securely")
    entry_name = st.text_input("Entry Name (e.g., 'Bank Account')")
    user_data = st.text_area("Data to Encrypt")
    passkey = st.text_input("Encryption Passkey", type="password")
    confirm = st.text_input("Confirm Passkey", type="password")
    
    if st.button("Encrypt & Save"):
        if passkey != confirm:
            st.error("Passkeys don't match!")
        elif not entry_name or not user_data:
            st.error("All fields are required!")
        else:
            encrypted_text, hashed_passkey, salt = encrypt_data(user_data, passkey)
            stored_data[st.session_state.current_user]["entries"][entry_name] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey,
                "salt": salt
            }
            save_data(stored_data)
            st.success("✅ Data stored securely!")

elif choice == "Retrieve Data" and st.session_state.current_user:
    if check_lockout():
        st.stop()
        
    st.subheader("🔍 Retrieve Your Data")
    user_entries = stored_data[st.session_state.current_user]["entries"]
    entry_name = st.selectbox("Select Entry", options=list(user_entries.keys()))
    passkey = st.text_input("Enter Passkey", type="password")
    
    if st.button("Decrypt"):
        entry = user_entries[entry_name]
        decrypted_text = decrypt_data(entry["encrypted_text"], passkey, entry["salt"])
        
        if decrypted_text:
            st.session_state.failed_attempts = 0
            st.text_area("Decrypted Data", value=decrypted_text, height=200)
        else:
            st.error("❌ Incorrect passkey!")
            if record_failed_attempt():
                st.experimental_rerun()
            st.warning(f"Attempts remaining: {MAX_ATTEMPTS - st.session_state.failed_attempts}")

# Hide pages if not logged in
if st.session_state.current_user is None and choice in ["Store Data", "Retrieve Data"]:
    st.warning("Please login first to access this page")
    st.experimental_rerun()
