import streamlit as st
import hashlib
from cryptography.fernet import Fernet

KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory storage
stored_data = {}
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'authorized' not in st.session_state:
    st.session_state.authorized = True

# Hashing Function
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt Function
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt Function
def decrypt_data(encrypted_text, passkey):
    hashed_pass = hash_passkey(passkey)

    for key, val in stored_data.items():
        if key == encrypted_text and val["passkey"] == hashed_pass:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    
    st.session_state.failed_attempts += 1
    return None

# Reauthorization/Login
def reauthorize():
    st.session_state.authorized = False

# UI Title
st.title("🔒 Secure Data Encryption System by Muhammad Tabish Ali")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# Home Page
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("This app allows you to securely store and retrieve encrypted data using a passkey.")

# Store Data Page
elif choice == "Store Data":
    st.subheader("📦 Store Your Data")
    text = st.text_area("Enter data to encrypt:")
    passkey = st.text_input("Enter a passkey:", type="password")

    if st.button("Encrypt & Store"):
        if text and passkey:
            hashed_pass = hash_passkey(passkey)
            encrypted = encrypt_data(text)
            stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed_pass}
            st.success(f"✅ Data encrypted and stored!\n\nEncrypted Text:\n`{encrypted}`")
        else:
            st.warning("⚠️ Please enter both data and a passkey.")

# Retrieve Data Page
elif choice == "Retrieve Data":
    if not st.session_state.authorized:
        st.warning("🔐 You must login again after 3 failed attempts.")
        st.stop()

    st.subheader("🔍 Retrieve Encrypted Data")
    encrypted_input = st.text_area("Enter encrypted data:")
    passkey = st.text_input("Enter passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey:
            result = decrypt_data(encrypted_input, passkey)
            if result:
                st.success(f"✅ Decrypted Data:\n{result}")
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("⛔ Too many failed attempts. Redirecting to login...")
                    reauthorize()
                    st.experimental_rerun()
        else:
            st.warning("⚠️ Enter both fields.")

# Login Page
elif choice == "Login":
    st.subheader("🔑 Re-login to continue")
    master_pass = st.text_input("Enter master password:", type="password")

    if st.button("Login"):
        if master_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.success("✅ Logged in successfully!")
        else:
            st.error("❌ Incorrect master password.")
