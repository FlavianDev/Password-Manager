# 🔐 Password Manager v2.0

A modern, secure **password manager** built with **Python** and **Tkinter**, featuring session-based authentication, encrypted local storage, unique per-user salts, and a clean service-oriented architecture.

**Made by [@flaviandev](https://github.com/flaviandev) · 2025**

---

## ✨ Features

### 🔒 Security
- Session-based authentication with configurable timeout  
- Unique encryption salt generated once per user  
- Master password confirmation on first setup  
- Encrypted credential storage (Fernet / AES)  
- Automatic session invalidation and clipboard auto-clear  

### 🧼 Data Safety
- Full input validation & sanitization  
- Secure, temporary password reveal (auto-hide)  
- No plaintext passwords stored on disk or logs  

### 🧠 User Experience
- Fast search and filtering  
- Built-in password generator with customizable rules  
- Clean, responsive Tkinter interface  

### 🏗️ Architecture
Service-based, modular design:
- **AuthService** – authentication, key derivation, session handling  
- **StorageService** – encrypted CRUD operations and backups  
- **ValidationService** – input validation and sanitization  
- **ConfigService** & **LoggerService**

---

## 🛠️ Requirements

- **Python 3.8+**
- Dependencies:
  ```bash
  pip install cryptography pyperclip

## ⬇️ Download & Usage

### Download Executable
👉 **[Download the latest executable](https://github.com/flaviandev/Password-Manager/releases/latest)**

### Security Notes
- Master password is **never stored**
- Encryption salt is generated once and stored in plaintext JSON
- Uses industry-standard cryptography
- Session timeout prevents unauthorized access

### License
Open source — free to use, modify, and distribute.
