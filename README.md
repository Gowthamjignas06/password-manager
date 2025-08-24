# 🔐 Password Manager (Bash + GPG)

A lightweight **command-line password manager** written in **Bash**, with **GPG-based symmetric encryption**.  
This project demonstrates secure credential storage, user management, and password generation without external dependencies beyond standard Unix tools.

---

## 🚀 Features
- User **registration & login** with encrypted storage  
- Add, view, and delete credentials  
- Automatic strong **password generation**  
- Master index for multiple users  
- Uses `gpg` with strong symmetric encryption  
- Built-in lightweight **test mode** (`--test`)  

---

## 🛠️ Requirements
- `bash` (>= 4.x)  
- `gpg`  
- Standard Unix tools: `grep`, `sed`, `awk`, `column`, `head`, `tr`, `mktemp`, `mkdir`, `rm`, `mv`

---

## 📦 Installation
Clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/password-manager-bash.git
cd password-manager-bash
chmod +x password_manager.sh
