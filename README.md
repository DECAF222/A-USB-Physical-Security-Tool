# 🔐 A-USB Physical Security Tool

This is a Python-based GUI application designed to enhance the physical security of your system's USB ports. The app allows only authenticated users to enable USB ports by verifying an OTP sent via email, helping prevent unauthorized access via USB devices.

## 🚀 Features

- 🧰 Simple **Tkinter GUI**
- 📩 **OTP authentication** via email
- 🔒 **Block or enable USB ports** using Windows Registry
- 📦 One-click executable using **PyInstaller**
- 🖼 HTML support to show additional app info

## 📁 Files

| File Name          | Description                               |
|--------------------|-------------------------------------------|
| `app.py`           | Main GUI application                      |
| `project_info.html`| Info page opened via a GUI button         |
| `image.png`        | Used in the GUI                           |

## 🛠 How It Works

1. User opens the GUI (`app.py`).
2. Clicks "Request OTP" – app sends a **One-Time Password** to the user's email.
3. After entering the correct OTP, USB ports are enabled.
4. If the app is exited or incorrect OTP is entered, ports stay disabled.

## 🧪 Requirements

- Python 3.x
- `smtplib` (standard)
- `tkinter` (standard)
- Admin privileges to modify USB registry settings

## 💻 Running the App

### Run directly:
```bash
python app.py

⚙️ Create Executable:
Use PyInstaller:

bash
Copy
Edit
pyinstaller --onefile --add-data "project_info.html;." --add-data "image.png;." app.py
Make sure to use --add-data syntax based on your OS
(use : instead of ; on macOS/Linux).

🔐 Registry Changes
The app modifies this key to disable USB ports:

sql
Copy
Edit
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\USBSTOR
Set Start = 4 → Disable USB

Set Start = 3 → Enable USB

⚠️ Admin privileges required

📧 Email Configuration
You'll need to:

Replace sender_email, password, and receiver_email inside app.py with your own credentials.

Or, use environment variables for better security.

📜 License
This project is for educational and security research purposes only.
Use responsibly.

Made with ❤️ by Nitish

yaml
Copy
Edit

---

Let me know if you want to:
- Add a project banner
- Include a `.gitignore`
- Generate a requirements.txt

I can help you enhance it further!
