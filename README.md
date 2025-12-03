# Password Manager

A password manager made in Python with a Tkinter GUI, credential encryption using Fernet, password generation, search, backup import/export, and logging. Made by [@flaviandev](https://www.github.com/flaviandev), 2025

## How to use

### Before opening/building

#### Step 1: Add encryption "salt"

Inside main.py at line 31, change the placeholder salt with a secure random salt. The salt can be any string, just make sure you remember it.

#### Step 2: Make executable

After replacing the placeholder salt, you can build the executable:

```
  pyinstaller main.py --onedir --noconsole
```

### Using the app

#### Step 1: Login

The app uses a master password login, on first launch, you can login with any password. After logging in and adding credentials, an encrypted storage file will be created automatically. Afterwards, you can only use the same password used on the first login to decrypt the storage file.

#### Step 2: Managing credentials

After logging in using the master password, the main window will be shown. Here you can search, add, edit or delete credentials.

Each credential entry contains:
* Service Name
* Username
* Password
* Tags
* Notes

You can generate a password inside of the app where you determine the length and what characters are used.

#### Step 3: Backup

You can import / export encrypted backup for safe keeping, in the main window at the top left, press on the file button.