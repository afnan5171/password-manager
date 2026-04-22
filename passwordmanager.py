import os
import json
import base64
import hashlib
import secrets
import string
import tkinter as tk
from tkinter import messagebox, simpledialog
from cryptography.fernet import Fernet

DATA_FILE = "vault.json"


def derive_key(password: str, salt: bytes) -> bytes:
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        200000,
        dklen=32
    )
    return base64.urlsafe_b64encode(key)


def create_new_vault(master_password: str) -> None:
    salt = os.urandom(16)
    key = derive_key(master_password, salt)

    vault_data = {
        "salt": base64.b64encode(salt).decode(),
        "entries": []
    }

    encrypted_check = Fernet(key).encrypt(b"vault_unlocked").decode()
    vault_data["check"] = encrypted_check

    with open(DATA_FILE, "w") as file:
        json.dump(vault_data, file, indent=4)


def load_vault():
    if not os.path.exists(DATA_FILE):
        return None

    with open(DATA_FILE, "r") as file:
        return json.load(file)


def verify_master_password(master_password: str, vault_data: dict):
    salt = base64.b64decode(vault_data["salt"])
    key = derive_key(master_password, salt)
    fernet = Fernet(key)

    try:
        decrypted_check = fernet.decrypt(vault_data["check"].encode()).decode()
        return decrypted_check == "vault_unlocked", fernet
    except Exception:
        return False, None


class PasswordManagerApp:
    def __init__(self, root, fernet):
        self.root = root
        self.fernet = fernet

        self.root.title("Password Manager")
        self.root.geometry("500x420")
        self.root.resizable(False, False)

        tk.Label(root, text="Website / App", font=("Arial", 12)).pack(pady=(15, 5))
        self.site_entry = tk.Entry(root, width=40, font=("Arial", 12))
        self.site_entry.pack()

        tk.Label(root, text="Username", font=("Arial", 12)).pack(pady=(15, 5))
        self.username_entry = tk.Entry(root, width=40, font=("Arial", 12))
        self.username_entry.pack()

        tk.Label(root, text="Password", font=("Arial", 12)).pack(pady=(15, 5))
        self.password_entry = tk.Entry(root, width=40, font=("Arial", 12))
        self.password_entry.pack()

        button_frame = tk.Frame(root)
        button_frame.pack(pady=20)

        tk.Button(
            button_frame,
            text="Generate Password",
            width=18,
            command=self.generate_password
        ).grid(row=0, column=0, padx=8, pady=8)

        tk.Button(
            button_frame,
            text="Save Password",
            width=18,
            command=self.save_password
        ).grid(row=0, column=1, padx=8, pady=8)

        tk.Button(
            button_frame,
            text="Show All",
            width=18,
            command=self.show_all
        ).grid(row=1, column=0, padx=8, pady=8)

        tk.Button(
            button_frame,
            text="Delete Entry",
            width=18,
            command=self.delete_entry
        ).grid(row=1, column=1, padx=8, pady=8)

        tk.Button(root, text="Exit", width=20, command=root.quit).pack(pady=10)

    def generate_password(self):
        alphabet = string.ascii_letters + string.digits + string.punctuation
        generated = "".join(secrets.choice(alphabet) for _ in range(16))

        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, generated)

        messagebox.showinfo("Generated", "Secure password generated.")

    def save_password(self):
        site = self.site_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if not site or not username or not password:
            messagebox.showerror("Error", "Please fill in all fields.")
            return

        encrypted_password = self.fernet.encrypt(password.encode()).decode()

        vault_data = load_vault()
        vault_data["entries"].append({
            "site": site,
            "username": username,
            "password": encrypted_password
        })

        with open(DATA_FILE, "w") as file:
            json.dump(vault_data, file, indent=4)

        messagebox.showinfo("Saved", "Password saved successfully.")

        self.site_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

    def show_all(self):
        vault_data = load_vault()
        entries = vault_data.get("entries", [])

        if not entries:
            messagebox.showinfo("No Entries", "No saved passwords found.")
            return

        output = []

        for entry in entries:
            try:
                decrypted_password = self.fernet.decrypt(
                    entry["password"].encode()
                ).decode()
            except Exception:
                decrypted_password = "[Could not decrypt]"

            output.append(
                f"Site: {entry['site']}\n"
                f"Username: {entry['username']}\n"
                f"Password: {decrypted_password}\n"
                f"{'-' * 30}"
            )

        messagebox.showinfo("Saved Passwords", "\n".join(output))

    def delete_entry(self):
        site_to_delete = simpledialog.askstring(
            "Delete",
            "Enter the website/app name to delete:"
        )

        if not site_to_delete:
            return

        vault_data = load_vault()
        entries = vault_data.get("entries", [])

        updated_entries = [
            entry for entry in entries
            if entry["site"].lower() != site_to_delete.lower()
        ]

        if len(updated_entries) == len(entries):
            messagebox.showinfo("Not Found", "No entry found with that name.")
            return

        vault_data["entries"] = updated_entries

        with open(DATA_FILE, "w") as file:
            json.dump(vault_data, file, indent=4)

        messagebox.showinfo("Deleted", f"Entry for '{site_to_delete}' deleted.")


def first_time_setup():
    root = tk.Tk()
    root.withdraw()

    while True:
        master_password = simpledialog.askstring(
            "Setup",
            "Create a master password:",
            show="*"
        )

        if master_password is None:
            return None

        if len(master_password) < 8:
            messagebox.showerror(
                "Weak Password",
                "Master password must be at least 8 characters."
            )
            continue

        confirm_password = simpledialog.askstring(
            "Setup",
            "Confirm master password:",
            show="*"
        )

        if master_password != confirm_password:
            messagebox.showerror("Mismatch", "Passwords do not match.")
            continue

        create_new_vault(master_password)
        messagebox.showinfo("Success", "Vault created successfully.")
        return master_password


def login():
    vault_data = load_vault()

    if vault_data is None:
        master_password = first_time_setup()

        if master_password is None:
            return None

        vault_data = load_vault()
        valid, fernet = verify_master_password(master_password, vault_data)

        if valid:
            return fernet

        return None

    root = tk.Tk()
    root.withdraw()

    for _ in range(3):
        master_password = simpledialog.askstring(
            "Login",
            "Enter master password:",
            show="*"
        )

        if master_password is None:
            return None

        valid, fernet = verify_master_password(master_password, vault_data)

        if valid:
            return fernet

        messagebox.showerror("Access Denied", "Incorrect master password.")

    messagebox.showerror("Locked Out", "Too many failed attempts.")
    return None


def main():
    fernet = login()

    if fernet is None:
        return

    root = tk.Tk()
    PasswordManagerApp(root, fernet)
    root.mainloop()


if __name__ == "__main__":
    main()