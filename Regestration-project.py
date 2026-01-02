import hashlib
import json
import os
import re
import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog
import csv

# ---------------- User System Classes ----------------

class User:
    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password_hash = self.hash_password(password)

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()


class RegistrationSystem:
    def __init__(self, filename="users.json"):
        self.filename = filename
        self.users = self.load_users()
        self.logged_in_user = None

    def load_users(self):
        if os.path.exists(self.filename):
            with open(self.filename, 'r') as f:
                return json.load(f)
        return {}

    def save_users(self):
        with open(self.filename, 'w') as f:
            json.dump(self.users, f, indent=4)

    def is_valid_email(self, email):
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(pattern, email) is not None

    def is_strong_password(self, password):
        return (len(password) >= 8 and
                re.search(r'[A-Z]', password) and
                re.search(r'[a-z]', password) and
                re.search(r'\d', password))

    def register(self, username, email, password):
        if username in self.users:
            return False, "Username already exists!"
        if not self.is_valid_email(email):
            return False, "Invalid email format!"
        if not self.is_strong_password(password):
            return False, "Password must be 8+ chars with uppercase, lowercase, and a digit"

        new_user = User(username, email, password)
        self.users[username] = {
            "email": email,
            "password_hash": new_user.password_hash
        }
        self.save_users()
        return True, f"User '{username}' registered successfully."

    def login(self, username, password):
        if username not in self.users:
            return False, "Username not found!"

        hashed_input = hashlib.sha256(password.encode()).hexdigest()
        if hashed_input == self.users[username]["password_hash"]:
            self.logged_in_user = username
            return True, f"Login successful. Welcome, {username}!"
        return False, "Incorrect password!"

    def logout(self):
        if self.logged_in_user:
            user = self.logged_in_user
            self.logged_in_user = None
            return f"{user} logged out successfully."
        return "No user is currently logged in."

    def change_password(self, old_password, new_password):
        if not self.logged_in_user:
            return False, "You must login first."

        hashed_old = hashlib.sha256(old_password.encode()).hexdigest()
        if hashed_old != self.users[self.logged_in_user]["password_hash"]:
            return False, "Old password incorrect!"

        if not self.is_strong_password(new_password):
            return False, "New password not strong enough!"

        self.users[self.logged_in_user]["password_hash"] = hashlib.sha256(new_password.encode()).hexdigest()
        self.save_users()
        return True, "Password changed successfully."

    def delete_user(self, username):
        if username in self.users:
            del self.users[username]
            self.save_users()
            if self.logged_in_user == username:
                self.logged_in_user = None
            return True, f"User '{username}' deleted successfully."
        return False, "Username not found!"

    def show_users(self):
        if not self.users:
            return "No users registered yet."
        result = "Registered Users:\n"
        for username, info in self.users.items():
            result += f"Username: {username}, Email: {info['email']}\n"
        return result

    def export_to_csv(self, filename="users.csv"):
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['username', 'email', 'password_hash']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for username, info in self.users.items():
                writer.writerow({'username': username, 'email': info['email'], 'password_hash': info['password_hash']})
        return f"Users exported to {filename} successfully."


# ---------------- GUI Forms ----------------

class RegistrationGUI:
    def __init__(self, root, system):
        self.system = system
        self.root = root
        root.title("Advanced Registration System")
        root.geometry("400x450")

        tk.Label(root, text="Advanced Registration System", font=("Arial", 16)).pack(pady=10)
        tk.Button(root, text="Register", width=30, command=self.register_window).pack(pady=5)
        tk.Button(root, text="Login", width=30, command=self.login_window).pack(pady=5)
        tk.Button(root, text="Logout", width=30, command=self.logout_user).pack(pady=5)
        tk.Button(root, text="Change Password", width=30, command=self.change_password_window).pack(pady=5)
        tk.Button(root, text="Delete User", width=30, command=self.delete_user_window).pack(pady=5)
        tk.Button(root, text="Show Users", width=30, command=self.show_users).pack(pady=5)
        tk.Button(root, text="Export to CSV", width=30, command=self.export_csv).pack(pady=5)
        tk.Button(root, text="Exit", width=30, command=root.quit).pack(pady=5)

    # ---------------- Register ----------------

    def register_window(self):
        win = tk.Toplevel(self.root)
        win.title("Register")
        win.geometry("350x250")

        tk.Label(win, text="Username").pack()
        username_entry = tk.Entry(win)
        username_entry.pack()
        username_error = tk.Label(win, text="", fg="red")
        username_error.pack()

        tk.Label(win, text="Email").pack()
        email_entry = tk.Entry(win)
        email_entry.pack()
        email_error = tk.Label(win, text="", fg="red")
        email_error.pack()

        tk.Label(win, text="Password").pack()
        password_entry = tk.Entry(win, show="*")
        password_entry.pack()
        password_error = tk.Label(win, text="", fg="red")
        password_error.pack()

        def submit():
            username_error.config(text="")
            email_error.config(text="")
            password_error.config(text="")

            username = username_entry.get()
            email = email_entry.get()
            password = password_entry.get()

            success, message = self.system.register(username, email, password)
            if success:
                messagebox.showinfo("Success", message)
                win.destroy()
            else:
                if "Username" in message:
                    username_error.config(text=message)
                elif "email" in message:
                    email_error.config(text=message)
                elif "Password" in message:
                    password_error.config(text=message)

        tk.Button(win, text="Register", command=submit).pack(pady=10)

    # ---------------- Login ----------------

    def login_window(self):
        win = tk.Toplevel(self.root)
        win.title("Login")
        win.geometry("300x200")

        tk.Label(win, text="Username").pack()
        username_entry = tk.Entry(win)
        username_entry.pack()
        username_error = tk.Label(win, text="", fg="red")
        username_error.pack()

        tk.Label(win, text="Password").pack()
        password_entry = tk.Entry(win, show="*")
        password_entry.pack()
        password_error = tk.Label(win, text="", fg="red")
        password_error.pack()

        def submit():
            username_error.config(text="")
            password_error.config(text="")

            username = username_entry.get()
            password = password_entry.get()

            success, message = self.system.login(username, password)
            if success:
                messagebox.showinfo("Login", message)
                win.destroy()
            else:
                if "Username" in message:
                    username_error.config(text=message)
                else:
                    password_error.config(text=message)

        tk.Button(win, text="Login", command=submit).pack(pady=10)

    # ---------------- Logout ----------------

    def logout_user(self):
        messagebox.showinfo("Logout", self.system.logout())

    # ---------------- Change Password ----------------

    def change_password_window(self):
        if not self.system.logged_in_user:
            messagebox.showerror("Error", "You must login first.")
            return

        win = tk.Toplevel(self.root)
        win.title("Change Password")
        win.geometry("300x200")

        tk.Label(win, text="Old Password").pack()
        old_entry = tk.Entry(win, show="*")
        old_entry.pack()
        old_error = tk.Label(win, text="", fg="red")
        old_error.pack()

        tk.Label(win, text="New Password").pack()
        new_entry = tk.Entry(win, show="*")
        new_entry.pack()
        new_error = tk.Label(win, text="", fg="red")
        new_error.pack()

        def submit():
            old_error.config(text="")
            new_error.config(text="")

            old_pass = old_entry.get()
            new_pass = new_entry.get()

            success, message = self.system.change_password(old_pass, new_pass)
            if success:
                messagebox.showinfo("Success", message)
                win.destroy()
            else:
                if "Old" in message:
                    old_error.config(text=message)
                else:
                    new_error.config(text=message)

        tk.Button(win, text="Change Password", command=submit).pack(pady=10)

    # ---------------- Delete User ----------------

    def delete_user_window(self):
        win = tk.Toplevel(self.root)
        win.title("Delete User")
        win.geometry("300x150")

        tk.Label(win, text="Username").pack()
        entry = tk.Entry(win)
        entry.pack()
        error_label = tk.Label(win, text="", fg="red")
        error_label.pack()

        def submit():
            error_label.config(text="")
            username = entry.get()

            success, message = self.system.delete_user(username)
            if success:
                messagebox.showinfo("Delete User", message)
                win.destroy()
            else:
                error_label.config(text=message)

        tk.Button(win, text="Delete User", command=submit).pack(pady=10)

    # ---------------- Show Users ----------------

    def show_users(self):
        users = self.system.show_users()
        messagebox.showinfo("Users", users)

    # ---------------- Export CSV ----------------

    def export_csv(self):
        filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if filename:
            messagebox.showinfo("Export CSV", self.system.export_to_csv(filename))


# ---------------- Run GUI ----------------

if __name__ == "__main__":
    root = tk.Tk()
    system = RegistrationSystem()
    gui = RegistrationGUI(root, system)
    root.mainloop()
