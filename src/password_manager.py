import tkinter as tk
from tkinter import ttk, messagebox as ms, filedialog as fd
import matplotlib
matplotlib.use("TkAgg")
from customtkinter import *
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import sqlite3
import bcrypt
import re
import os
from cryptography.fernet import Fernet
from PIL import Image

from database import initialize_database, get_database_path

class PasswordManager:
    def __init__(self, root):
        self.root = root
        set_appearance_mode("dark")
        set_default_color_theme("blue")
        
        initialize_database()
        
        self.username = None
        self.df_passwords = pd.DataFrame()

        # Encryption key management
        self.key = self._load_or_generate_key()
        self.cipher = Fernet(self.key)

        # Main frames
        self.login_frame = CTkFrame(root, width=300, height=400, corner_radius=10)
        self.main_frame = CTkFrame(root, corner_radius=10)
        
        self._create_login_widgets()
        self._create_main_widgets()
        
        self.show_login_frame()

    def _load_or_generate_key(self):
        """Loads or generates a new encryption key."""
        key_path = "secret.key"
        if os.path.exists(key_path):
            with open(key_path, "rb") as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_path, "wb") as f:
                f.write(key)
            return key

    def show_login_frame(self):
        """Hides the main frame and shows the login frame."""
        self.main_frame.pack_forget()
        self.login_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        self._check_for_users()

    def show_main_frame(self):
        """Hides the login frame and shows the main application frame."""
        self.login_frame.place_forget()
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.fetchall_app()
        self.update_dashboard()

    def _create_login_widgets(self):
        """Creates widgets for the login and registration screen."""
        # Logo
        try:
            logo_image = Image.open("assets/logo.png")
            logo_photo = CTkImage(light_image=logo_image, dark_image=logo_image, size=(100, 100))
            logo_label = CTkLabel(self.login_frame, text="", image=logo_photo)
            logo_label.grid(row=0, column=0, columnspan=2, pady=(20, 10))
        except FileNotFoundError:
            print("Logo file not found: assets/logo.png")

        # --- Login Widgets ---
        self.login_subframe = CTkFrame(self.login_frame, fg_color="transparent")
        self.login_subframe.grid(row=1, column=0, columnspan=2, sticky="nsew")

        self.username_entry = CTkEntry(self.login_subframe, placeholder_text="Username", width=250)
        self.username_entry.pack(pady=10, padx=20)
        
        self.password_entry = CTkEntry(self.login_subframe, placeholder_text="Password", show="*", width=250)
        self.password_entry.pack(pady=10, padx=20)

        self.login_button = CTkButton(self.login_subframe, text="Login", command=self.login, width=250)
        self.login_button.pack(pady=20, padx=20)
        
        self.go_to_register_button = CTkButton(self.login_subframe, text="Register", command=self.show_registration_frame, width=250, fg_color="transparent", border_width=1)
        self.go_to_register_button.pack(pady=10, padx=20)

        # --- Registration Widgets ---
        self.registration_subframe = CTkFrame(self.login_frame, fg_color="transparent")
        
        self.reusername_entry = CTkEntry(self.registration_subframe, placeholder_text="Username", width=250)
        self.reusername_entry.pack(pady=5, padx=20)
        
        self.reemail_entry = CTkEntry(self.registration_subframe, placeholder_text="Email", width=250)
        self.reemail_entry.pack(pady=5, padx=20)

        self.repassword_entry = CTkEntry(self.registration_subframe, placeholder_text="Password", show="*", width=250)
        self.repassword_entry.pack(pady=5, padx=20)
        
        self.repassword_entry1 = CTkEntry(self.registration_subframe, placeholder_text="Confirm Password", show="*", width=250)
        self.repassword_entry1.pack(pady=5, padx=20)

        self.submit_button = CTkButton(self.registration_subframe, text="Submit Registration", command=self.submit_registration, width=250)
        self.submit_button.pack(pady=20, padx=20)

        self.go_to_login_button = CTkButton(self.registration_subframe, text="Back to Login", command=self.show_login_subframe, width=250, fg_color="transparent", border_width=1)
        self.go_to_login_button.pack(pady=10, padx=20)

    def _check_for_users(self):
        """Enables registration for multiple users."""
        pass

    def show_registration_frame(self):
        self.login_subframe.grid_forget()
        self.registration_subframe.grid(row=1, column=0, columnspan=2, sticky="nsew")

    def show_login_subframe(self):
        self.registration_subframe.grid_forget()
        self.login_subframe.grid(row=1, column=0, columnspan=2, sticky="nsew")

    def _create_main_widgets(self):
        """Creates the main application widgets after login."""
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)

        # --- Top Frame for Search and Logout ---
        top_frame = CTkFrame(self.main_frame)
        top_frame.grid(row=0, column=0, columnspan=2, sticky="ew", padx=10, pady=10)

        CTkLabel(top_frame, text="Search:").pack(side="left", padx=(10, 5))
        self.search_entry = CTkEntry(top_frame, placeholder_text="Search for any value...")
        self.search_entry.pack(side="left", fill="x", expand=True, padx=5)
        self.search_entry.bind("<KeyRelease>", lambda e: self.search_records())
        
        self.logout_button = CTkButton(top_frame, text="Logout", command=self.logout)
        self.logout_button.pack(side="right", padx=10)

        # --- Tab View for Dashboard and Manager ---
        tabview = CTkTabview(self.main_frame)
        tabview.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        
        tab_dashboard = tabview.add("Dashboard")
        tab_manager = tabview.add("Application Manager")

        # --- Dashboard Tab ---
        tab_dashboard.grid_columnconfigure(0, weight=1)
        tab_dashboard.grid_rowconfigure(0, weight=1)
        self.fig, self.ax = plt.subplots(figsize=(10, 5))
        self.fig.patch.set_facecolor("#2B2B2B") # Match dark theme
        self.ax.set_facecolor("#2B2B2B")
        self.ax.tick_params(axis="x", colors="white")
        self.ax.tick_params(axis="y", colors="white")
        self.ax.xaxis.label.set_color("white")
        self.ax.yaxis.label.set_color("white")
        self.ax.title.set_color("white")

        self.canvas_widget = FigureCanvasTkAgg(self.fig, master=tab_dashboard)
        self.canvas_widget.get_tk_widget().grid(row=0, column=0, sticky="nsew")
        
        # --- Application Manager Tab ---
        tab_manager.grid_rowconfigure(0, weight=1)
        tab_manager.grid_columnconfigure(0, weight=3)
        tab_manager.grid_columnconfigure(1, weight=1)
        
        tree_frame = CTkFrame(tab_manager)
        tree_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        self.columns = ("app_name", "app_user", "app_password", "app_email", "creation_date")
        self.tree = ttk.Treeview(tree_frame, columns=self.columns, show="headings", height=20)
        
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background="#2B2B2B", foreground="white", fieldbackground="#2B2B2B", borderwidth=0)
        style.map("Treeview", background=[("selected", "#1F6AA5")])
        style.configure("Treeview.Heading", background="#242424", foreground="white", relief="flat")
        style.map("Treeview.Heading", background=[("active", "#313131")])
        
        self.tree.heading("app_name", text="Application")
        self.tree.heading("app_user", text="Username")
        self.tree.heading("app_password", text="Password")
        self.tree.heading("app_email", text="Email")
        self.tree.heading("creation_date", text="Date Added")

        for col in self.columns:
            self.tree.column(col, width=120, stretch=False)
        
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.tree.bind("<<TreeviewSelect>>", self._item_selected)

        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=0, column=1, sticky="ns")

        # --- Info/Actions Frame ---
        info_frame = CTkFrame(tab_manager)
        info_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        
        CTkLabel(info_frame, text="Manage Records", font=CTkFont(size=16, weight="bold")).pack(pady=10)

        self.app_name_entry = CTkEntry(info_frame, placeholder_text="Application Name")
        self.app_name_entry.pack(fill="x", padx=10, pady=5)
        self.app_user_entry = CTkEntry(info_frame, placeholder_text="Application Username")
        self.app_user_entry.pack(fill="x", padx=10, pady=5)
        self.app_pass_entry = CTkEntry(info_frame, placeholder_text="Application Password")
        self.app_pass_entry.pack(fill="x", padx=10, pady=5)
        self.app_email_entry = CTkEntry(info_frame, placeholder_text="Application Email")
        self.app_email_entry.pack(fill="x", padx=10, pady=5)

        btn_frame = CTkFrame(info_frame, fg_color="transparent")
        btn_frame.pack(fill="x", pady=10)
        btn_frame.grid_columnconfigure((0,1), weight=1)

        CTkButton(btn_frame, text="Add", command=self.add_recordtree).grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        CTkButton(btn_frame, text="Update", command=self.update_recordtree).grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        CTkButton(btn_frame, text="Delete", command=self.delete_treerecord, fg_color="#D32F2F", hover_color="#B71C1C").grid(row=1, column=0, padx=5, pady=5, sticky="ew")
        CTkButton(btn_frame, text="Clear Fields", command=self._clear_entries).grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        CTkButton(info_frame, text="Show/Hide Password", command=self.show_application_password).pack(fill="x", padx=10, pady=10)
        CTkButton(info_frame, text="Export All (CSV)", command=self.export_all_records).pack(fill="x", padx=10, pady=5)
    
    # --- Backend and Logic Methods ---

    def _valid_email(self, email):
        regex = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
        return re.fullmatch(regex, email)

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().encode('utf-8')
        
        if not username or not password:
            ms.showerror("Error", "Username and password cannot be empty.")
            return

        try:
            db = sqlite3.connect(get_database_path())
            c = db.cursor()
            c.execute("SELECT password FROM account WHERE username=?", (username,))
            result = c.fetchone()
            
            if result and bcrypt.checkpw(password, result[0]):
                self.username = username
                ms.showinfo("Success", f"Welcome, {username}!")
                
                # Log the login event
                c.execute("INSERT INTO event (logindate, event, username) VALUES (datetime('now'), 'login', ?)", (self.username,))
                db.commit()
                db.close()
                
                self.show_main_frame()
            else:
                db.close()
                ms.showerror("Error", "Invalid username or password.")
        except sqlite3.Error as e:
            ms.showerror("Database Error", f"An error occurred: {e}")

    def logout(self):
        self.username = None
        self.df_passwords = pd.DataFrame()
        self.tree.delete(*self.tree.get_children())
        self._clear_entries()
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.show_login_frame()

    def submit_registration(self):
        new_user = self.reusername_entry.get().lower().strip()
        new_email = self.reemail_entry.get().strip()
        new_password = self.repassword_entry.get()
        confirm_password = self.repassword_entry1.get()

        if not all([new_user, new_email, new_password, confirm_password]):
            ms.showerror("Error", "All fields must be filled.")
            return
        if not self._valid_email(new_email):
            ms.showerror("Error", "Invalid email format.")
            return
        if new_password != confirm_password:
            ms.showerror("Error", "Passwords do not match.")
            return

        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        
        try:
            db = sqlite3.connect(get_database_path())
            c = db.cursor()
            c.execute("INSERT INTO account (username, password, email, admin, creationdate) VALUES (?, ?, ?, ?, datetime('now'))",
                      (new_user, hashed_password, new_email, 0))
            db.commit()
            db.close()
            ms.showinfo("Success", "Account created successfully! Please log in.")
            self.reusername_entry.delete(0, tk.END)
            self.reemail_entry.delete(0, tk.END)
            self.repassword_entry.delete(0, tk.END)
            self.repassword_entry1.delete(0, tk.END)
            self.show_login_subframe()
        except sqlite3.IntegrityError:
            ms.showerror("Error", "Username already exists.")
        except sqlite3.Error as e:
            ms.showerror("Database Error", f"An error occurred: {e}")

    def fetchall_app(self):
        """Fetches all password records for the logged-in user."""
        if not self.username: return
        try:
            db = sqlite3.connect(get_database_path())
            query = "SELECT nameapp, user_app, password, email_in_app, creationdate FROM userapplication WHERE username = ?"
            self.df_passwords = pd.read_sql_query(query, db, params=(self.username,))
            db.close()
            self._populate_tree()
        except Exception as e:
            ms.showerror("Error", f"Failed to fetch records: {e}")

    def _populate_tree(self, data_frame=None):
        """Populates the treeview with data from a DataFrame."""
        self.tree.delete(*self.tree.get_children())
        df = data_frame if data_frame is not None else self.df_passwords
        
        for _, row in df.iterrows():
            # Passwords are encrypted, so show asterisks
            display_row = list(row)
            display_row[2] = "********" 
            self.tree.insert("", tk.END, values=display_row)

    def _item_selected(self, event=None):
        """Handles selection of an item in the treeview."""
        selected_items = self.tree.selection()
        if not selected_items:
            return
        
        selected_item = selected_items[0]
        values = self.tree.item(selected_item, "values")
        
        self._clear_entries()
        self.app_name_entry.insert(0, values[0])
        self.app_user_entry.insert(0, values[1])
        # We don't insert the password for security
        self.app_email_entry.insert(0, values[3])

    def _clear_entries(self):
        self.app_name_entry.delete(0, tk.END)
        self.app_user_entry.delete(0, tk.END)
        self.app_pass_entry.delete(0, tk.END)
        self.app_email_entry.delete(0, tk.END)

    def add_recordtree(self):
        app_name = self.app_name_entry.get()
        app_user = self.app_user_entry.get()
        app_pass = self.app_pass_entry.get()
        app_email = self.app_email_entry.get()

        if not all([app_name, app_user, app_pass]):
            ms.showerror("Error", "Application name, username, and password are required.")
            return

        encrypted_pass = self.cipher.encrypt(app_pass.encode('utf-8'))
        
        try:
            db = sqlite3.connect(get_database_path())
            c = db.cursor()
            # Ensure the app name exists in the infoapplication table
            c.execute("INSERT OR IGNORE INTO infoapplication (nameapp) VALUES (?)", (app_name,))
            
            c.execute (
                """INSERT INTO userapplication (nameapp, user_app, password, email_in_app, creationdate, username)
                VALUES (?, ?, ?, ?, datetime('now'), ?)
            """, (app_name, app_user, encrypted_pass, app_email, self.username))
            db.commit()
            db.close()
            
            self._clear_entries()
            ms.showinfo("Success", "Record added successfully.")
            self.fetchall_app()
        except sqlite3.Error as e:
            ms.showerror("Database Error", f"Could not add record: {e}")

    def update_recordtree(self):
        selected_items = self.tree.selection()
        if not selected_items:
            ms.showerror("Error", "Please select a record to update.")
            return
        
        original_app_name = self.tree.item(selected_items[0], "values")[0]
        
        app_name = self.app_name_entry.get()
        app_user = self.app_user_entry.get()
        app_pass = self.app_pass_entry.get() # New password can be blank
        app_email = self.app_email_entry.get()

        if not all([app_name, app_user]):
            ms.showerror("Error", "Application name and username are required.")
            return

        try:
            db = sqlite3.connect(get_database_path())
            c = db.cursor()
            
            if app_pass:
                # If a new password is provided, encrypt it
                encrypted_pass = self.cipher.encrypt(app_pass.encode('utf-8'))
                c.execute (
                    """UPDATE userapplication 
                    SET nameapp=?, user_app=?, password=?, email_in_app=?
                    WHERE nameapp=? AND username=?
                """, (app_name, app_user, encrypted_pass, app_email, original_app_name, self.username))
            else:
                # Otherwise, keep the old password
                c.execute (
                    """UPDATE userapplication 
                    SET nameapp=?, user_app=?, email_in_app=?
                    WHERE nameapp=? AND username=?
                """, (app_name, app_user, app_email, original_app_name, self.username))

            db.commit()
            db.close()
            
            self._clear_entries()
            ms.showinfo("Success", "Record updated successfully.")
            self.fetchall_app()
        except sqlite3.Error as e:
            ms.showerror("Database Error", f"Could not update record: {e}")

    def delete_treerecord(self):
        selected_items = self.tree.selection()
        if not selected_items:
            ms.showerror("Error", "Please select a record to delete.")
            return

        if not ms.askyesno("Confirm Delete", "Are you sure you want to delete this record?"):
            return
            
        original_app_name = self.tree.item(selected_items[0], "values")[0]

        try:
            db = sqlite3.connect(get_database_path())
            c = db.cursor()
            c.execute("DELETE FROM userapplication WHERE nameapp=? AND username=?", (original_app_name, self.username))
            db.commit()
            db.close()

            self._clear_entries()
            ms.showinfo("Success", "Record deleted.")
            self.fetchall_app()
        except sqlite3.Error as e:
            ms.showerror("Database Error", f"Could not delete record: {e}")

    def show_application_password(self):
        selected_items = self.tree.selection()
        if not selected_items:
            ms.showerror("Error", "Please select a record to view the password.")
            return

        # Find the original row in the DataFrame
        app_name = self.tree.item(selected_items[0], "values")[0]
        record = self.df_passwords[self.df_passwords["nameapp"] == app_name]
        
        if record.empty:
            ms.showerror("Error", "Could not find the original record.")
            return

        encrypted_pass = record["password"].iloc[0]
        
        try:
            decrypted_pass = self.cipher.decrypt(encrypted_pass).decode('utf-8')
            ms.showinfo("Password", f"The password for '{app_name}' is:\n\n{decrypted_pass}")
        except Exception as e:
            ms.showerror("Decryption Error", "Could not decrypt password. The key may have changed or the data is corrupt.")

    def search_records(self):
        search_term = self.search_entry.get().lower()
        if not search_term:
            self._populate_tree()
            return

        # Make a copy to avoid altering the main DataFrame
        df_copy = self.df_passwords.copy()
        
        # Temporarily decrypt passwords for searching
        def decrypt_for_search(p):
            try:
                return self.cipher.decrypt(p).decode('utf-8').lower()
            except:
                return "" # Return empty string if decryption fails

        # We can search using name of app, user app, and email. 
        mask = (df_copy["nameapp"].str.lower().str.contains(search_term)) | \
               (df_copy["user_app"].str.lower().str.contains(search_term)) | \
               (df_copy["email_in_app"].str.lower().str.contains(search_term))

        self._populate_tree(df_copy[mask])

    def export_all_records(self):
        if self.df_passwords.empty:
            ms.showwarning("Export", "No records to export.")
            return
            
        file_path = fd.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if not file_path:
            return

        # Decrypt passwords before exporting
        df_to_export = self.df_passwords.copy()
        df_to_export["password"] = df_to_export["password"].apply(lambda p: self.cipher.decrypt(p).decode("utf-8") if p else "")
        
        df_to_export.to_csv(file_path, index=False)
        ms.showinfo("Success", f"All records exported to {file_path}")

    def update_dashboard(self):
        """Fetches login data and updates the bar chart."""
        self.ax.clear()
        
        try:
            db = sqlite3.connect(get_database_path())
            query = "SELECT logindate FROM event WHERE event = 'login' AND username = ?"
            df_logins = pd.read_sql_query(query, db, params=(self.username,))
            db.close()

            if df_logins.empty:
                months, counts = ["No Data"], [0]
            else:
                df_logins["logindate"] = pd.to_datetime(df_logins["logindate"])
                df_logins["month_year"] = df_logins["logindate"].dt.to_period("M").astype(str)
                login_counts = df_logins.groupby("month_year").size()
                months = login_counts.index.tolist()
                counts = login_counts.values
            
            x_pos = np.arange(len(months))
            self.ax.bar(x_pos, counts, color="#4AA5EB")
            self.ax.set_xticks(x_pos)
            self.ax.set_xticklabels(months, rotation=30, ha="right")
            
            self.ax.set_ylabel("Login Count", color="white")
            self.ax.set_xlabel("Month", color='white')
            self.ax.set_title(f"Login Activity for {self.username}", color="white")
            self.ax.grid(alpha=0.3)

        except Exception as e:
            self.ax.set_title(f"Error loading dashboard: {e}", color="red")

        self.fig.tight_layout()
        self.canvas_widget.draw()

def run_app():
    """Initializes and runs the password manager application."""
    root = CTk()
    root.title("OneLock")
    root.geometry("1200x700+100+50")
    
    try:
        root.iconbitmap("assets/icons.ico")
    except tk.TclError:
        print("Icon file not here: assets/icons.ico")
        
    app = PasswordManager(root)
    root.mainloop()
