import os
import string
import pandas as pd
import random
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import zipfile
from datetime import datetime

# Modern color scheme
BG_COLOR = "#f0f0f0"
PRIMARY_COLOR = "#4a6fa5"
SECONDARY_COLOR = "#166088"
ACCENT_COLOR = "#4fc3f7"
TEXT_COLOR = "#333333"
WARNING_COLOR = "#ff5252"

ALPHABET = string.ascii_letters + string.digits

class PasswordManager:
    def __init__(self):
        if not os.path.isfile('data.csv'):
            self.create_csv()

    def generate_password(self, length=16):
        """Generate a random password of specified length."""
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for _ in range(length))
        return password

    def create_csv(self):
        data = {'Url/App name': [], 'Username': [], 'Password': []}
        df = pd.DataFrame(data)
        df.to_csv('data.csv', index=False)

    def backup(self):
        """Create a backup of data.csv in ZIP format."""
        if not os.path.isfile('data.csv'):
            return "File data.csv not found. Make sure the file exists."

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        zip_filename = f"backup_{timestamp}.zip"

        with zipfile.ZipFile(zip_filename, 'w') as zipf:
            zipf.write('data.csv', os.path.basename('data.csv'))

        return f"Backup created: {zip_filename}"

    def generate_key(self, master_pass):
        return ''.join(random.choice(ALPHABET) for _ in range(len(master_pass)))

    def encrypt(self, password, master_pass):
        encrypted_password = ""
        key = self.generate_key(master_pass)

        for i in range(len(password)):
            shift = (ord(master_pass[i % len(master_pass)]) + ord(key[i % len(key)]) + i) % len(ALPHABET)
            if password[i] in ALPHABET:
                new_pos = (ALPHABET.find(password[i]) + shift) % len(ALPHABET)
                encrypted_password += ALPHABET[new_pos]
            else:
                encrypted_password += password[i]

        return key + encrypted_password

    def decrypt(self, encrypted_password, master_pass):
        key = encrypted_password[:len(master_pass)]
        encrypted_password = encrypted_password[len(key):]

        decrypted_password = ""

        for i in range(len(encrypted_password)):
            shift = (ord(master_pass[i % len(master_pass)]) + ord(key[i % len(key)]) + i) % len(ALPHABET)
            if encrypted_password[i] in ALPHABET:
                new_pos = (ALPHABET.find(encrypted_password[i]) - shift) % len(ALPHABET)
                decrypted_password += ALPHABET[new_pos]
            else:
                decrypted_password += encrypted_password[i]

        return decrypted_password

    def add(self, url, username, password, master_pass):
        if url == '':
            return "WARNING: URL or App Name cannot be empty."

        encrypted_url = self.encrypt(url, master_pass)
        encrypted_username = self.encrypt(username, master_pass)
        encrypted_password = self.encrypt(password, master_pass)

        user_data = {'Url/App name': [encrypted_url], 'Username': [encrypted_username], 'Password': [encrypted_password]}
        df = pd.DataFrame(user_data)
        df.to_csv('data.csv', mode='a', header=False, index=False)
        return "Credentials Added Successfully."

    def show_all_urls(self, master_pass):
        df = pd.read_csv('data.csv')
        decrypted_urls = [self.decrypt(row['Url/App name'], master_pass) for index, row in df.iterrows()]
        return decrypted_urls

    def search(self, master_pass, url=''):
        df = pd.read_csv('data.csv')

        decrypted_urls = [self.decrypt(row['Url/App name'], master_pass) for index, row in df.iterrows()]
        
        filtered_indices = [index for index, dec_url in enumerate(decrypted_urls) if url.lower() in dec_url.lower()]

        results = []
        if not filtered_indices:
            return ["No matching credentials found."]
        
        for index in filtered_indices:
            found_password = df.at[index, 'Password']
            found_username = df.at[index, 'Username']
            found_url = df.at[index, 'Url/App name']
            dec_password = self.decrypt(found_password, master_pass)
            dec_username = self.decrypt(found_username, master_pass)
            dec_url = self.decrypt(found_url, master_pass)
            results.append(f"Index: {index}, URL: {dec_url}, Username: {dec_username}, Password: {dec_password}")

        return results

    def edit(self, index, new_url, new_username, new_password, master_pass):
        df = pd.read_csv("data.csv")

        if not df.index.isin([index]).any():
            return "Invalid index. No such entry exists."

        new_url = self.encrypt(new_url, master_pass) if new_url else df.at[index, 'Url/App name']
        new_username = self.encrypt(new_username, master_pass) if new_username else df.at[index, 'Username']
        new_password = self.encrypt(new_password, master_pass) if new_password else df.at[index, 'Password']

        df.at[index, 'Url/App name'] = new_url
        df.at[index, 'Username'] = new_username
        df.at[index, 'Password'] = new_password
        df.to_csv('data.csv', index=False)
        return "Credentials Edited Successfully."

    def delete(self, index):
        df = pd.read_csv("data.csv")

        if not df.index.isin([index]).any():
            return "Invalid index. No such entry exists."
        
        df.drop(index, inplace=True)
        df.to_csv('data.csv', index=False)
        return "Credentials Deleted Successfully."


class ModernApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.manager = PasswordManager()
        self.master_pass = ""
        self.last_username = ""
        self.last_password = ""

        self.title("SecurePass Manager")
        self.geometry("600x600")
        self.configure(bg=BG_COLOR)
        
        # Set application icon (replace with your own icon path if available)
        try:
            self.iconbitmap('icon.ico')
        except:
            pass

        self.style = ttk.Style()
        self.style.configure('TFrame', background=BG_COLOR)
        self.style.configure('TLabel', background=BG_COLOR, foreground=TEXT_COLOR)
        self.style.configure('TButton', background=PRIMARY_COLOR, foreground='black', 
                            font=('Helvetica', 10, 'bold'), padding=5)
        self.style.map('TButton', 
                      background=[('active', SECONDARY_COLOR), ('disabled', '#cccccc')])
        
        self.create_widgets()
    
    def create_widgets(self):
        # Master password frame
        self.master_frame = ttk.Frame(self)
        self.master_frame.pack(pady=40, padx=20, fill='x')
        
        ttk.Label(self.master_frame, text="SecurePass Manager", 
                 font=('Helvetica', 16, 'bold')).pack(pady=10)
        
        ttk.Label(self.master_frame, text="Enter Master Password:", 
                 font=('Helvetica', 10)).pack(pady=5)
        
        self.master_entry = ttk.Entry(self.master_frame, show='•', font=('Helvetica', 10))
        self.master_entry.pack(pady=5, ipady=5, ipadx=50)
        
        self.submit_master_btn = ttk.Button(self.master_frame, text="Unlock", 
                                          command=self.set_master_password)
        self.submit_master_btn.pack(pady=10)
        
        # Warning label
        self.warning_label = ttk.Label(self.master_frame, 
                                     text="⚠️ WARNING: If you lose your master password, you won't be able\n"
                                          "to recover your saved passwords. Use a strong, memorable password.",
                                     foreground=WARNING_COLOR, font=('Helvetica', 9))
        self.warning_label.pack(pady=10)
        
        # Main application frame (hidden until master password is set)
        self.main_frame = ttk.Frame(self)
        
        # Results area
        self.results_text = scrolledtext.ScrolledText(
            self.main_frame, width=70, height=15, wrap=tk.WORD, 
            bg='white', fg=TEXT_COLOR, font=('Consolas', 10),
            padx=10, pady=10
        )
        self.results_text.pack(pady=20, padx=20, fill='both', expand=True)
        
        # Button frame
        self.button_frame = ttk.Frame(self.main_frame)
        self.button_frame.pack(pady=10)
        
        # Create buttons
        buttons = [
            ("Add Credentials", self.add_credential),
            ("Search", self.search_credentials),
            ("Edit", self.edit_credential),
            ("Delete", self.delete_credential),
            ("Show All", self.show_all_urls),
            ("Generate Password", self.generate_password_gui),
            ("Copy Login", self.copy_login),
            ("Copy Password", self.copy_password),
            ("Backup", self.backup_callback)
        ]
        
        for i, (text, command) in enumerate(buttons):
            btn = ttk.Button(self.button_frame, text=text, command=command)
            btn.grid(row=i//3, column=i%3, padx=5, pady=5, sticky='ew')
        
        # Bind Enter key to submit master password
        self.master_entry.bind('<Return>', lambda event: self.set_master_password())
    
    def set_master_password(self):
        self.master_pass = self.master_entry.get()
        if len(self.master_pass) < 8:
            messagebox.showerror("Invalid Password", 
                               "Master password must be at least 8 characters.")
        else:
            self.master_frame.pack_forget()
            self.main_frame.pack(fill='both', expand=True)
            self.results_text.insert(tk.END, "Welcome to SecurePass Manager!\n")
            self.results_text.insert(tk.END, "Use the buttons above to manage your credentials.\n\n")
            self.results_text.configure(state='disabled')
    
    def generate_password_gui(self):
        generated_password = self.manager.generate_password()
        self.results_text.configure(state='normal')
        self.results_text.delete('1.0', tk.END)
        self.results_text.insert(tk.END, "Generated Password:\n")
        self.results_text.insert(tk.END, f"\n{generated_password}\n\n")
        self.results_text.insert(tk.END, "Click 'Add Credentials' to save this password.")
        self.results_text.configure(state='disabled')
    
    def add_credential(self):
        self.show_input_dialog("Add Credentials", ["URL/App Name", "Username", "Password"], self.add_callback)
    
    def search_credentials(self):
        self.show_input_dialog("Search Credentials", ["URL/App Name (leave blank for all)"], self.search_callback)
    
    def edit_credential(self):
        self.show_input_dialog("Edit Credentials", 
                              ["Index", "New URL/App Name", "New Username", "New Password"], 
                              self.edit_callback)
    
    def delete_credential(self):
        self.show_input_dialog("Delete Credentials", ["Index"], self.delete_callback)
    
    def show_all_urls(self):
        urls = self.manager.show_all_urls(self.master_pass)
        self.results_text.configure(state='normal')
        self.results_text.delete('1.0', tk.END)
        if urls:
            self.results_text.insert(tk.END, "Saved URLs/App Names:\n\n")
            self.results_text.insert(tk.END, "\n".join(urls))
        else:
            self.results_text.insert(tk.END, "No URLs/App names found.")
        self.results_text.configure(state='disabled')
    
    def show_input_dialog(self, title, fields, callback):
        dialog = tk.Toplevel(self)
        dialog.title(title)
        dialog.configure(bg=BG_COLOR)
        dialog.geometry("400x{}".format(100 + len(fields)*75))
        
        frame = ttk.Frame(dialog)
        frame.pack(pady=20, padx=20, fill='both', expand=True)
        
        entries = []
        for field in fields:
            ttk.Label(frame, text=field).pack(pady=(10, 0))
            entry = ttk.Entry(frame, font=('Helvetica', 10))
            entry.pack(pady=5, ipady=3, fill='x')
            entries.append(entry)
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="Submit", 
                  command=lambda: self.on_dialog_submit(dialog, entries, callback)).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Cancel", 
                  command=dialog.destroy).pack(side='left', padx=5)
        
        dialog.bind('<Return>', lambda event: self.on_dialog_submit(dialog, entries, callback))
    
    def on_dialog_submit(self, dialog, entries, callback):
        values = [entry.get() for entry in entries]
        dialog.destroy()
        
        self.results_text.configure(state='normal')
        self.results_text.delete('1.0', tk.END)
        
        try:
            result = callback(*values)
            self.results_text.insert(tk.END, result)
        except Exception as e:
            self.results_text.insert(tk.END, f"Error: {str(e)}")
        
        self.results_text.configure(state='disabled')
    
    def add_callback(self, url, username, password):
        return self.manager.add(url, username, password, self.master_pass)
    
    def search_callback(self, url):
        results = self.manager.search(self.master_pass, url)
        if results:
            # Store last username and password for copy functionality
            try:
                self.last_username = results[0].split(", Username: ")[1].split(", Password: ")[0].strip()
                self.last_password = results[0].split(", Password: ")[1].strip()
            except:
                pass
        return "\n".join(results) if results else "No results found."
    
    def edit_callback(self, index, new_url, new_username, new_password):
        return self.manager.edit(int(index), new_url, new_username, new_password, self.master_pass)
    
    def delete_callback(self, index):
        return self.manager.delete(int(index))
    
    def copy_login(self):
        if self.last_username:
            self.clipboard_clear()
            self.clipboard_append(self.last_username)
            self.results_text.configure(state='normal')
            self.results_text.delete('1.0', tk.END)
            self.results_text.insert(tk.END, "Username copied to clipboard!")
            self.results_text.configure(state='disabled')
    
    def copy_password(self):
        if self.last_password:
            self.clipboard_clear()
            self.clipboard_append(self.last_password)
            self.results_text.configure(state='normal')
            self.results_text.delete('1.0', tk.END)
            self.results_text.insert(tk.END, "Password copied to clipboard!")
            self.results_text.configure(state='disabled')
    
    def backup_callback(self):
        message = self.manager.backup()
        self.results_text.configure(state='normal')
        self.results_text.delete('1.0', tk.END)
        self.results_text.insert(tk.END, message)
        self.results_text.configure(state='disabled')


if __name__ == "__main__":
    app = ModernApp()
    app.mainloop()
