import os
import string
import pandas as pd
import random
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, font
import zipfile
from datetime import datetime
import hashlib
import binascii
import secrets
import json
import base64
import csv
import hmac
        
# Modern color scheme
BG_COLOR = "#003366"  # Dark background
PRIMARY_COLOR = "#4682b4"
SECONDARY_COLOR = "#9acd32"
ACCENT_COLOR = "#4fc3f7"
TEXT_COLOR = "#e0ffff"  # White text
WARNING_COLOR = "#ff5252"
ENTRY_BG = "#002147"  # Darker entry fields
BUTTON_HOVER = "#00bfff"

# Font settings
FONT_FAMILY = "Segoe UI"  # Modern Windows font
TITLE_FONT = (FONT_FAMILY, 18, "bold")
LABEL_FONT = (FONT_FAMILY, 10)
BUTTON_FONT = (FONT_FAMILY, 12, "bold")
ENTRY_FONT = (FONT_FAMILY, 12)

ALPHABET = string.ascii_letters + string.digits

class PasswordManager:
    def __init__(self, master_pass=None):
        self.config = self.load_config(master_pass) if master_pass else {'iterations': 100000}
        self.iterations = self.config.get('iterations', 100000)
        
        if not os.path.isfile('data.csv'):
            self.create_csv()
    @staticmethod
    def load_config():
        if os.path.isfile('config.json'):
            try:
                with open('config.json', 'r') as f:
                    config = json.load(f)
                    if 'iterations' in config:
                        config['iterations'] = transform_iterations(config['iterations'], reverse=True)
                    return config
            except:
                return {'iterations': 100000}
        return {'iterations': 100000}
    @staticmethod
    def save_config(config):
        config_copy = config.copy()
        if 'iterations' in config_copy:
            config_copy['iterations'] = PasswordManager.transform_iterations(config_copy['iterations'])
        with open('config.json', 'w') as f:
            json.dump(config_copy, f, indent=2)
            
    @staticmethod
    def transform_iterations(value, reverse=False):
        if not reverse:
            salt = random.randint(1000, 9999)
            combined = (value * 3 + salt) * 7 + 13579
            hash_obj = hashlib.sha256(str(combined).encode())
            hash_digest = hash_obj.hexdigest()
            hash_int = int(hash_digest[:8], 16) 
            offset = random.randint(50000, 100000)
            result = {
                'hash': hash_digest,
                'offset': offset,
                'salt': salt,
                'masked_value': hash_int ^ offset
            }
            return json.dumps(result)
        else:
            try:
                data = json.loads(value)
                hash_digest = data['hash']
                offset = data['offset']
                salt = data['salt']
                masked_value = data['masked_value']
                hash_int = masked_value ^ offset
                for possible_value in range(0, 2000000):
                    combined = (possible_value * 3 + salt) * 7 + 13579
                    hash_check = hashlib.sha256(str(combined).encode()).hexdigest()
                    hash_int_check = int(hash_check[:8], 16)
                    if hash_int_check == hash_int:
                        return possible_value
                return 100000
            except:
                return 100000


    def update_iterations(self, new_iterations):
        self.iterations = new_iterations
        self.config['iterations'] = new_iterations
        PasswordManager.save_config(self.config)
            
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
        """Create a backup of data.csv and config.json in ZIP format in backups directory."""
        # Sprawdź czy istnieje katalog data, jeśli nie - utwórz
        data_dir = 'data'
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)
        
        # Ścieżki do plików
        data_csv = os.path.join(data_dir, 'data.csv')
        config_json = os.path.join(data_dir, 'config.json')
        
        # Sprawdź czy istnieją pliki do backupu
        files_to_backup = []
        if os.path.isfile(data_csv):
            files_to_backup.append(data_csv)
        if os.path.isfile(config_json):
            files_to_backup.append(config_json)
        
        if not files_to_backup:
            return "Error: No files found to backup (data/data.csv or data/config.json)"

        # Utwórz katalog backups jeśli nie istnieje
        backup_dir = 'backups'
        if not os.path.exists(backup_dir):
            try:
                os.makedirs(backup_dir)
            except OSError as e:
                return f"Error creating backup directory: {str(e)}"

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        zip_filename = os.path.join(backup_dir, f"backup_{timestamp}.zip")

        try:
            with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for filepath in files_to_backup:
                    zipf.write(filepath, os.path.basename(filepath))
            return f"Backup created successfully: {zip_filename}\nBacked up files: {', '.join(os.path.basename(f) for f in files_to_backup)}"
        except Exception as e:
            return f"Error creating backup: {str(e)}"

    def _derive_key(self, password, salt):
        dk = hashlib.pbkdf2_hmac('sha512', 
                                password.encode('utf-8'), 
                                salt, 
                                self.iterations)
        
        # Dodatkowe "solenie" klucza
        pepper = b"fixed_pepper_value"  # Stała wartość dodająca entropii
        return binascii.hexlify(hashlib.blake2b(dk + pepper).digest()).decode('utf-8')

    def encrypt(self, plaintext, master_pass):
        salt = secrets.token_bytes(32)  # Zwiększona długość soli do 32 bajtów
        key = self._derive_key(master_pass, salt)
        
        # Wiele warstw szyfrowania
        encrypted = self._multi_layer_encrypt(plaintext, key)
        
        # Dodatkowe zabezpieczenie wartości
        hmac_value = hmac.new(key.encode('utf-8'), encrypted.encode('utf-8'), 'sha3_256').hexdigest()
        
        return f"{binascii.hexlify(salt).decode('utf-8')}:{encrypted}:{hmac_value}"

    def _multi_layer_encrypt(self, text, key):
        # Pierwsza warstwa - XOR
        result = []
        for i, c in enumerate(text):
            key_char = key[(i + len(text)) % len(key)]
            result.append(chr(ord(c) ^ ord(key_char)))
        
        # Druga warstwa - odwrócenie i przesunięcie
        reversed_key = key[::-1]
        shifted = []
        for i, c in enumerate(result):
            shifted.append(chr((ord(c) + ord(reversed_key[i % len(reversed_key)])) % 256))
        
        # Trzecia warstwa - mieszanie
        mixed = []
        for i in range(0, len(shifted), 2):
            if i+1 < len(shifted):
                mixed.append(shifted[i+1])
                mixed.append(shifted[i])
            else:
                mixed.append(shifted[i])
        
        # Kodowanie Base64 z dodatkowym zabezpieczeniem
        mixed_str = ''.join(mixed)
        encrypted_bytes = mixed_str.encode('utf-8')
        return base64.b64encode(encrypted_bytes).decode('utf-8')

    def decrypt(self, ciphertext, master_pass):
        if ciphertext.count(':') != 2:
            return "[DECRYPTION ERROR: Invalid format]"
            
        salt_hex, encrypted_b64, hmac_value = ciphertext.split(':')
        
        try:
            salt = binascii.unhexlify(salt_hex)
            key = self._derive_key(master_pass, salt)
            
            # Weryfikacja HMAC
            expected_hmac = hmac.new(key.encode('utf-8'), encrypted_b64.encode('utf-8'), 'sha3_256').hexdigest()
            if not hmac.compare_digest(hmac_value, expected_hmac):
                return "[DECRYPTION ERROR: Integrity check failed]"
                
            return self._multi_layer_decrypt(encrypted_b64, key)
        except Exception as e:
            return f"[DECRYPTION ERROR: {str(e)}]"

    def _multi_layer_decrypt(self, encrypted_b64, key):
        # Dekodowanie Base64
        encrypted_bytes = base64.b64decode(encrypted_b64)
        encrypted_str = encrypted_bytes.decode('utf-8')
        
        # Odwrócenie mieszania
        mixed = list(encrypted_str)
        unmixed = []
        for i in range(0, len(mixed), 2):
            if i+1 < len(mixed):
                unmixed.append(mixed[i+1])
                unmixed.append(mixed[i])
            else:
                unmixed.append(mixed[i])
        
        # Odwrócenie przesunięcia
        reversed_key = key[::-1]
        unshifted = []
        for i, c in enumerate(unmixed):
            unshifted.append(chr((ord(c) - ord(reversed_key[i % len(reversed_key)])) % 256))
        
        # Odwrócenie XOR
        result = []
        for i, c in enumerate(unshifted):
            key_char = key[(i + len(unshifted)) % len(key)]
            result.append(chr(ord(c) ^ ord(key_char)))
        
        return ''.join(result)

    def add(self, url, username, password, master_pass):
        # Najpierw sprawdź czy istnieje plik konfiguracyjny
        if not os.path.isfile('config.json'):
            return ("SECURITY CONFIGURATION NEEDED\n\n"
                    "Before adding credentials:\n"
                    "1. Set PBKDF2 iterations (10,000-200,000 default 100000)\n"
                    "2. Save settings\n\n"
                    "Why this matters?\n"
                    "• Iterations strengthen your master password\n"
                    "• Required for consistent encryption\n"
                    "• Affects all devices using this vault")

        if url == '':
            return "WARNING: URL or App Name cannot be empty."

        try:
            # Sprawdź czy dane zawierają niebezpieczne znaki
            if not all(self.is_valid_credential(field) for field in [url, username, password]):
                return "WARNING: Invalid characters in input fields"

            # Sprawdź czy URL już istnieje
            if os.path.isfile('data.csv'):
                df = pd.read_csv('data.csv')
                for _, row in df.iterrows():
                    decrypted_url = self.decrypt(row['Url/App name'], master_pass)
                    if not decrypted_url.startswith('[DECRYPTION ERROR') and decrypted_url == url:
                        return "WARNING: This URL/App already exists in database"

            # Zaszyfruj dane
            encrypted_url = self.encrypt(url, master_pass)
            encrypted_username = self.encrypt(username, master_pass)
            encrypted_password = self.encrypt(password, master_pass)

            # Zapisz do pliku CSV
            new_data = {
                'Url/App name': [encrypted_url],
                'Username': [encrypted_username],
                'Password': [encrypted_password]
            }
            new_df = pd.DataFrame(new_data)
            
            if not os.path.isfile('data.csv'):
                new_df.to_csv('data.csv', index=False)
            else:
                new_df.to_csv('data.csv', mode='a', header=False, index=False)
                
            return "Credentials Added Successfully."
        except Exception as e:
            return f"Error adding credentials: {str(e)}"

    def is_valid_credential(self, text):
        """Sprawdza czy tekst zawiera tylko bezpieczne znaki"""
        if not isinstance(text, str):
            return False
        # Dopuszczamy podstawowe znaki ASCII (32-126) + polskie znaki
        return all(ord(c) <= 126 or c in 'ąćęłńóśźżĄĆĘŁŃÓŚŹŻ' for c in text)

    def show_all_urls(self, master_pass):
        if not os.path.isfile('data.csv'):
            return []

        try:
            df = pd.read_csv('data.csv')
            decrypted_urls = []
            
            for _, row in df.iterrows():
                try:
                    decrypted = self.decrypt(row['Url/App name'], master_pass)
                    if not decrypted.startswith('[DECRYPTION ERROR'):
                        decrypted_urls.append(decrypted)
                except:
                    continue
                    
            return decrypted_urls
        except Exception as e:
            print(f"Error reading URLs: {str(e)}")
            return []

    def search(self, master_pass, url=None):
        if url is None or len(url.strip()) < 2:
            return ["Please enter at least 2 characters to search."]
        
        if not os.path.isfile('data.csv'):
            return ["No credentials stored yet."]

        try:
            df = pd.read_csv('data.csv')
            results = []
            
            for index, row in df.iterrows():
                try:
                    dec_url = self.decrypt(row['Url/App name'], master_pass)
                    if dec_url.startswith('[DECRYPTION ERROR'):
                        continue
                        
                    if url.lower() in dec_url.lower():
                        dec_username = self.decrypt(row['Username'], master_pass)
                        dec_password = self.decrypt(row['Password'], master_pass)
                        
                        if (not dec_username.startswith('[DECRYPTION ERROR') and 
                            not dec_password.startswith('[DECRYPTION ERROR')):
                            results.append(
                                f"Index: {index}, "
                                f"URL: {dec_url}, "
                                f"Username: {dec_username}, "
                                f"Password: {dec_password}"
                            )
                except:
                    continue

            return results if results else ["No matching credentials found."]
        except Exception as e:
            return [f"Search error: {str(e)}"]

    def edit(self, index, new_url, new_username, new_password, master_pass):
        if not os.path.isfile('data.csv'):
            return "Error: No credentials file found"

        try:
            df = pd.read_csv('data.csv')
            
            if not (0 <= index < len(df)):
                return "Invalid index. No such entry exists."

            # Walidacja nowych danych
            if ((new_url and not self.is_valid_credential(new_url)) or 
                (new_username and not self.is_valid_credential(new_username)) or 
                (new_password and not self.is_valid_credential(new_password))):
                return "WARNING: Invalid characters in input fields"

            # Backup przed modyfikacją
            backup_result = self.backup()
            if not backup_result.startswith("Backup created"):
                return f"Backup failed: {backup_result}"

            # Przygotuj nowe zaszyfrowane wartości
            new_encrypted_url = self.encrypt(new_url, master_pass) if new_url else None
            new_encrypted_username = self.encrypt(new_username, master_pass) if new_username else None
            new_encrypted_password = self.encrypt(new_password, master_pass) if new_password else None

            # Sprawdź integralność nowych zaszyfrowanych danych
            if new_encrypted_url and self.decrypt(new_encrypted_url, master_pass).startswith('[DECRYPTION ERROR'):
                return "Error: Failed to encrypt new URL"
            if new_encrypted_username and self.decrypt(new_encrypted_username, master_pass).startswith('[DECRYPTION ERROR'):
                return "Error: Failed to encrypt new username"
            if new_encrypted_password and self.decrypt(new_encrypted_password, master_pass).startswith('[DECRYPTION ERROR'):
                return "Error: Failed to encrypt new password"

            # Aktualizacja pól
            if new_url:
                df.at[index, 'Url/App name'] = new_encrypted_url
            if new_username:
                df.at[index, 'Username'] = new_encrypted_username
            if new_password:
                df.at[index, 'Password'] = new_encrypted_password

            # Bezpieczny zapis do pliku tymczasowego
            temp_file = 'data_temp.csv'
            df.to_csv(temp_file, index=False)
            
            # Zamiana plików
            os.replace(temp_file, 'data.csv')
            
            return "Credentials Edited Successfully."
        except Exception as e:
            return f"Error editing credentials: {str(e)}"

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
        self.last_generated_password = ""

        self.title("SecurePass Manager")
        self.window_height = 700  # początkowa wysokość
        self.geometry(f"550x{self.window_height}")
        self.configure(bg=BG_COLOR)
        
        try:
            self.iconbitmap('data\icon.ico')
        except:
            pass
            
        # Dodajemy pasek menu
        self.create_menu_bar()

        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TFrame', background=BG_COLOR)
        self.style.configure('TLabel', background=BG_COLOR, foreground=TEXT_COLOR, font=LABEL_FONT)
        self.style.configure('TButton', 
                           background=PRIMARY_COLOR, 
                           foreground=TEXT_COLOR,
                           font=BUTTON_FONT,
                           borderwidth=1,
                           focusthickness=3,
                           focuscolor='none')
        self.style.map('TButton',
                      background=[('active', BUTTON_HOVER), ('disabled', '#555555')],
                      foreground=[('disabled', '#aaaaaa')])
        self.style.configure('TEntry', 
                           fieldbackground=ENTRY_BG,
                           foreground=TEXT_COLOR,
                           insertcolor=TEXT_COLOR,
                           borderwidth=1,
                           relief='flat',
                           padding=5)
        self.style.configure('Vertical.TScrollbar', 
                           background=BG_COLOR,
                           troughcolor=BG_COLOR,
                           bordercolor=BG_COLOR)

        self.create_widgets()
        self.check_config_and_toggle_options()

    def create_menu_bar(self):
        """Tworzy pasek menu na górze okna"""
        menubar = tk.Menu(self, bg=ENTRY_BG, fg=TEXT_COLOR, activebackground=PRIMARY_COLOR, 
                         activeforeground=TEXT_COLOR)
        
        # Menu Help z pozycją About
        help_menu = tk.Menu(menubar, tearoff=0, bg=ENTRY_BG, fg=TEXT_COLOR, 
                           activebackground=PRIMARY_COLOR, activeforeground=TEXT_COLOR)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Info", command=self.show_info)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.config(menu=menubar)

    def show_about(self):
        """Wyświetla okno dialogowe z informacjami o programie"""
        about_window = tk.Toplevel(self)
        about_window.title("About SecurePass Manager")
        about_window.geometry("400x500")
        about_window.resizable(False, False)
        about_window.configure(bg=BG_COLOR)
        
        try:
            about_window.iconbitmap('data\icon.ico')
        except:
            pass

        # Ramka główna
        frame = ttk.Frame(about_window)
        frame.pack(pady=20, padx=20, fill='both', expand=True)
        
        # Nagłówek
        ttk.Label(
            frame,
            text="SecurePass Manager",
            font=TITLE_FONT,
            foreground=ACCENT_COLOR
        ).pack(pady=(0, 10))
        
        # Wersja
        ttk.Label(
            frame,
            text="Version 1.1",
            font=LABEL_FONT,
            foreground=TEXT_COLOR
        ).pack(pady=(0, 20))
        
        # Opis programu
        about_text = """A secure password manager with strong encryption.

Features:
- AES-Like encryption
- Secure password generation
- Encrypted credential storage
- Backup functionality
- Cross-platform compatibility

Created with Python and Tkinter

Contact:
email: pleomati@gmail.com
https://github.com/pleomati/securepass
author: Adam Pasiak
"""
        text_widget = tk.Text(
            frame,
            bg=ENTRY_BG,
            fg=TEXT_COLOR,
            font=LABEL_FONT,
            wrap=tk.WORD,
            height=8,
            padx=10,
            pady=10,
            relief='flat',
            highlightthickness=0
        )
        text_widget.insert(tk.END, about_text)
        text_widget.config(state='disabled')
        text_widget.pack(fill='both', expand=True)
        
        # Copyright
        ttk.Label(
            frame,
            text="© 2025 SecurePass Team",
            font=('Segoe UI', 9),
            foreground=SECONDARY_COLOR
        ).pack(pady=(10, 0))
        
        # Przycisk zamknięcia
        ttk.Button(
            frame,
            text="Close",
            command=about_window.destroy,
            style='TButton'
        ).pack(pady=(20, 0))
        
    def show_info(self):
        """Wyświetla okno dialogowe z informacjami o programie"""
        about_window = tk.Toplevel(self)
        about_window.title("About SecurePass Manager")
        about_window.geometry("500x700")
        about_window.resizable(False, False)
        about_window.configure(bg=BG_COLOR)
        
        try:
            about_window.iconbitmap('data\icon.ico')
        except:
            pass

        # Ramka główna
        frame = ttk.Frame(about_window)
        frame.pack(pady=20, padx=20, fill='both', expand=True)
        
        # Nagłówek
        ttk.Label(
            frame,
            text="SecurePass Manager",
            font=TITLE_FONT,
            foreground=ACCENT_COLOR
        ).pack(pady=(0, 10))
        
        # Wersja
        ttk.Label(
            frame,
            text="Version 1.1",
            font=LABEL_FONT,
            foreground=TEXT_COLOR
        ).pack(pady=(0, 20))
        
        # Opis programu
        about_text = """Iterations Explained:
The iteration count determines how many times the 
password hashing algorithm repeats its process.
Higher values:
✓ Increase resistance to brute-force attacks
✓ Make password cracking exponentially harder
✓ Improve overall security
But also:
✗ Slightly slow down operations
✗ Increase resource usage

Recommended: 100,000-200,000 iterations
(default: 100,000)

Additional Features:
- Secure password generator
- Encrypted credential storage
- Automatic backups
- Clipboard protection
- Cross-platform compatibility

Technology Stack:
- Python 3.7+
- Tkinter GUI
- PBKDF2-HMAC-SHA512
- SHA3-256 for HMAC
- Base64 encoding
"""
        text_widget = tk.Text(
            frame,
            bg=ENTRY_BG,
            fg=TEXT_COLOR,
            font=LABEL_FONT,
            wrap=tk.WORD,
            height=8,
            padx=10,
            pady=10,
            relief='flat',
            highlightthickness=0
        )
        text_widget.insert(tk.END, about_text)
        text_widget.config(state='disabled')
        text_widget.pack(fill='both', expand=True)
        
        # Copyright
        ttk.Label(
            frame,
            text="© 2025 SecurePass Team",
            font=('Segoe UI', 9),
            foreground=SECONDARY_COLOR
        ).pack(pady=(10, 0))
        
        # Przycisk zamknięcia
        ttk.Button(
            frame,
            text="Close",
            command=about_window.destroy,
            style='TButton'
        ).pack(pady=(20, 0))

    
    def check_config_and_toggle_options_on_save(self):
        # Ukrywa lub pokazuje opcje zmiany iteracji w zależności od istnienia pliku
        if os.path.isfile('config.json'):
            # Ukryj opcje
            self.iterations_label.pack_forget()
            self.iterations_scale.pack_forget()
            #self.iterations_label_value.pack_forget()
            self.save_iterations_btn.pack_forget()
            self.decrease_btn.pack_forget()
            self.increase_btn.pack_forget()
        else:
            # Pokaż opcje
            self.iterations_label.pack(pady=(10, 5))
            self.iterations_scale.pack(pady=5, fill='x', expand=True)
            #self.iterations_label_value.pack(pady=5)
            self.save_iterations_btn.pack(pady=10)

    def check_config_and_toggle_options(self):
        # Ukrywa lub pokazuje opcje zmiany iteracji w zależności od istnienia pliku
        if os.path.isfile('config.json'):
            # Ukryj opcje
            self.iterations_label.pack_forget()
            self.iterations_scale.pack_forget()
            #self.iterations_label_value.pack_forget()
            self.save_iterations_btn.pack_forget()
            self.decrease_btn.pack_forget()
            self.increase_btn.pack_forget()
            # Zmniejsz wysokość okna o 150, nie schodząc poniżej 200
            self.window_height = max(200, self.window_height - 145)
            self.geometry(f"550x{self.window_height}")
        else:
            # Pokaż opcje
            self.iterations_label.pack(pady=(10, 5))
            self.iterations_scale.pack(pady=5, fill='x', expand=True)
            #self.iterations_label_value.pack(pady=5)
            self.save_iterations_btn.pack(pady=10)

    def save_iterations(self):
        try:
            new_value = int(self.iterations_value.get())
            if 10000 <= new_value <= 200000:
                self.manager.update_iterations(new_value)
                messagebox.showinfo("Zapisano", f"Ustawienia iteracji zapisane: {new_value}")
                # Zmniejsz wysokość okna o 150, nie schodząc poniżej 200
                self.window_height = max(200, self.window_height - 150)
                self.geometry(f"550x{self.window_height}")
                self.check_config_and_toggle_options_on_save()
            else:
                messagebox.showerror("Błędna wartość", "Wartość musi być w zakresie od 10 000 do 200 000.")
        except ValueError:
            messagebox.showerror("Błędna wartość", "Proszę wpisać poprawną liczbę.")

    
    def create_widgets(self):
        # Main container frame
        self.main_container = ttk.Frame(self)
        self.main_container.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Master password frame
        self.master_frame = ttk.Frame(self.main_container)
        self.master_frame.pack(fill='both', expand=True)
        
        # App title
        self.title_label = ttk.Label(
            self.master_frame, 
            text="SecurePass Manager", 
            font=TITLE_FONT,
            foreground=ACCENT_COLOR
        )
        self.title_label.pack(pady=(0, 20))
        
        # Master password entry
        self.master_label = ttk.Label(
            self.master_frame, 
            text="Enter Master Password:",
            font=LABEL_FONT
        )
        self.master_label.pack(pady=(0, 5))
        
        self.master_entry = ttk.Entry(
            self.master_frame, 
            show='•', 
            font=ENTRY_FONT,
            width=30
        )
        self.master_entry.pack(pady=5, ipady=8)
        self.setup_entry_context_menu(self.master_entry)
        
        # Unlock button
        self.submit_master_btn = ttk.Button(
            self.master_frame, 
            text="Unlock", 
            command=self.set_master_password
        )
        self.submit_master_btn.pack(pady=15, ipady=5, ipadx=20)
        
        # Warning label
        self.warning_label = ttk.Label(
            self.master_frame, 
            text="⚠WARNING: If you lose your master password, you won't be able\n"
                 "to recover your saved passwords. Use a strong, memorable password.",
            foreground=WARNING_COLOR, 
            font=(FONT_FAMILY, 11),
            justify='center'
        )
        self.warning_label.pack(pady=(20, 0))
        
        # Main application frame (hidden until master password is set)
        self.app_frame = ttk.Frame(self.main_container)
        
        # Results area with modern scrollbar
        self.results_frame = ttk.Frame(self.app_frame)
        self.results_frame.pack(fill='both', expand=True, pady=(0, 15))
        
        self.results_text = scrolledtext.ScrolledText(
            self.results_frame, 
            width=60, 
            height=15, 
            wrap=tk.WORD,
            bg=ENTRY_BG,
            fg=TEXT_COLOR, 
            font=ENTRY_FONT,
            insertbackground=TEXT_COLOR,
            highlightthickness=0,
            padx=10, 
            pady=10
        )
        self.results_text.pack(fill='both', expand=True)
        
        # Button grid
        self.button_frame = ttk.Frame(self.app_frame)
        self.button_frame.pack(fill='x', pady=(0, 10))
        
        # Button configuration
        buttons = [
            ("Add", self.add_credential, PRIMARY_COLOR),
            ("Search", self.search_credentials, PRIMARY_COLOR),
            ("Edit", self.edit_credential, PRIMARY_COLOR),
            ("Delete", self.delete_credential, WARNING_COLOR),
            ("Show All", self.show_all_urls, SECONDARY_COLOR),
            ("Generate", self.generate_password_gui, ACCENT_COLOR),
            ("Copy Login", self.copy_login, SECONDARY_COLOR),
            ("Copy Password", self.copy_password, SECONDARY_COLOR),
            ("Backup", self.backup_callback, SECONDARY_COLOR)
        ]
        
        # Create buttons in a 3x3 grid
        for i, (text, command, color) in enumerate(buttons):
            btn = ttk.Button(
                self.button_frame, 
                text=text, 
                command=command,
                style='Custom.TButton'
            )
            # Temporary styling - we'll configure this after
            btn.grid(
                row=i//3, 
                column=i%3, 
                padx=5, 
                pady=5, 
                sticky='nsew'
            )
            btn.configure(style=f'Custom{color}.TButton')
        
        # Configure grid weights
        for i in range(3):
            self.button_frame.columnconfigure(i, weight=1)
        
        # Bind Enter key to submit master password
        self.master_entry.bind('<Return>', lambda event: self.set_master_password())
        self.iterations_value = tk.IntVar()
        # ustaw początkową wartość z config, albo domyślnie 200000
        self.iterations_value.set(self.manager.iterations)

        # Etykieta informacyjna z wartością
        self.iterations_label_text = "Number of iterations (default 100000):"
        self.iterations_label = ttk.Label(
            self.app_frame, 
            text=f"{self.iterations_label_text} {self.iterations_value.get()}",
            font=LABEL_FONT
        )
        self.iterations_label.pack(pady=(10, 5))
        
        # Tworzymy ramkę
        self.iterations_frame = ttk.Frame(self.app_frame)
        self.iterations_frame.pack(pady=5, fill='x', expand=True)

        # Przyciski
        self.decrease_btn = ttk.Button(self.iterations_frame, text="−", width=3, command=self.decrease_iterations)
        self.decrease_btn.pack(side='left', padx=2)

        self.iterations_scale = ttk.Scale(
            self.iterations_frame,
            from_=10000,
            to=200000,
            orient='horizontal',
            variable=self.iterations_value
        )
        self.iterations_scale.pack(side='left', fill='x', expand=True)

        self.increase_btn = ttk.Button(self.iterations_frame, text="+", width=3, command=self.increase_iterations)
        self.increase_btn.pack(side='left', padx=2)

        # Podłącz trace do zmiany wartości
        self.iterations_value.trace_add('write', self.update_iterations_label)
        
        # Przycisk zapisu
        self.save_iterations_btn = ttk.Button(
            self.app_frame,
            text="Save",
            command=self.save_iterations
        )
        self.save_iterations_btn.pack(pady=10)
        
    def decrease_iterations(self):
        current = self.iterations_value.get()
        new_value = max(10000, int(current) - 1)
        self.iterations_value.set(new_value)

    def increase_iterations(self):
        current = self.iterations_value.get()
        new_value = min(200000, int(current) + 1)
        self.iterations_value.set(new_value)
     
    def update_iterations_label(self, *args):
        current_value = self.iterations_value.get()
        self.iterations_label.config(text=f"{self.iterations_label_text} {current_value}")

        
    def setup_entry_context_menu(self, entry_widget):
        """Setup right-click context menu for an entry widget"""
        def show_context_menu(event):
            context_menu.tk_popup(event.x_root, event.y_root)
        
        context_menu = tk.Menu(entry_widget, tearoff=0, bg=ENTRY_BG, fg=TEXT_COLOR)
        context_menu.add_command(
            label="Cut", 
            command=lambda: entry_widget.event_generate("<<Cut>>")
        )
        context_menu.add_command(
            label="Copy", 
            command=lambda: entry_widget.event_generate("<<Copy>>")
        )
        context_menu.add_command(
            label="Paste", 
            command=lambda: entry_widget.event_generate("<<Paste>>")
        )
        context_menu.add_separator()
        context_menu.add_command(
            label="Select All", 
            command=lambda: entry_widget.select_range(0, tk.END)
        )
        
        entry_widget.bind("<Button-3>", show_context_menu)  # Right-click
        entry_widget.bind("<Control-a>", lambda e: entry_widget.select_range(0, tk.END))
        entry_widget.bind("<Control-A>", lambda e: entry_widget.select_range(0, tk.END))
    
    def set_master_password(self):
        self.master_pass = self.master_entry.get()
        if len(self.master_pass) < 8:
            messagebox.showerror(
                "Invalid Password", 
                "Master password must be at least 8 characters."
            )
        else:
            self.master_frame.pack_forget()
            self.app_frame.pack(fill='both', expand=True)
            self.results_text.insert(tk.END, "Welcome to SecurePass Manager!\n\n")
            self.results_text.insert(tk.END, "Use the buttons above to manage your credentials.\n")
            self.results_text.configure(state='disabled')
    
    def generate_password_gui(self):
        generated_password = self.manager.generate_password()
        self.last_generated_password = generated_password
        self.results_text.configure(state='normal')
        self.results_text.delete('1.0', tk.END)
        self.results_text.insert(tk.END, "Generated Password:\n")
        self.results_text.insert(tk.END, f"\n{generated_password}\n\n")
        self.results_text.insert(tk.END, "Click 'Copy Password' to save this password.")
        self.results_text.configure(state='disabled')
    
    def add_credential(self):
        self.show_input_dialog("Add Credentials", ["URL/App Name", "Username", "Password"], self.add_callback)
    
    def search_credentials(self):
        self.show_input_dialog("Search Credentials", ["URL/App Name"], self.search_callback)
    
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
        dialog.geometry("250x{}".format(120 + len(fields)*75))
        
        frame = ttk.Frame(dialog)
        frame.pack(pady=20, padx=20, fill='both', expand=True)
        
        entries = []
        for field in fields:
            ttk.Label(frame, text=field).pack(pady=(10, 0))
            entry = ttk.Entry(frame, font=('Helvetica', 10))
            entry.pack(pady=5, ipady=3, fill='x')
            
            # Add right-click context menu to each entry field
            self.setup_entry_context_menu(entry)
            
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
        # Sprawdź czy hasło główne jest ustawione
        if not self.master_pass:
            return "ERROR: Master password not set. Please unlock the application first."
            
        result = self.manager.add(url, username, password, self.master_pass)
        
        # Jeśli błąd dotyczy braku config.json, pokaż przycisk ustawień
        if "set the iteration count first" in result:
            self.results_text.configure(state='normal')
            self.results_text.delete('1.0', tk.END)
            self.results_text.insert(tk.END, result)
            
            # Dodaj przycisk do przejścia do ustawień
            self.results_text.configure(state='normal')
            self.results_text.insert(tk.END, "\n\nClick here to set iterations: ")
            self.results_text.tag_config("link", foreground=ACCENT_COLOR, underline=1)
            self.results_text.tag_bind("link", "<Button-1>", lambda e: self.show_iterations_settings())
            self.results_text.insert(tk.END, "Set Iterations", "link")
            self.results_text.configure(state='disabled')
            return
            
        return result

    def show_iterations_settings(self):
        """Pokazuje panel ustawień iteracji"""
        self.iterations_label.pack(pady=(10, 5))
        self.iterations_scale.pack(pady=5, fill='x', expand=True)
        self.iterations_label_value.pack(pady=5)
        self.save_iterations_btn.pack(pady=10)
        # Przewiń do ustawień jeśli potrzeba
        self.canvas.yview_moveto(1)
    
    def search_callback(self, url):
        results = self.manager.search(self.master_pass, url)
        if results:
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
        if self.last_generated_password:
            self.clipboard_clear()
            self.clipboard_append(self.last_generated_password)
            self.results_text.configure(state='normal')
            self.results_text.delete('1.0', tk.END)
            self.results_text.insert(tk.END, "Generated password copied to clipboard!")
            self.results_text.configure(state='disabled')
        elif self.last_password:
            self.clipboard_clear()
            self.clipboard_append(self.last_password)
            self.results_text.configure(state='normal')
            self.results_text.delete('1.0', tk.END)
            self.results_text.insert(tk.END, "Stored password copied to clipboard!")
            self.results_text.configure(state='disabled')
        else:
            self.results_text.configure(state='normal')
            self.results_text.delete('1.0', tk.END)
            self.results_text.insert(tk.END, "No password available to copy!")
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