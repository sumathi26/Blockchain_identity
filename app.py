import hashlib
import json
from datetime import datetime
import qrcode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog, ttk
from PIL import Image, ImageTk
import ssl
import cv2
import numpy as np
from web3 import Web3
from eth_account import Account
import secrets

class IdentityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Blockchain Identity Verification")
        self.root.geometry("1000x800")
        
        # Initialize components
        self.blockchain = Blockchain()
        self.crypto = CryptoUtils()
        self.current_user = None
        self.current_qr_path = None
        self.current_qr_data = None
        
        # Email configuration - REPLACE WITH YOUR ACTUAL EMAIL CREDENTIALS
        self.email_config = {
            'sender_email': 'your.email@gmail.com',
            'sender_password': 'your_app_password',
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 465
        }
        
        # Create UI
        self.create_login_screen()

    def create_login_screen(self):
        """Create the login/registration screen"""
        self.clear_window()
        
        # Main container
        container = tk.Frame(self.root, padx=20, pady=20)
        container.pack(expand=True, fill="both")
        
        # Title
        tk.Label(container, text="Blockchain Identity Verification", 
                font=("Arial", 16, "bold")).pack(pady=20)
        
        # Login frame
        login_frame = tk.Frame(container)
        login_frame.pack(pady=20)
        
        # Email
        tk.Label(login_frame, text="Email:", font=("Arial", 11)).grid(row=0, column=0, sticky="e", pady=5)
        self.email_entry = tk.Entry(login_frame, width=30, font=("Arial", 11))
        self.email_entry.grid(row=0, column=1, pady=5, padx=5)
        
        # Password
        tk.Label(login_frame, text="Password:", font=("Arial", 11)).grid(row=1, column=0, sticky="e", pady=5)
        self.password_entry = tk.Entry(login_frame, width=30, show="*", font=("Arial", 11))
        self.password_entry.grid(row=1, column=1, pady=5, padx=5)
        
        # Buttons
        btn_frame = tk.Frame(container)
        btn_frame.pack(pady=20)
        
        tk.Button(btn_frame, text="Login", command=self.login, 
                 width=15, font=("Arial", 11)).pack(side="left", padx=10)
        tk.Button(btn_frame, text="Register", command=self.show_register_dialog,
                 width=15, font=("Arial", 11)).pack(side="left", padx=10)

    def show_register_dialog(self):
        """Show registration dialog with all credential fields"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Register New User")
        dialog.geometry("600x700")
        
        # Scrollable frame
        canvas = tk.Canvas(dialog)
        scrollbar = ttk.Scrollbar(dialog, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Personal Information
        personal_frame = ttk.LabelFrame(scrollable_frame, text="Personal Information", padding=10)
        personal_frame.pack(fill="x", pady=10, padx=10)
        
        fields = [
            ("Full Name", "name"),
            ("Date of Birth (DD/MM/YYYY)", "dob"),
            ("Gender", "gender"),
            ("Phone Number", "phone"),
            ("Email", "email"),
            ("Password", "password", True),
            ("Address", "address"),
            ("City", "city"),
            ("State", "state"),
            ("PIN Code", "pin"),
            ("Country", "country")
        ]
        
        self.reg_entries = {}
        for i, (label, field, *options) in enumerate(fields):
            ttk.Label(personal_frame, text=label+":").grid(row=i, column=0, sticky="e", pady=2)
            if options and options[0]:  # Password field
                entry = ttk.Entry(personal_frame, show="*")
            else:
                entry = ttk.Entry(personal_frame)
            entry.grid(row=i, column=1, pady=2, padx=5, sticky="ew")
            self.reg_entries[field] = entry
        
        # Government IDs
        govt_frame = ttk.LabelFrame(scrollable_frame, text="Government IDs", padding=10)
        govt_frame.pack(fill="x", pady=10, padx=10)
        
        govt_fields = [
            ("Aadhaar Number", "aadhaar"),
            ("PAN Number", "pan"),
            ("Passport Number", "passport"),
            ("Voter ID", "voter_id"),
            ("Driving License", "driving_license")
        ]
        
        for i, (label, field) in enumerate(govt_fields):
            ttk.Label(govt_frame, text=label+":").grid(row=i, column=0, sticky="e", pady=2)
            entry = ttk.Entry(govt_frame)
            entry.grid(row=i, column=1, pady=2, padx=5, sticky="ew")
            self.reg_entries[field] = entry
        
        # Register button
        ttk.Button(scrollable_frame, text="Register", command=lambda: self.register_user(dialog)).pack(pady=20)

    def register_user(self, dialog):
        """Handle user registration with all fields"""
        credentials = {
            'personal': {
                'name': self.reg_entries['name'].get(),
                'dob': self.reg_entries['dob'].get(),
                'gender': self.reg_entries['gender'].get(),
                'phone': self.reg_entries['phone'].get(),
                'address': self.reg_entries['address'].get(),
                'city': self.reg_entries['city'].get(),
                'state': self.reg_entries['state'].get(),
                'pin': self.reg_entries['pin'].get(),
                'country': self.reg_entries['country'].get()
            },
            'government_ids': {
                'aadhaar': self.reg_entries['aadhaar'].get(),
                'pan': self.reg_entries['pan'].get(),
                'passport': self.reg_entries['passport'].get(),
                'voter_id': self.reg_entries['voter_id'].get(),
                'driving_license': self.reg_entries['driving_license'].get()
            }
        }
        
        email = self.reg_entries['email'].get()
        password = self.reg_entries['password'].get()
        
        if self.blockchain.register_user(email, password, credentials):
            # Show Ethereum account info
            eth_account = self.blockchain.users[email]['eth_account']
            messagebox.showinfo(
                "Registration Successful",
                f"Account created!\n\nEthereum Address: {eth_account['address']}\n"
                f"Private Key: {eth_account['private_key']}\n\n"
                "Save this private key securely to access your Ethereum account."
            )
            dialog.destroy()
        else:
            messagebox.showerror("Error", "Registration failed. Email may already exist.")

    def login(self):
        """Handle user login"""
        email = self.email_entry.get()
        password = self.password_entry.get()
        
        if self.blockchain.verify_user(email, password):
            self.current_user = email
            self.create_dashboard()
        else:
            messagebox.showerror("Error", "Invalid email or password")

    def create_dashboard(self):
        """Create the main user dashboard"""
        self.clear_window()
        
        # Header
        header = tk.Frame(self.root, padx=10, pady=10, bg="#f0f0f0")
        header.pack(fill="x")
        
        tk.Label(header, text=f"Welcome, {self.current_user}", bg="#f0f0f0", 
                font=("Arial", 12, "bold")).pack(side="left")
        tk.Button(header, text="Logout", command=self.logout).pack(side="right")
        
        # Notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(expand=True, fill="both", padx=10, pady=10)
        
        # Share Credentials Tab
        share_tab = ttk.Frame(notebook)
        notebook.add(share_tab, text="Share Credentials")
        self.create_share_credentials_view(share_tab)
        
        # QR Code Tab
        qr_tab = ttk.Frame(notebook)
        notebook.add(qr_tab, text="QR Verification")
        self.create_qr_verification_view(qr_tab)
        
        # View Credentials Tab
        view_tab = ttk.Frame(notebook)
        notebook.add(view_tab, text="My Credentials")
        self.create_credentials_view(view_tab)
        
        # Ethereum Transactions Tab
        eth_tab = ttk.Frame(notebook)
        notebook.add(eth_tab, text="Ethereum Transactions")
        self.create_ethereum_transactions_view(eth_tab)

    def create_share_credentials_view(self, parent):
        """Create the share credentials tab"""
        share_frame = ttk.LabelFrame(parent, text="Share Your Credentials", padding=15)
        share_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        ttk.Label(share_frame, text="Recipient (Email or Ethereum Address):").grid(row=0, column=0, sticky="e", pady=5)
        self.recipient_entry = ttk.Entry(share_frame, width=50)
        self.recipient_entry.grid(row=0, column=1, pady=5, padx=5)
        
        ttk.Label(share_frame, text="Select Credentials to Share:").grid(row=1, column=0, sticky="ne", pady=5)
        
        # Credential selection checkboxes
        self.share_vars = {
            'personal_info': tk.BooleanVar(value=True),
            'aadhaar': tk.BooleanVar(),
            'pan': tk.BooleanVar(),
            'passport': tk.BooleanVar(),
            'voter_id': tk.BooleanVar(),
            'driving_license': tk.BooleanVar()
        }
        
        cb_frame = ttk.Frame(share_frame)
        cb_frame.grid(row=1, column=1, sticky="w", pady=5)
        
        ttk.Checkbutton(cb_frame, text="Personal Information", variable=self.share_vars['personal_info']).pack(anchor="w")
        ttk.Checkbutton(cb_frame, text="Aadhaar Number", variable=self.share_vars['aadhaar']).pack(anchor="w")
        ttk.Checkbutton(cb_frame, text="PAN Number", variable=self.share_vars['pan']).pack(anchor="w")
        ttk.Checkbutton(cb_frame, text="Passport Number", variable=self.share_vars['passport']).pack(anchor="w")
        ttk.Checkbutton(cb_frame, text="Voter ID", variable=self.share_vars['voter_id']).pack(anchor="w")
        ttk.Checkbutton(cb_frame, text="Driving License", variable=self.share_vars['driving_license']).pack(anchor="w")
        
        ttk.Button(share_frame, text="Share Credentials", command=self.share_credentials).grid(row=2, column=0, columnspan=2, pady=15)

    def create_qr_verification_view(self, parent):
        """Create the QR verification tab"""
        qr_frame = ttk.LabelFrame(parent, text="QR Code Verification", padding=15)
        qr_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # QR Display
        self.qr_image_label = ttk.Label(qr_frame)
        self.qr_image_label.pack(pady=10)
        
        btn_frame = ttk.Frame(qr_frame)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Generate QR Code", command=self.generate_qr).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Save QR Code", command=self.save_qr).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Verify QR Code", command=self.verify_qr_dialog).pack(side="left", padx=5)

    def create_credentials_view(self, parent):
        """Create the credentials viewing tab"""
        container = ttk.Frame(parent)
        container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Password verification
        verify_frame = ttk.Frame(container)
        verify_frame.pack(pady=20)
        
        ttk.Label(verify_frame, text="Enter your password to view credentials:").pack(side="left", padx=5)
        self.cred_password_entry = ttk.Entry(verify_frame, show="*")
        self.cred_password_entry.pack(side="left", padx=5)
        ttk.Button(verify_frame, text="View", command=self.show_credentials).pack(side="left", padx=5)
        
        # Credentials display area
        self.credentials_display = tk.Text(container, wrap="word", state="disabled", height=20, padx=10, pady=10)
        self.credentials_display.pack(fill="both", expand=True)
        
        # Configure tags for formatting
        self.credentials_display.tag_config("header", font=("Arial", 12, "bold"), foreground="blue")
        self.credentials_display.tag_config("label", font=("Arial", 10, "bold"))

    def create_ethereum_account_view(self, parent):
        """Create UI for Ethereum account management"""
        frame = ttk.LabelFrame(parent, text="Ethereum Account", padding=10)
        frame.pack(fill="x", pady=10, padx=10)
        
        # Current address display
        self.eth_address_var = tk.StringVar()
        ttk.Label(frame, text="Your Address:").grid(row=0, column=0, sticky="e")
        ttk.Entry(frame, textvariable=self.eth_address_var, state="readonly", width=50).grid(row=0, column=1, padx=5)
        ttk.Button(frame, text="Copy", command=self.copy_eth_address).grid(row=0, column=2)
        
        # Private key entry (hidden by default)
        self.show_priv_key = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame, text="Show Private Key", variable=self.show_priv_key, 
                       command=self.toggle_private_key).grid(row=1, column=0, sticky="e")
        
        self.priv_key_entry = ttk.Entry(frame, show="*", width=50)
        self.priv_key_entry.grid(row=1, column=1, padx=5)
        
        # Import/Export buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=2, column=0, columnspan=3, pady=10)
        
        ttk.Button(btn_frame, text="Import Account", command=self.import_eth_account).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Generate New", command=self.generate_eth_account).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Export Keystore", command=self.export_keystore).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Manual Entry", command=self.manual_eth_entry).pack(side="left", padx=5)

    def create_ethereum_transactions_view(self, parent):
        """Create the Ethereum transactions viewing tab"""
        container = ttk.Frame(parent)
        container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Address management
        self.create_ethereum_account_view(container)
        
        # Transaction controls
        control_frame = ttk.Frame(container)
        control_frame.pack(fill="x", pady=10)
        
        ttk.Button(control_frame, text="Send ETH", command=self.show_send_eth_dialog).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Refresh", command=self.refresh_eth_transactions).pack(side="left", padx=5)
        ttk.Button(control_frame, text="View All TXs", command=self.view_all_transactions).pack(side="left", padx=5)
        
        # Transaction history treeview with more columns
        self.eth_transactions_tree = ttk.Treeview(container, 
            columns=('hash', 'type', 'from_to', 'value', 'status', 'time'), 
            show='headings')
        
        # Configure columns
        self.eth_transactions_tree.heading('hash', text='Tx Hash')
        self.eth_transactions_tree.heading('type', text='Type')
        self.eth_transactions_tree.heading('from_to', text='From/To')
        self.eth_transactions_tree.heading('value', text='Value (ETH)')
        self.eth_transactions_tree.heading('status', text='Status')
        self.eth_transactions_tree.heading('time', text='Time')
        
        self.eth_transactions_tree.column('hash', width=150)
        self.eth_transactions_tree.column('type', width=50)
        self.eth_transactions_tree.column('from_to', width=150)
        self.eth_transactions_tree.column('value', width=80)
        self.eth_transactions_tree.column('status', width=50)
        self.eth_transactions_tree.column('time', width=120)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=self.eth_transactions_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.eth_transactions_tree.configure(yscrollcommand=scrollbar.set)
        
        self.eth_transactions_tree.pack(fill="both", expand=True)
        
        # Context menu for tx details
        self.tx_context_menu = tk.Menu(self.root, tearoff=0)
        self.tx_context_menu.add_command(label="View Details", command=self.show_tx_details)
        self.eth_transactions_tree.bind("<Button-3>", self.show_tx_context_menu)
        
        # Load initial transactions
        self.refresh_eth_transactions()

    def manual_eth_entry(self):
        """Allow manual entry of Ethereum address and private key"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Manual Ethereum Entry")
        dialog.geometry("500x300")
        
        ttk.Label(dialog, text="Ethereum Address:").pack(pady=5)
        address_entry = ttk.Entry(dialog, width=50)
        address_entry.pack(pady=5)
        
        ttk.Label(dialog, text="Private Key:").pack(pady=5)
        priv_key_entry = ttk.Entry(dialog, show="*", width=50)
        priv_key_entry.pack(pady=5)
        
        def save_entry():
            address = address_entry.get().strip()
            priv_key = priv_key_entry.get().strip()
            
            if not address or not priv_key:
                messagebox.showerror("Error", "Both fields are required")
                return
                
            try:
                # Validate the private key
                account = Account.from_key(priv_key)
                
                # Verify the address matches
                if account.address.lower() != address.lower():
                    messagebox.showerror("Error", "Private key doesn't match the address")
                    return
                    
                # Save the account
                if self.current_user not in self.blockchain.users:
                    self.blockchain.users[self.current_user] = {}
                    
                self.blockchain.users[self.current_user]['eth_account'] = {
                    'address': account.address,
                    'private_key': priv_key
                }
                self.update_eth_display()
                dialog.destroy()
                messagebox.showinfo("Success", "Ethereum account saved successfully!")
                self.refresh_eth_transactions()
            except ValueError as e:
                messagebox.showerror("Error", f"Invalid private key: {str(e)}")
        
        ttk.Button(dialog, text="Save", command=save_entry).pack(pady=10)

    def toggle_private_key(self):
        """Toggle private key visibility"""
        show = self.show_priv_key.get()
        self.priv_key_entry.config(show="" if show else "*")
        
        if show and self.current_user:
            user = self.blockchain.users.get(self.current_user, {})
            if user.get('eth_account'):
                self.priv_key_entry.delete(0, "end")
                self.priv_key_entry.insert(0, user['eth_account']['private_key'])

    def copy_eth_address(self):
        """Copy Ethereum address to clipboard"""
        if self.current_user and self.blockchain.users.get(self.current_user, {}).get('eth_account'):
            addr = self.blockchain.users[self.current_user]['eth_account']['address']
            self.root.clipboard_clear()
            self.root.clipboard_append(addr)
            messagebox.showinfo("Copied", "Ethereum address copied to clipboard")

    def import_eth_account(self):
        """Import existing Ethereum account"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Import Ethereum Account")
        
        ttk.Label(dialog, text="Private Key:").pack(pady=5)
        priv_key_entry = ttk.Entry(dialog, show="*", width=50)
        priv_key_entry.pack(pady=5)
        
        def do_import():
            priv_key = priv_key_entry.get()
            try:
                account = Account.from_key(priv_key)
                if self.current_user not in self.blockchain.users:
                    self.blockchain.users[self.current_user] = {}
                    
                self.blockchain.users[self.current_user]['eth_account'] = {
                    'address': account.address,
                    'private_key': priv_key
                }
                self.update_eth_display()
                dialog.destroy()
                messagebox.showinfo("Success", "Account imported successfully!")
                self.refresh_eth_transactions()
            except:
                messagebox.showerror("Error", "Invalid private key")
        
        ttk.Button(dialog, text="Import", command=do_import).pack(pady=10)

    def generate_eth_account(self):
        """Generate new Ethereum account"""
        if messagebox.askyesno("Confirm", "Generate new Ethereum account?\nThis will replace any existing account."):
            eth_account = self.blockchain.create_ethereum_account()
            if self.current_user not in self.blockchain.users:
                self.blockchain.users[self.current_user] = {}
                
            self.blockchain.users[self.current_user]['eth_account'] = eth_account
            self.update_eth_display()
            messagebox.showinfo("New Account", 
                              f"Account created!\n\nAddress: {eth_account['address']}\n"
                              f"Private Key: {eth_account['private_key']}\n\n"
                              "Save this private key securely!")
            self.refresh_eth_transactions()

    def export_keystore(self):
        """Export account as encrypted keystore"""
        if not self.current_user or not self.blockchain.users.get(self.current_user, {}).get('eth_account'):
            messagebox.showerror("Error", "No Ethereum account found")
            return
        
        password = simpledialog.askstring("Password", "Set keystore password:", show="*")
        if not password:
            return
        
        try:
            priv_key = self.blockchain.users[self.current_user]['eth_account']['private_key']
            keyfile = Account.encrypt(priv_key, password)
            
            file_path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("Keystore File", "*.json")]
            )
            
            if file_path:
                with open(file_path, 'w') as f:
                    json.dump(keyfile, f)
                messagebox.showinfo("Success", f"Keystore saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {str(e)}")

    def update_eth_display(self):
        """Update Ethereum address display"""
        if self.current_user and self.blockchain.users.get(self.current_user, {}).get('eth_account'):
            addr = self.blockchain.users[self.current_user]['eth_account']['address']
            self.eth_address_var.set(addr)
            self.priv_key_entry.delete(0, "end")
            self.priv_key_entry.insert(0, self.blockchain.users[self.current_user]['eth_account']['private_key'])

    def show_send_eth_dialog(self):
        """Dialog for sending ETH transactions"""
        if not self.current_user or not self.blockchain.users.get(self.current_user, {}).get('eth_account'):
            messagebox.showerror("Error", "No Ethereum account configured")
            return
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Send Ethereum Transaction")
        dialog.geometry("500x400")
        
        ttk.Label(dialog, text="Recipient Address:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        recipient_entry = ttk.Entry(dialog, width=50)
        recipient_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(dialog, text="Amount (ETH):").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        amount_entry = ttk.Entry(dialog)
        amount_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        
        ttk.Label(dialog, text="Gas Price (Gwei):").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        gas_price_entry = ttk.Entry(dialog)
        gas_price_entry.insert(0, "50")  # Default gas price
        gas_price_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        
        ttk.Label(dialog, text="Gas Limit:").grid(row=3, column=0, padx=5, pady=5, sticky="e")
        gas_limit_entry = ttk.Entry(dialog)
        gas_limit_entry.insert(0, "21000")  # Default gas limit for simple transfers
        gas_limit_entry.grid(row=3, column=1, padx=5, pady=5, sticky="w")
        
        ttk.Label(dialog, text="Data (Optional):").grid(row=4, column=0, padx=5, pady=5, sticky="ne")
        data_entry = tk.Text(dialog, height=4, width=40)
        data_entry.grid(row=4, column=1, padx=5, pady=5)
        
        def send_transaction():
            recipient = recipient_entry.get().strip()
            amount = amount_entry.get().strip()
            gas_price = gas_price_entry.get().strip()
            gas_limit = gas_limit_entry.get().strip()
            data = data_entry.get("1.0", "end").strip()
            
            if not recipient or not amount:
                messagebox.showerror("Error", "Recipient and amount are required")
                return
            
            try:
                # Validate inputs
                if not Web3.is_address(recipient):
                    messagebox.showerror("Error", "Invalid recipient address")
                    return
                
                eth_amount = float(amount)
                gas_price_wei = Web3.to_wei(gas_price, 'gwei')
                gas_limit_int = int(gas_limit)
                
                tx_hash = self.blockchain.send_ethereum_transaction(
                    self.current_user,
                    recipient,
                    data,
                    eth_amount=eth_amount,
                    gas_price=gas_price_wei,
                    gas_limit=gas_limit_int)
                
                if tx_hash:
                    messagebox.showinfo("Success", f"Transaction sent!\nTX Hash: {tx_hash}")
                    self.refresh_eth_transactions()
                    dialog.destroy()
                else:
                    messagebox.showerror("Error", "Failed to send transaction")
            except ValueError as e:
                messagebox.showerror("Error", f"Invalid input: {str(e)}")
            except Exception as e:
                messagebox.showerror("Error", f"Transaction failed: {str(e)}")
        
        ttk.Button(dialog, text="Send", command=send_transaction).grid(row=5, column=1, pady=10, sticky="e")

    def refresh_eth_transactions(self):
        """Refresh Ethereum transaction history with more details"""
        if not self.current_user:
            return
            
        # Clear existing data
        for item in self.eth_transactions_tree.get_children():
            self.eth_transactions_tree.delete(item)
        
        user_data = self.blockchain.users.get(self.current_user, {})
        if not user_data or 'eth_account' not in user_data:
            return
            
        address = user_data['eth_account']['address']
        
        try:
            # Get latest block number
            latest_block = self.blockchain.w3.eth.block_number
            
            # Scan recent blocks for transactions (last 50 blocks for demo)
            for block_num in range(max(0, latest_block-50), latest_block+1):
                block = self.blockchain.w3.eth.get_block(block_num, full_transactions=True)
                for tx in block.transactions:
                    # Check if this transaction involves our address
                    if tx['from'].lower() == address.lower() or (tx['to'] and tx['to'].lower() == address.lower()):
                        # Determine transaction type
                        tx_type = "IN" if tx['to'] and tx['to'].lower() == address.lower() else "OUT"
                        
                        # Format value in ETH
                        value = float(self.blockchain.w3.from_wei(tx['value'], 'ether'))
                        
                        # Get transaction status
                        receipt = self.blockchain.w3.eth.get_transaction_receipt(tx.hash)
                        status = "✓" if receipt and receipt['status'] == 1 else "✗"
                        
                        # Get timestamp
                        timestamp = datetime.fromtimestamp(block.timestamp).strftime('%Y-%m-%d %H:%M')
                        
                        # Insert into treeview
                        self.eth_transactions_tree.insert('', 'end', 
                            values=(
                                tx.hash.hex()[:10] + "...",  # Shortened hash
                                tx_type,
                                tx['from'][:10] + "..." if tx_type == "IN" else tx['to'][:10] + "...",
                                f"{value:.6f}",
                                status,
                                timestamp
                            ),
                            tags=("incoming" if tx_type == "IN" else "outgoing"))
        
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch transactions: {str(e)}")

    def view_all_transactions(self):
        """View all transactions for the current address in a new window"""
        if not self.current_user or not self.blockchain.users.get(self.current_user, {}).get('eth_account'):
            messagebox.showerror("Error", "No Ethereum account configured")
            return
        
        address = self.blockchain.users[self.current_user]['eth_account']['address']
        
        try:
            # Create a new window for all transactions
            tx_window = tk.Toplevel(self.root)
            tx_window.title(f"All Transactions for {address[:10]}...")
            tx_window.geometry("1000x600")
            
            # Create a treeview with scrollbars
            frame = ttk.Frame(tx_window)
            frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            tree = ttk.Treeview(frame, 
                              columns=('hash', 'block', 'from', 'to', 'value', 'gas', 'status', 'time'), 
                              show='headings')
            
            # Configure columns
            tree.heading('hash', text='Tx Hash')
            tree.heading('block', text='Block')
            tree.heading('from', text='From')
            tree.heading('to', text='To')
            tree.heading('value', text='Value (ETH)')
            tree.heading('gas', text='Gas Used')
            tree.heading('status', text='Status')
            tree.heading('time', text='Time')
            
            tree.column('hash', width=150)
            tree.column('block', width=80)
            tree.column('from', width=150)
            tree.column('to', width=150)
            tree.column('value', width=80)
            tree.column('gas', width=80)
            tree.column('status', width=50)
            tree.column('time', width=120)
            
            # Add scrollbars
            v_scroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
            h_scroll = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
            tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
            
            tree.grid(row=0, column=0, sticky="nsew")
            v_scroll.grid(row=0, column=1, sticky="ns")
            h_scroll.grid(row=1, column=0, sticky="ew")
            
            frame.grid_rowconfigure(0, weight=1)
            frame.grid_columnconfigure(0, weight=1)
            
            # Get all transactions for this address
            transactions = []
            latest_block = self.blockchain.w3.eth.block_number
            
            # Scan all blocks (this is slow for large block ranges - in production use an indexer)
            for block_num in range(0, latest_block+1):
                block = self.blockchain.w3.eth.get_block(block_num, full_transactions=True)
                for tx in block.transactions:
                    if tx['from'].lower() == address.lower() or (tx['to'] and tx['to'].lower() == address.lower()):
                        transactions.append((block_num, tx))
            
            # Sort by block number (newest first)
            transactions.sort(key=lambda x: x[0], reverse=True)
            
            # Add to treeview
            for block_num, tx in transactions:
                receipt = self.blockchain.w3.eth.get_transaction_receipt(tx.hash)
                value = float(self.blockchain.w3.from_wei(tx['value'], 'ether'))
                status = "✓" if receipt and receipt['status'] == 1 else "✗"
                timestamp = datetime.fromtimestamp(
                    self.blockchain.w3.eth.get_block(block_num).timestamp
                ).strftime('%Y-%m-%d %H:%M')
                
                tree.insert('', 'end', 
                          values=(
                              tx.hash.hex()[:10] + "...",
                              block_num,
                              tx['from'][:10] + "...",
                              tx['to'][:10] + "..." if tx['to'] else "Contract",
                              f"{value:.6f}",
                              receipt.gasUsed if receipt else "Pending",
                              status,
                              timestamp
                          ))
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load transactions: {str(e)}")

    def show_tx_context_menu(self, event):
        """Show context menu for transaction right-click"""
        item = self.eth_transactions_tree.identify_row(event.y)
        if item:
            self.eth_transactions_tree.selection_set(item)
            self.tx_context_menu.post(event.x_root, event.y_root)

    def show_tx_details(self):
        """Show detailed transaction information"""
        selected = self.eth_transactions_tree.selection()
        if not selected:
            return
            
        tx_hash = self.eth_transactions_tree.item(selected[0])['values'][0]
        
        try:
            # Find the full hash (we stored shortened version in the tree)
            full_hash = None
            address = self.blockchain.users[self.current_user]['eth_account']['address']
            
            # Check recent blocks for the full hash
            latest_block = self.blockchain.w3.eth.block_number
            for block_num in range(max(0, latest_block-50), latest_block+1):
                block = self.blockchain.w3.eth.get_block(block_num, full_transactions=True)
                for tx in block.transactions:
                    if tx.hash.hex().startswith(tx_hash.replace("...", "")):
                        full_hash = tx.hash
                        break
                if full_hash:
                    break
            
            if not full_hash:
                messagebox.showerror("Error", "Could not find full transaction hash")
                return
                
            tx = self.blockchain.w3.eth.get_transaction(full_hash)
            receipt = self.blockchain.w3.eth.get_transaction_receipt(full_hash)
            
            details = (
                f"Transaction Hash: {full_hash.hex()}\n"
                f"From: {tx['from']}\n"
                f"To: {tx['to'] if tx['to'] else 'Contract Creation'}\n"
                f"Value: {self.blockchain.w3.from_wei(tx['value'], 'ether')} ETH\n"
                f"Gas Price: {self.blockchain.w3.from_wei(tx['gasPrice'], 'gwei')} Gwei\n"
                f"Gas Used: {receipt['gasUsed'] if receipt else 'Pending'}\n"
                f"Block: {tx['blockNumber'] if 'blockNumber' in tx else 'Pending'}\n"
                f"Timestamp: {datetime.fromtimestamp(self.blockchain.w3.eth.get_block(tx['blockNumber']).timestamp) if 'blockNumber' in tx else 'Pending'}\n"
                f"Data: {tx['input'] or 'None'}"
            )
            
            messagebox.showinfo("Transaction Details", details)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get details: {str(e)}")

    def show_credentials(self):
        """Show the user's credentials after password verification"""
        password = self.cred_password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter your password")
            return
            
        if not self.blockchain.verify_user(self.current_user, password):
            messagebox.showerror("Error", "Invalid password")
            return
            
        user_data = self.blockchain.users[self.current_user]
        encrypted_data = user_data['encrypted_credentials']
        key = user_data['key']
        
        try:
            decrypted_data = self.crypto.decrypt_data(encrypted_data, key)
            credentials = json.loads(decrypted_data)
            
            # Clear and update display
            self.credentials_display.config(state="normal")
            self.credentials_display.delete(1.0, "end")
            
            # Personal Information
            self.credentials_display.insert("end", "Personal Information\n", "header")
            for field, value in credentials['personal'].items():
                self.credentials_display.insert("end", f"{field.replace('_', ' ').title()}: ", "label")
                self.credentials_display.insert("end", f"{value}\n")
            
            # Government IDs
            self.credentials_display.insert("end", "\nGovernment IDs\n", "header")
            for field, value in credentials['government_ids'].items():
                self.credentials_display.insert("end", f"{field.replace('_', ' ').title()}: ", "label")
                self.credentials_display.insert("end", f"{value}\n")
            
            self.credentials_display.config(state="disabled")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt credentials: {str(e)}")

    def send_email(self, recipient, subject, body):
        """Send an email with the given content"""
        try:
            # Create message container
            msg = MIMEMultipart()
            msg['From'] = self.email_config['sender_email']
            msg['To'] = recipient
            msg['Subject'] = subject
            
            # Add body to email
            msg.attach(MIMEText(body, 'plain'))
            
            # Create secure SSL context
            context = ssl.create_default_context()
            
            # Try to log in to server and send email
            with smtplib.SMTP_SSL(
                self.email_config['smtp_server'], 
                self.email_config['smtp_port'], 
                context=context
            ) as server:
                server.login(
                    self.email_config['sender_email'], 
                    self.email_config['sender_password']
                )
                server.sendmail(
                    self.email_config['sender_email'], 
                    recipient, 
                    msg.as_string()
                )
            return True
        except Exception as e:
            print(f"Failed to send email: {str(e)}")
            return False

    def share_credentials(self):
        """Share selected credentials with another user"""
        recipient = self.recipient_entry.get()
        if not recipient:
            messagebox.showerror("Error", "Please enter recipient email or Ethereum address")
            return
        
        # Check if recipient is Ethereum address
        is_eth_address = False
        if self.blockchain.w3.is_address(recipient):
            is_eth_address = True
        elif recipient not in self.blockchain.users:
            messagebox.showerror("Error", "Recipient not found")
            return
        
        password = simpledialog.askstring("Password", "Enter your password:", parent=self.root)
        if not password or not self.blockchain.verify_user(self.current_user, password):
            messagebox.showerror("Error", "Invalid password")
            return
            
        user_data = self.blockchain.users[self.current_user]
        encrypted_data = user_data['encrypted_credentials']
        key = user_data['key']
        
        try:
            decrypted_data = self.crypto.decrypt_data(encrypted_data, key)
            all_credentials = json.loads(decrypted_data)
            
            # Filter credentials based on selection
            shared_credentials = {}
            
            if self.share_vars['personal_info'].get():
                shared_credentials['personal'] = all_credentials['personal']
            
            govt_ids = {}
            for field in ['aadhaar', 'pan', 'passport', 'voter_id', 'driving_license']:
                if self.share_vars[field].get():
                    govt_ids[field] = all_credentials['government_ids'][field]
            
            if govt_ids:
                shared_credentials['government_ids'] = govt_ids
            
            if not shared_credentials:
                messagebox.showerror("Error", "No credentials selected to share")
                return
            
            # Format the message
            message = "Shared Credentials:\n\n"
            if 'personal' in shared_credentials:
                message += "Personal Information:\n"
                for field, value in shared_credentials['personal'].items():
                    message += f"  {field.replace('_', ' ').title()}: {value}\n"
            
            if 'government_ids' in shared_credentials:
                message += "\nGovernment IDs:\n"
                for field, value in shared_credentials['government_ids'].items():
                    message += f"  {field.replace('_', ' ').title()}: {value}\n"
            
            # Send to Ethereum if recipient is address
            if is_eth_address:
                tx_hash = self.blockchain.send_ethereum_transaction(
                    self.current_user,
                    recipient,
                    message  # The formatted credential data
                )
                
                if tx_hash:
                    messagebox.showinfo("Success", 
                        f"Credentials sent to Ethereum address!\nTransaction Hash: {tx_hash}")
                    self.refresh_eth_transactions()
                else:
                    messagebox.showerror("Error", "Failed to send to Ethereum")
            else:
                # Existing email sending code
                if self.send_email(recipient, "Identity Credentials Shared", message):
                    messagebox.showinfo("Success", f"Credentials successfully sent to {recipient}")
                    self.blockchain.add_transaction(self.current_user, recipient, "Credentials shared")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to process credentials: {str(e)}")

    def generate_qr(self):
        """Generate QR code for verification and store the data"""
        password = simpledialog.askstring("Password", "Enter your password:", parent=self.root)
        if not password or not self.blockchain.verify_user(self.current_user, password):
            messagebox.showerror("Error", "Invalid password")
            return
            
        qr_path, qr_data = self.blockchain.generate_qr(self.current_user, password)
        if qr_path:
            # Store QR data for verification
            self.current_qr_data = qr_data
            
            # Display QR code
            img = Image.open(qr_path)
            img.thumbnail((300, 300))
            photo = ImageTk.PhotoImage(img)
            self.qr_image_label.config(image=photo)
            self.qr_image_label.image = photo
            self.current_qr_path = qr_path
            
            # Show the verification code for testing purposes
            messagebox.showinfo(
                "QR Code Generated", 
                f"QR code generated successfully.\n\nVerification code: {qr_data}"
            )
        else:
            messagebox.showerror("Error", "Failed to generate QR code")

    def save_qr(self):
        """Save the generated QR code to a file"""
        if not hasattr(self, 'current_qr_path') or not self.current_qr_path:
            messagebox.showerror("Error", "No QR code generated to save")
            return
            
        initial_file = os.path.basename(self.current_qr_path)
        file_path = filedialog.asksaveasfilename(
            title="Save QR Code",
            initialfile=initial_file,
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                img = Image.open(self.current_qr_path)
                img.save(file_path)
                messagebox.showinfo("Success", f"QR code saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save QR code: {str(e)}")

    def verify_qr_dialog(self):
        """Dialog for QR code verification using OpenCV"""
        file_path = filedialog.askopenfilename(
            title="Select QR Code Image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                # Read the image using OpenCV
                img = cv2.imread(file_path)
                
                # Initialize QR code detector
                detector = cv2.QRCodeDetector()
                
                # Detect and decode QR code
                data, vertices, _ = detector.detectAndDecode(img)
                
                if not data:
                    messagebox.showerror("Error", "No QR code found in the image")
                    return
                
                # Verify the QR code data with blockchain
                if self.blockchain.verify_qr(data):
                    # Get user email from the QR data
                    qr_json = json.loads(data)
                    email = qr_json['email']
                    
                    # Get user details to display
                    user_data = self.blockchain.users.get(email, {})
                    if user_data:
                        # Format verification message
                        verification_msg = (
                            "Verification successful!\n\n"
                            f"Identity verified for: {email}\n"
                            f"Verification timestamp: {qr_json.get('timestamp', 'Unknown')}"
                        )
                        
                        messagebox.showinfo("Verification Success", verification_msg)
                    else:
                        messagebox.showinfo("Verification Success", 
                                          "QR code is valid but user details not found")
                else:
                    messagebox.showerror("Error", "Verification failed\n\nQR code is invalid or expired")
                    
            except json.JSONDecodeError:
                messagebox.showerror("Error", "Invalid QR code format")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to process QR code: {str(e)}")

    def logout(self):
        """Handle user logout"""
        self.current_user = None
        self.create_login_screen()

    def clear_window(self):
        """Clear all widgets from the window"""
        for widget in self.root.winfo_children():
            widget.destroy()

class Blockchain:
    def __init__(self):
        self.chain = []
        self.users = {}
        self.create_block(proof=1, previous_hash='0')
        
        # Ethereum integration
        self.w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))  # Ganache
        self.chain_id = 1337  # Ganache chain ID
        
        if not self.w3.is_connected():
            print("Warning: Failed to connect to Ganache. Ethereum features will be disabled.")
    
    def create_block(self, proof, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(datetime.now()),
            'proof': proof,
            'previous_hash': previous_hash,
            'transactions': []
        }
        self.chain.append(block)
        return block
    
    def get_previous_block(self):
        return self.chain[-1]
    
    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        while not check_proof:
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof
    
    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()
    
    def add_transaction(self, sender, recipient, data):
        """Add transaction to blockchain and Ethereum"""
        previous_block = self.get_previous_block()
        
        # Add to our local blockchain
        tx = {
            'sender': sender,
            'recipient': recipient,
            'data': data,
            'timestamp': str(datetime.now())
        }
        previous_block['transactions'].append(tx)
        
        # Also send to Ethereum if recipient is an Ethereum address
        if sender in self.users and 'eth_account' in self.users[sender] and self.w3.is_address(recipient):
            self.send_ethereum_transaction(
                sender,
                recipient,
                f"Credential shared: {data[:50]}..."  # Truncate long data
            )
        
        return previous_block['index']

    def create_ethereum_account(self):
        """Create a new Ethereum account for a user"""
        private_key = secrets.token_hex(32)
        account = Account.from_key(private_key)
        return {
            'address': account.address,
            'private_key': private_key
        }

    def send_ethereum_transaction(self, sender_email, recipient_address, data="", eth_amount=0, gas_price=None, gas_limit=None):
        """Send transaction to Ethereum blockchain"""
        if sender_email not in self.users:
            return False
            
        user = self.users[sender_email]
        if 'eth_account' not in user:
            return False
            
        # Prepare transaction
        nonce = self.w3.eth.get_transaction_count(user['eth_account']['address'])
        
        tx = {
            'chainId': self.chain_id,
            'to': recipient_address,
            'nonce': nonce,
            'gas': gas_limit if gas_limit else 200000,
            'gasPrice': gas_price if gas_price else self.w3.to_wei('50', 'gwei'),
            'value': self.w3.to_wei(eth_amount, 'ether'),
            'data': self.w3.to_hex(text=data)
        }
        
        # Estimate gas if sending data
        if data:
            try:
                tx['gas'] = self.w3.eth.estimate_gas(tx)
            except:
                pass
        
        # Sign and send
        try:
            signed_tx = self.w3.eth.account.sign_transaction(
                tx, 
                user['eth_account']['private_key']
            )
            
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            return tx_hash.hex()
        except Exception as e:
            print(f"Transaction error: {str(e)}")
            return False
    
    def register_user(self, email, password, credentials):
        if email in self.users:
            return False
        
        # Create Ethereum account
        eth_account = self.create_ethereum_account()
        
        key = CryptoUtils.generate_key()
        encrypted_credentials = CryptoUtils.encrypt_data(json.dumps(credentials), key)
        
        self.users[email] = {
            'password': hashlib.sha256(password.encode()).hexdigest(),
            'encrypted_credentials': encrypted_credentials,
            'key': key,
            'verifications': [],
            'eth_account': eth_account  # Store Ethereum account
        }
        
        self.add_transaction("System", email, "User registered")
        return True
    
    def verify_user(self, email, password):
        if email not in self.users:
            return False
        stored_hash = self.users[email]['password']
        return hashlib.sha256(password.encode()).hexdigest() == stored_hash
    
    def share_credentials(self, sender_email, sender_password, recipient_email):
        # This is now handled in the IdentityApp class with more features
        return False
    
    def generate_qr(self, email, password):
        if not self.verify_user(email, password):
            return None, None
        
        verification_token = hashlib.sha256(get_random_bytes(16)).hexdigest()
        self.users[email]['verifications'].append(verification_token)
        
        qr_data = {
            'email': email,
            'token': verification_token,
            'timestamp': str(datetime.now())
        }
        
        json_data = json.dumps(qr_data)
        
        # Create QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(json_data)
        qr.make(fit=True)
        img = qr.make_image(fill='black', back_color='white')
        
        # Save QR code
        if not os.path.exists('qrcodes'):
            os.makedirs('qrcodes')
        img_path = f'qrcodes/{email}_{verification_token[:5]}.png'
        img.save(img_path)
        
        return img_path, json_data
    
    def verify_qr(self, qr_data):
        try:
            data = json.loads(qr_data)
            email = data['email']
            token = data['token']
            
            if email in self.users and token in self.users[email]['verifications']:
                self.users[email]['verifications'].remove(token)
                return True
            return False
        except:
            return False

class CryptoUtils:
    @staticmethod
    def generate_key():
        return get_random_bytes(16)  # AES-128
    
    @staticmethod
    def encrypt_data(data, key):
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
        iv = cipher.iv
        return iv + ct_bytes
    
    @staticmethod
    def decrypt_data(encrypted_data, key):
        iv = encrypted_data[:16]
        ct = encrypted_data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode()

if __name__ == "__main__":
    root = tk.Tk()
    app = IdentityApp(root)
    root.mainloop()