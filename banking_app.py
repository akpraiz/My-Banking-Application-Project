#!/usr/bin/env python3
"""
CLI Banking Application with "Go Back / Exit" functionality
- sqlite3 for persistence
- PBKDF2-HMAC-SHA256 password hashing with salt
- Input validations and user-friendly navigation
"""

import sqlite3
import re
import secrets
import hashlib
import time
from getpass import getpass
from datetime import datetime

DB_FILE = "bank.db"
MIN_OPENING_DEPOSIT = 2000.0
PBKDF2_ITERATIONS = 100_000

# -----------------------
# Utility Functions
# -----------------------

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            account_number TEXT NOT NULL UNIQUE,
            balance REAL NOT NULL DEFAULT 0.0,
            created_at TEXT NOT NULL
        );
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            amount REAL NOT NULL,
            timestamp TEXT NOT NULL,
            balance_before REAL NOT NULL,
            balance_after REAL NOT NULL,
            description TEXT,
            counterparty_account TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """)
        conn.commit()

def hash_password(password: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return dk.hex()

def generate_salt_hex() -> str:
    return secrets.token_hex(16)

def generate_account_number(conn) -> str:
    cursor = conn.cursor()
    while True:
        num = secrets.randbelow(90_000_000) + 10_000_000
        acct = str(num)
        exists = cursor.execute("SELECT 1 FROM users WHERE account_number = ?", (acct,)).fetchone()
        if not exists:
            return acct

# -----------------------
# Validation Helpers
# -----------------------

def validate_full_name(name: str):
    if not name.strip():
        return False, "Full name cannot be blank."
    if name.lower() in ("back", "exit"):
        return "back", None
    if len(name) < 4:
        return False, "Full name must be at least 4 characters."
    if not re.fullmatch(r"[A-Za-z ]+", name):
        return False, "Name may only contain alphabetic characters and spaces."
    return True, name.strip()

def validate_username(username: str):
    if not username.strip():
        return False, "Username cannot be blank."
    if username.lower() in ("back", "exit"):
        return "back", None
    if not (3 <= len(username) <= 20):
        return False, "Username must be between 3 and 20 characters."
    if not re.fullmatch(r"[A-Za-z0-9_]+", username):
        return False, "Username may only contain letters, numbers and underscores."
    return True, username.strip()

def validate_password_rules(password: str):
    if password.lower() in ("back", "exit"):
        return "back", None
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if not re.search(r"[A-Z]", password):
        return False, "Must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Must contain at least one digit."
    if not re.search(r"[^\w\s]", password):
        return False, "Must contain at least one special character."
    return True, None

def validate_money_input(value: str):
    if value.lower() in ("back", "exit"):
        return "back", None
    try:
        amt = float(value)
        if amt <= 0:
            return False, "Amount must be greater than zero."
        return True, amt
    except ValueError:
        return False, "Please enter a valid numeric amount."

# -----------------------
# Database Access
# -----------------------

def get_user_by_username(conn, username: str):
    return conn.execute(
        "SELECT id, full_name, username, password_hash, salt, account_number, balance FROM users WHERE username = ?",
        (username,)
    ).fetchone()

def get_user_by_account(conn, account_number: str):
    return conn.execute(
        "SELECT id, full_name, username, password_hash, salt, account_number, balance FROM users WHERE account_number = ?",
        (account_number,)
    ).fetchone()

def record_transaction(conn, user_id, tx_type, amount, balance_before, balance_after, description=None, counterparty_account=None):
    conn.execute("""
        INSERT INTO transactions (user_id, type, amount, timestamp, balance_before, balance_after, description, counterparty_account)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, tx_type, amount, datetime.utcnow().isoformat(), balance_before, balance_after, description, counterparty_account))
    conn.commit()

# -----------------------
# Core Flows
# -----------------------

def register_flow():
    print("\n=== Create a New Account (type 'back' anytime to cancel) ===")
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()

        while True:
            name_input = input("Full name: ")
            ok, val = validate_full_name(name_input)
            if ok == "back":
                print("Returning to main menu...")
                return
            if not ok:
                print("Error:", val)
                continue
            full_name = val
            break

        while True:
            uname_input = input("Username: ")
            ok, val = validate_username(uname_input)
            if ok == "back":
                print("Returning to main menu...")
                return
            if not ok:
                print("Error:", val)
                continue
            username = val
            if cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
                print("Error: Username already taken.")
                continue
            break

        while True:
            pwd = getpass("Password: ")
            ok, msg = validate_password_rules(pwd)
            if ok == "back":
                print("Returning to main menu...")
                return
            if not ok:
                print("Error:", msg)
                continue
            pwd2 = getpass("Confirm Password: ")
            if pwd2.lower() in ("back", "exit"):
                print("Returning to main menu...")
                return
            if pwd != pwd2:
                print("Error: Passwords do not match.")
                continue
            break

        while True:
            dep_in = input(f"Initial deposit (min {MIN_OPENING_DEPOSIT}): ")
            ok, amt = validate_money_input(dep_in)
            if ok == "back":
                print("Returning to main menu...")
                return
            if not ok:
                print("Error:", amt)
                continue
            if amt < MIN_OPENING_DEPOSIT:
                print(f"Minimum opening deposit is {MIN_OPENING_DEPOSIT}.")
                continue
            deposit_amt = amt
            break

        salt = generate_salt_hex()
        pwd_hash = hash_password(pwd, salt)
        acct = generate_account_number(conn)
        now = datetime.utcnow().isoformat()

        cursor.execute("""
            INSERT INTO users (full_name, username, password_hash, salt, account_number, balance, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (full_name, username, pwd_hash, salt, acct, deposit_amt, now))
        conn.commit()

        user_id = cursor.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()[0]
        record_transaction(conn, user_id, "deposit", deposit_amt, 0.0, deposit_amt, "Opening deposit")

        print(f"\n✅ Account created successfully! Your account number is {acct}")
        print("Returning to main menu...\n")
        time.sleep(1)


def login_flow():
    print("\n=== Log In (type 'back' anytime to return) ===")
    with sqlite3.connect(DB_FILE) as conn:
        while True:
            username = input("Username: ").strip()
            if username.lower() in ("back", "exit"):
                print("Returning to main menu...")
                return None
            ok, val = validate_username(username)
            if ok == "back":
                print("Returning to main menu...")
                return None
            if not ok:
                print("Error:", val)
                continue
            row = get_user_by_username(conn, val)
            if not row:
                print("Error: Username not found.")
                continue

            user_id, full_name, uname_db, pwd_hash_db, salt, acct, balance = row
            pwd = getpass("Password: ")
            if pwd.lower() in ("back", "exit"):
                print("Returning to main menu...")
                return None

            if not secrets.compare_digest(hash_password(pwd, salt), pwd_hash_db):
                print("Error: Invalid credentials.")
                continue

            print(f"✅ Welcome back, {full_name}!")
            time.sleep(1)
            return {"id": user_id, "full_name": full_name, "username": uname_db, "account_number": acct, "balance": balance}

# -----------------------
# Account Operations
# -----------------------

def show_account_details(session):
    print("\n=== Account Details ===")
    print("Full name:", session["full_name"])
    print("Username:", session["username"])
    print("Account number:", session["account_number"])
    print(f"Balance: ₦{session['balance']:.2f}")
    input("\nPress Enter to go back...")

def balance_inquiry(session):
    with sqlite3.connect(DB_FILE) as conn:
        bal = conn.execute("SELECT balance FROM users WHERE id = ?", (session["id"],)).fetchone()[0]
        session["balance"] = bal
    print(f"\nYour current balance is ₦{bal:.2f}")
    input("Press Enter to go back...")

def deposit_flow(session):
    print("\n=== Deposit Money (type 'back' to cancel) ===")
    amt_in = input("Enter amount: ")
    ok, val = validate_money_input(amt_in)
    if ok == "back":
        print("Returning to menu...")
        return
    if not ok:
        print("Error:", val)
        return
    amount = val
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        before = cur.execute("SELECT balance FROM users WHERE id=?", (session["id"],)).fetchone()[0]
        after = before + amount
        cur.execute("UPDATE users SET balance=? WHERE id=?", (after, session["id"]))
        conn.commit()
        record_transaction(conn, session["id"], "deposit", amount, before, after, "Deposit")
        session["balance"] = after
    print(f"✅ Deposit successful! New balance: ₦{after:.2f}")
    time.sleep(1)

def withdrawal_flow(session):
    print("\n=== Withdraw Money (type 'back' to cancel) ===")
    amt_in = input("Enter amount: ")
    ok, val = validate_money_input(amt_in)
    if ok == "back":
        print("Returning to menu...")
        return
    if not ok:
        print("Error:", val)
        return
    amount = val
    with sqlite3.connect(DB_FILE) as conn:
        cur = conn.cursor()
        before = cur.execute("SELECT balance FROM users WHERE id=?", (session["id"],)).fetchone()[0]
        if amount > before:
            print("❌ Insufficient funds.")
            return
        after = before - amount
        cur.execute("UPDATE users SET balance=? WHERE id=?", (after, session["id"]))
        conn.commit()
        record_transaction(conn, session["id"], "withdrawal", amount, before, after, "Withdrawal")
        session["balance"] = after
    print(f"✅ Withdrawal successful! New balance: ₦{after:.2f}")
    time.sleep(1)

def transfer_flow(session):
    print("\n=== Transfer Money (type 'back' to cancel) ===")
    with sqlite3.connect(DB_FILE) as conn:
        while True:
            recipient = input("Recipient account number (8 digits): ").strip()
            if recipient.lower() in ("back", "exit"):
                print("Returning to menu...")
                return
            if not recipient.isdigit() or len(recipient) != 8:
                print("Error: Must be 8 digits.")
                continue
            if recipient == session["account_number"]:
                print("Error: You cannot transfer to yourself.")
                continue
            rec = get_user_by_account(conn, recipient)
            if not rec:
                print("Error: Account not found.")
                continue
            break

        amt_in = input("Amount to transfer: ")
        ok, val = validate_money_input(amt_in)
        if ok == "back":
            print("Returning to menu...")
            return
        if not ok:
            print("Error:", val)
            return
        amount = val

        cur = conn.cursor()
        before = cur.execute("SELECT balance FROM users WHERE id=?", (session["id"],)).fetchone()[0]
        if amount > before:
            print("❌ Insufficient funds.")
            return

        rec_id, _, _, _, _, rec_acct, rec_bal = rec
        sender_after = before - amount
        rec_after = rec_bal + amount

        cur.execute("UPDATE users SET balance=? WHERE id=?", (sender_after, session["id"]))
        cur.execute("UPDATE users SET balance=? WHERE id=?", (rec_after, rec_id))
        conn.commit()

        record_transaction(conn, session["id"], "transfer", amount, before, sender_after, f"Transfer to {recipient}", recipient)
        record_transaction(conn, rec_id, "deposit", amount, rec_bal, rec_after, f"Transfer from {session['account_number']}", session["account_number"])

        session["balance"] = sender_after
        print(f"✅ Transfer successful! New balance: ₦{sender_after:.2f}")
        time.sleep(1)

def transaction_history_flow(session):
    print("\n=== Transaction History ===")
    with sqlite3.connect(DB_FILE) as conn:
        rows = conn.execute(
            "SELECT type, amount, timestamp, balance_before, balance_after, description, counterparty_account FROM transactions WHERE user_id = ? ORDER BY timestamp DESC",
            (session["id"],)
        ).fetchall()
        if not rows:
            print("You have no transactions yet.")
        else:
            for r in rows:
                t_type, amt, ts, b_before, b_after, desc, cp = r
                print(f"[{ts}] {t_type.upper()} ₦{amt:.2f} | {b_before:.2f} → {b_after:.2f} | {desc or ''} {cp or ''}")
    input("\nPress Enter to go back...")

# -----------------------
# Menus
# -----------------------

def user_session_loop(session):
    while True:
        print("\n=== Home Menu ===")
        print("1. Account Details")
        print("2. Balance Inquiry")
        print("3. Deposit")
        print("4. Withdraw")
        print("5. Transfer")
        print("6. Transaction History")
        print("7. Log Out")
        choice = input("Choose an option: ").strip()
        if choice == "1":
            show_account_details(session)
        elif choice == "2":
            balance_inquiry(session)
        elif choice == "3":
            deposit_flow(session)
        elif choice == "4":
            withdrawal_flow(session)
        elif choice == "5":
            transfer_flow(session)
        elif choice == "6":
            transaction_history_flow(session)
        elif choice == "7":
            print("Logging out...")
            time.sleep(0.5)
            break
        else:
            print("Invalid option, try again.")

def main_menu():
    init_db()
    print("🏦 Welcome to CLI Bank")
    while True:
        print("\n=== Main Menu ===")
        print("1. Register")
        print("2. Log In")
        print("3. Quit")
        choice = input("Choose an option: ").strip()
        if choice == "1":
            register_flow()
        elif choice == "2":
            session = login_flow()
            if session:
                user_session_loop(session)
        elif choice == "3":
            print("Goodbye 👋")
            break
        else:
            print("Invalid choice, please enter 1–3.")

if __name__ == "__main__":
    main_menu()
