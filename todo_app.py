"""
To-Do List App (Tkinter)
------------------------
Features:
  - Register / Login (passwords are hashed, never stored in plain text)
  - Blue themed interface
  - Add tasks with a deadline date (YYYY-MM-DD)
  - Mark done / undo, delete, clear completed
  - Dashboard showing Total, Pending, Done and Overdue task counts
  - Every user only sees their own tasks (saved in todo.db)

Run:  python todo_app.py
"""

import hashlib
import hmac
import os
import sqlite3
import tkinter as tk
from datetime import date
from tkinter import messagebox, ttk

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "todo.db")

# ---------- Colours ----------
BLUE_DARK = "#1e3a8a"
BLUE = "#2563eb"
BLUE_LIGHT = "#eff6ff"
WHITE = "#ffffff"
RED = "#dc2626"
GRAY = "#94a3b8"


# =====================================================================
#  Database layer (no GUI code here)
# =====================================================================
class Database:
    def __init__(self, path=DB_PATH):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                salt BLOB NOT NULL,
                password_hash BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                text TEXT NOT NULL,
                deadline TEXT NOT NULL,
                done INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id)
            );
            """
        )
        self.conn.commit()

    @staticmethod
    def _hash(password, salt):
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)

    # ----- users -----
    def register(self, username, password):
        """Returns True if the account was created, False if username is taken."""
        salt = os.urandom(16)
        try:
            self.conn.execute(
                "INSERT INTO users (username, salt, password_hash) VALUES (?, ?, ?)",
                (username, salt, self._hash(password, salt)),
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def verify(self, username, password):
        """Returns the user id if the login is correct, otherwise None."""
        row = self.conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row and hmac.compare_digest(
            row["password_hash"], self._hash(password, row["salt"])
        ):
            return row["id"]
        return None

    # ----- tasks -----
    def add_task(self, user_id, text, deadline):
        self.conn.execute(
            "INSERT INTO tasks (user_id, text, deadline) VALUES (?, ?, ?)",
            (user_id, text, deadline),
        )
        self.conn.commit()

    def get_tasks(self, user_id):
        return self.conn.execute(
            "SELECT * FROM tasks WHERE user_id = ? ORDER BY done ASC, deadline ASC, id ASC",
            (user_id,),
        ).fetchall()

    def toggle(self, task_id, user_id):
        self.conn.execute(
            "UPDATE tasks SET done = 1 - done WHERE id = ? AND user_id = ?",
            (task_id, user_id),
        )
        self.conn.commit()

    def delete(self, task_id, user_id):
        self.conn.execute(
            "DELETE FROM tasks WHERE id = ? AND user_id = ?", (task_id, user_id)
        )
        self.conn.commit()

    def clear_done(self, user_id):
        self.conn.execute(
            "DELETE FROM tasks WHERE user_id = ? AND done = 1", (user_id,)
        )
        self.conn.commit()


# =====================================================================
#  Login screen
# =====================================================================
class LoginFrame(tk.Frame):
    def __init__(self, master, app):
        super().__init__(master, bg=BLUE)
        self.app = app

        card = tk.Frame(self, bg=WHITE, padx=30, pady=25)
        card.place(relx=0.5, rely=0.45, anchor="center")

        tk.Label(card, text="To-Do List", font=("Arial", 22, "bold"),
                 bg=WHITE, fg=BLUE_DARK).pack(pady=(0, 4))
        tk.Label(card, text="Login or create an account", font=("Arial", 10),
                 bg=WHITE, fg="#475569").pack(pady=(0, 15))

        tk.Label(card, text="Username", bg=WHITE, anchor="w",
                 font=("Arial", 10, "bold")).pack(fill="x")
        self.username = tk.Entry(card, font=("Arial", 12), width=26)
        self.username.pack(pady=(2, 10), ipady=4)

        tk.Label(card, text="Password", bg=WHITE, anchor="w",
                 font=("Arial", 10, "bold")).pack(fill="x")
        self.password = tk.Entry(card, font=("Arial", 12), width=26, show="*")
        self.password.pack(pady=(2, 15), ipady=4)

        btns = tk.Frame(card, bg=WHITE)
        btns.pack(fill="x")
        tk.Button(btns, text="Login", bg=BLUE, fg=WHITE, font=("Arial", 11, "bold"),
                  relief="flat", cursor="hand2", command=self.login
                  ).pack(side="left", expand=True, fill="x", padx=(0, 4), ipady=4)
        tk.Button(btns, text="Register", bg=BLUE_DARK, fg=WHITE, font=("Arial", 11, "bold"),
                  relief="flat", cursor="hand2", command=self.register
                  ).pack(side="left", expand=True, fill="x", padx=(4, 0), ipady=4)

        self.username.focus()
        self.username.bind("<Return>", lambda e: self.password.focus())
        self.password.bind("<Return>", lambda e: self.login())

    def _read(self):
        return self.username.get().strip(), self.password.get()

    def login(self):
        username, password = self._read()
        if not username or not password:
            messagebox.showwarning("Missing details", "Enter username and password.")
            return
        user_id = self.app.db.verify(username, password)
        if user_id is None:
            messagebox.showerror("Login failed", "Invalid username or password.")
            self.password.delete(0, tk.END)
            return
        self.app.show_todo(user_id, username)

    def register(self):
        username, password = self._read()
        if not (3 <= len(username) <= 30):
            messagebox.showwarning("Invalid username", "Username must be 3-30 characters.")
            return
        if len(password) < 6:
            messagebox.showwarning("Weak password", "Password must be at least 6 characters.")
            return
        if self.app.db.register(username, password):
            messagebox.showinfo("Success", "Account created! You can now log in.")
            self.password.delete(0, tk.END)
        else:
            messagebox.showerror("Username taken", "That username already exists.")


# =====================================================================
#  Main to-do screen
# =====================================================================
class TodoFrame(tk.Frame):
    def __init__(self, master, app, user_id, username):
        super().__init__(master, bg=BLUE)
        self.app = app
        self.db = app.db
        self.user_id = user_id

        # ----- top bar -----
        top = tk.Frame(self, bg=BLUE)
        top.pack(fill="x", padx=15, pady=(12, 0))
        tk.Label(top, text=f"Logged in as {username}", bg=BLUE, fg=WHITE,
                 font=("Arial", 10)).pack(side="left")
        tk.Button(top, text="Logout", command=app.show_login, relief="flat",
                  bg=WHITE, fg=BLUE_DARK, cursor="hand2").pack(side="right")

        tk.Label(self, text="My To-Do List", font=("Arial", 22, "bold"),
                 bg=BLUE, fg=WHITE).pack(pady=(6, 8))

        # ----- stats -----
        stats_row = tk.Frame(self, bg=BLUE)
        stats_row.pack(fill="x", padx=15)
        self.stat_labels = {}
        for key, title in (("total", "Total"), ("pending", "Pending"),
                           ("done", "Done"), ("overdue", "Overdue")):
            box = tk.Frame(stats_row, bg=BLUE_LIGHT)
            box.pack(side="left", expand=True, fill="x", padx=3)
            num = tk.Label(box, text="0", font=("Arial", 18, "bold"),
                           bg=BLUE_LIGHT, fg=RED if key == "overdue" else BLUE_DARK)
            num.pack(pady=(6, 0))
            tk.Label(box, text=title, font=("Arial", 9), bg=BLUE_LIGHT,
                     fg="#475569").pack(pady=(0, 6))
            self.stat_labels[key] = num

        # ----- add task row -----
        add = tk.Frame(self, bg=WHITE, padx=10, pady=10)
        add.pack(fill="x", padx=18, pady=12)

        tk.Label(add, text="Task", bg=WHITE, font=("Arial", 9, "bold")).grid(row=0, column=0, sticky="w")
        tk.Label(add, text="Deadline (YYYY-MM-DD)", bg=WHITE, font=("Arial", 9, "bold")).grid(row=0, column=1, sticky="w", padx=(8, 0))

        self.task_entry = tk.Entry(add, font=("Arial", 12))
        self.task_entry.grid(row=1, column=0, sticky="ew", ipady=4)
        self.deadline_entry = tk.Entry(add, font=("Arial", 12), width=12)
        self.deadline_entry.insert(0, date.today().isoformat())
        self.deadline_entry.grid(row=1, column=1, padx=8, ipady=4)
        tk.Button(add, text="Add", bg=BLUE, fg=WHITE, font=("Arial", 10, "bold"),
                  relief="flat", width=7, cursor="hand2", command=self.add_task
                  ).grid(row=1, column=2, ipady=3)
        add.columnconfigure(0, weight=1)

        self.task_entry.bind("<Return>", lambda e: self.add_task())
        self.deadline_entry.bind("<Return>", lambda e: self.add_task())
        self.task_entry.focus()

        # ----- task table -----
        table_frame = tk.Frame(self, bg=WHITE)
        table_frame.pack(fill="both", expand=True, padx=18)

        columns = ("status", "task", "deadline")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings",
                                 selectmode="browse")
        self.tree.heading("status", text="Status")
        self.tree.heading("task", text="Task")
        self.tree.heading("deadline", text="Deadline")
        self.tree.column("status", width=80, anchor="center", stretch=False)
        self.tree.column("task", width=280)
        self.tree.column("deadline", width=100, anchor="center", stretch=False)
        self.tree.tag_configure("done", foreground=GRAY)
        self.tree.tag_configure("overdue", foreground=RED)

        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<Double-1>", lambda e: self.toggle_task())

        # ----- bottom buttons -----
        bottom = tk.Frame(self, bg=BLUE)
        bottom.pack(fill="x", padx=18, pady=12)
        for text, cmd, colour in (("Done / Undo", self.toggle_task, WHITE),
                                  ("Delete", self.delete_task, WHITE),
                                  ("Clear Done", self.clear_done, WHITE)):
            tk.Button(bottom, text=text, command=cmd, bg=colour, fg=BLUE_DARK,
                      relief="flat", cursor="hand2", font=("Arial", 10, "bold")
                      ).pack(side="left", expand=True, fill="x", padx=3, ipady=4)

        self.refresh()

    # ----- helpers -----
    def selected_id(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("No selection", "Please select a task first.")
            return None
        return int(sel[0])

    # ----- actions -----
    def add_task(self):
        text = self.task_entry.get().strip()
        deadline = self.deadline_entry.get().strip()
        if not text:
            messagebox.showwarning("Empty task", "Please type a task first.")
            return
        if len(text) > 200:
            messagebox.showwarning("Too long", "Task must be 200 characters or less.")
            return
        try:
            deadline = date.fromisoformat(deadline).isoformat()
        except ValueError:
            messagebox.showwarning("Invalid date", "Enter the deadline as YYYY-MM-DD, e.g. 2026-12-31.")
            return
        self.db.add_task(self.user_id, text, deadline)
        self.task_entry.delete(0, tk.END)
        self.refresh()

    def toggle_task(self):
        task_id = self.selected_id()
        if task_id is not None:
            self.db.toggle(task_id, self.user_id)
            self.refresh(keep=task_id)

    def delete_task(self):
        task_id = self.selected_id()
        if task_id is not None:
            self.db.delete(task_id, self.user_id)
            self.refresh()

    def clear_done(self):
        if not any(t["done"] for t in self.db.get_tasks(self.user_id)):
            messagebox.showinfo("Nothing to clear", "No completed tasks.")
            return
        self.db.clear_done(self.user_id)
        self.refresh()

    # ----- display -----
    def refresh(self, keep=None):
        self.tree.delete(*self.tree.get_children())
        today = date.today().isoformat()
        total = done = overdue = 0

        for t in self.db.get_tasks(self.user_id):
            total += 1
            is_overdue = (not t["done"]) and t["deadline"] < today
            if t["done"]:
                done += 1
                tags, status = ("done",), "Done"
            elif is_overdue:
                overdue += 1
                tags, status = ("overdue",), "Overdue"
            else:
                tags, status = (), "Pending"
            self.tree.insert("", "end", iid=str(t["id"]),
                             values=(status, t["text"], t["deadline"]), tags=tags)

        if keep is not None and self.tree.exists(str(keep)):
            self.tree.selection_set(str(keep))

        self.stat_labels["total"].config(text=str(total))
        self.stat_labels["pending"].config(text=str(total - done))
        self.stat_labels["done"].config(text=str(done))
        self.stat_labels["overdue"].config(text=str(overdue))


# =====================================================================
#  Application window
# =====================================================================
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("To-Do List")
        self.geometry("560x640")
        self.minsize(480, 560)
        self.configure(bg=BLUE)
        self.db = Database()
        self.current = None
        self.fix_treeview_colours()
        self.show_login()

    @staticmethod
    def fix_treeview_colours():
        # Workaround so row colours (tags) work on all Tk versions
        style = ttk.Style()
        style.map(
            "Treeview",
            foreground=[e for e in style.map("Treeview", query_opt="foreground")
                        if e[:2] != ("!disabled", "!selected")],
            background=[e for e in style.map("Treeview", query_opt="background")
                        if e[:2] != ("!disabled", "!selected")],
        )

    def _switch(self, frame):
        if self.current is not None:
            self.current.destroy()
        self.current = frame
        self.current.pack(fill="both", expand=True)

    def show_login(self):
        self._switch(LoginFrame(self, self))

    def show_todo(self, user_id, username):
        self._switch(TodoFrame(self, self, user_id, username))


if __name__ == "__main__":
    App().mainloop()
