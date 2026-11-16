# To-Do List (Tkinter)

A desktop to-do list app built with Python and Tkinter.

## Features
- Register / Login (passwords are hashed)
- Blue themed interface
- Tasks with deadlines (YYYY-MM-DD)
- Dashboard with Total, Pending, Done and Overdue counts
- Mark done / undo, delete, clear completed
- Each user sees only their own tasks (stored in a local SQLite file, todo.db)

## How to run
1. Install Python 3.8+ from https://www.python.org (tick "Add Python to PATH").
   Tkinter comes bundled with Python. No extra packages are needed.
2. Download or clone this repository.
3. Open a terminal in the project folder and run:

       python todo_app.py

On Mac/Linux use `python3 todo_app.py`.
