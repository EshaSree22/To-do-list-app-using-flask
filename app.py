from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from bson.objectid import ObjectId
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = 'secret123'
bcrypt = Bcrypt(app)

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client.todo_app
users = db.users
tasks = db.tasks

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uname = request.form['username']
        pwd = request.form['password']
        user = users.find_one({'username': uname})

        if user and bcrypt.check_password_hash(user['password'], pwd):
            session['username'] = uname
            flash('Login successful!', 'success')
            return redirect(url_for('todo'))
        else:
            flash('Incorrect username or password.', 'danger')

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        uname = request.form['username']
        pwd = request.form['password']
        if users.find_one({'username': uname}):
            flash('User already exists.', 'warning')
            return render_template('register.html')

        hashed_pwd = bcrypt.generate_password_hash(pwd).decode('utf-8')
        users.insert_one({'username': uname, 'password': hashed_pwd})
        flash('Signup successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/todo', methods=['GET', 'POST'])
def todo():
    if 'username' not in session:
        flash('You need to login first.', 'info')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        task = request.form['task']
        if task.strip():
            tasks.insert_one({'username': session['username'], 'task': task.strip(), 'status': 'pending'})
            flash('Task added.', 'success')
        else:
            flash('Task cannot be empty.', 'danger')

    # Fetch tasks and convert _id to string for templates
    pending_cursor = tasks.find({'username': session['username'], 'status': 'pending'})
    completed_cursor = tasks.find({'username': session['username'], 'status': 'completed'})

    pending = []
    for task in pending_cursor:
        task['_id'] = str(task['_id'])
        pending.append(task)

    completed = []
    for task in completed_cursor:
        task['_id'] = str(task['_id'])
        completed.append(task)

    return render_template('todo.html', pending=pending, completed=completed)

@app.route('/complete/<task_id>')
def complete(task_id):
    try:
        tasks.update_one({'_id': ObjectId(task_id)}, {'$set': {'status': 'completed'}})
        flash('Task marked as completed.', 'info')
    except Exception:
        flash('Invalid task ID.', 'danger')
    return redirect(url_for('todo'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
