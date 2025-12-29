import os
import json
import yaml
import threading
import subprocess
import signal
import time
import shutil
from datetime import datetime
from pathlib import Path
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import psutil

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['PROCESS_FOLDER'] = 'running_processes'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'py', 'txt', 'json', 'env', 'yaml', 'yml'}

# Create necessary directories
for folder in [app.config['UPLOAD_FOLDER'], app.config['PROCESS_FOLDER'], 'data']:
    Path(folder).mkdir(exist_ok=True)

# Simple file-based user system
class User(UserMixin):
    def __init__(self, id, username, is_admin=False):
        self.id = id
        self.username = username
        self.is_admin = is_admin

# File-based data storage
DATA_FILE = 'data/users.json'
PROCESSES_FILE = 'data/processes.json'

def load_users():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(DATA_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def load_processes():
    if os.path.exists(PROCESSES_FILE):
        with open(PROCESSES_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_processes(processes):
    with open(PROCESSES_FILE, 'w') as f:
        json.dump(processes, f, indent=2)

# Process Manager
class ProcessManager:
    def __init__(self):
        self.processes = {}
        self.load_running_processes()
    
    def load_running_processes(self):
        processes = load_processes()
        for pid, info in processes.items():
            if psutil.pid_exists(int(pid)):
                self.processes[pid] = info
            else:
                info['status'] = 'stopped'
                info['pid'] = None
    
    def start_process(self, process_id, filepath, process_type='script', bot_token=None):
        try:
            # Create virtual environment for the process
            venv_path = os.path.join(app.config['PROCESS_FOLDER'], f'venv_{process_id}')
            if not os.path.exists(venv_path):
                subprocess.run([sys.executable, '-m', 'venv', venv_path], check=True)
            
            # Install requirements if requirements.txt exists
            req_file = os.path.join(os.path.dirname(filepath), 'requirements.txt')
            if os.path.exists(req_file):
                pip_path = os.path.join(venv_path, 'bin', 'pip')
                subprocess.run([pip_path, 'install', '-r', req_file], check=True)
            
            # Prepare command
            python_path = os.path.join(venv_path, 'bin', 'python')
            
            if process_type == 'telegram_bot' and bot_token:
                cmd = [python_path, filepath, bot_token]
            else:
                cmd = [python_path, filepath]
            
            # Start process
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Store process info
            self.processes[str(proc.pid)] = {
                'id': process_id,
                'name': os.path.basename(filepath),
                'filepath': filepath,
                'status': 'running',
                'start_time': datetime.now().isoformat(),
                'user_id': current_user.id,
                'process_type': process_type,
                'bot_token': bot_token
            }
            
            save_processes(self.processes)
            
            # Start monitoring threads
            threading.Thread(target=self.monitor_output, args=(proc, process_id)).start()
            threading.Thread(target=self.monitor_process, args=(proc, process_id)).start()
            
            return True, proc.pid
        except Exception as e:
            return False, str(e)
    
    def stop_process(self, pid):
        try:
            if pid in self.processes:
                try:
                    os.kill(int(pid), signal.SIGTERM)
                except:
                    pass
                self.processes[pid]['status'] = 'stopped'
                self.processes[pid]['pid'] = None
                save_processes(self.processes)
                return True
        except Exception as e:
            print(f"Error stopping process: {e}")
        return False
    
    def monitor_output(self, proc, process_id):
        for line in proc.stdout:
            self.log_output(process_id, line.strip(), 'output')
    
    def monitor_process(self, proc, process_id):
        proc.wait()
        pid_str = str(proc.pid)
        if pid_str in self.processes:
            self.processes[pid_str]['status'] = 'stopped'
            save_processes(self.processes)
    
    def log_output(self, process_id, message, log_type='info'):
        log_file = os.path.join(app.config['PROCESS_FOLDER'], f'logs_{process_id}.txt')
        with open(log_file, 'a') as f:
            timestamp = datetime.now().isoformat()
            f.write(f"[{timestamp}] [{log_type.upper()}] {message}\n")
    
    def get_logs(self, process_id, lines=100):
        log_file = os.path.join(app.config['PROCESS_FOLDER'], f'logs_{process_id}.txt')
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                all_lines = f.readlines()
                return ''.join(all_lines[-lines:])
        return "No logs available."

process_manager = ProcessManager()

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    users = load_users()
    user_data = users.get(user_id)
    if user_data:
        return User(user_id, user_data['username'], user_data.get('is_admin', False))
    return None

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_user_processes(user_id):
    processes = load_processes()
    user_processes = []
    for pid, info in processes.items():
        if info.get('user_id') == user_id:
            info['pid'] = pid
            user_processes.append(info)
    return user_processes

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        users = load_users()
        
        # Check if user exists
        for uid, user_data in users.items():
            if user_data['username'] == username:
                flash('Username already exists!', 'danger')
                return redirect(url_for('register'))
        
        # Create new user
        user_id = str(len(users) + 1)
        users[user_id] = {
            'username': username,
            'password': generate_password_hash(password),
            'is_admin': False,
            'created_at': datetime.now().isoformat()
        }
        
        save_users(users)
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check for admin login
        if username == os.environ.get('ADMIN_USERNAME', 'admin'):
            if password == os.environ.get('ADMIN_PASSWORD', 'admin123'):
                admin_user = User('admin', 'admin', True)
                login_user(admin_user, remember=True)
                return redirect(url_for('dashboard'))
        
        users = load_users()
        
        for user_id, user_data in users.items():
            if user_data['username'] == username and check_password_hash(user_data['password'], password):
                user = User(user_id, username, user_data.get('is_admin', False))
                login_user(user, remember=True)
                return redirect(url_for('dashboard'))
        
        flash('Invalid credentials!', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_processes = get_user_processes(current_user.id)
    return render_template('dashboard.html', processes=user_processes)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], current_user.id)
        Path(user_folder).mkdir(exist_ok=True)
        
        filepath = os.path.join(user_folder, filename)
        file.save(filepath)
        
        # Create process entry
        processes = load_processes()
        process_id = str(len(processes) + 1)
        
        processes[process_id] = {
            'id': process_id,
            'name': filename,
            'filename': filename,
            'filepath': filepath,
            'status': 'stopped',
            'user_id': current_user.id,
            'process_type': 'script',
            'created_at': datetime.now().isoformat()
        }
        
        save_processes(processes)
        
        return jsonify({'success': True, 'filename': filename})
    
    return jsonify({'error': 'File type not allowed'}), 400

@app.route('/process/start', methods=['POST'])
@login_required
def start_process():
    data = request.get_json()
    process_id = data.get('process_id')
    process_type = data.get('process_type', 'script')
    bot_token = data.get('bot_token')
    
    processes = load_processes()
    process_info = None
    
    for pid, info in processes.items():
        if info['id'] == process_id and info['user_id'] == current_user.id:
            process_info = info
            break
    
    if not process_info:
        return jsonify({'error': 'Process not found'}), 404
    
    success, result = process_manager.start_process(
        process_id, 
        process_info['filepath'], 
        process_type,
        bot_token
    )
    
    if success:
        process_info['status'] = 'running'
        process_info['pid'] = str(result)
        process_info['process_type'] = process_type
        process_info['bot_token'] = bot_token
        save_processes(processes)
        return jsonify({'success': True, 'pid': result})
    else:
        return jsonify({'error': str(result)}), 500

@app.route('/process/stop', methods=['POST'])
@login_required
def stop_process():
    data = request.get_json()
    process_id = data.get('process_id')
    
    processes = load_processes()
    pid_to_stop = None
    
    for pid, info in processes.items():
        if info['id'] == process_id and info['user_id'] == current_user.id:
            pid_to_stop = pid
            break
    
    if not pid_to_stop:
        return jsonify({'error': 'Process not found'}), 404
    
    if process_manager.stop_process(pid_to_stop):
        processes[pid_to_stop]['status'] = 'stopped'
        save_processes(processes)
        return jsonify({'success': True})
    
    return jsonify({'error': 'Failed to stop process'}), 500

@app.route('/process/logs/<process_id>')
@login_required
def get_process_logs(process_id):
    logs = process_manager.get_logs(process_id)
    return jsonify({'logs': logs})

@app.route('/process/delete', methods=['POST'])
@login_required
def delete_process():
    data = request.get_json()
    process_id = data.get('process_id')
    
    processes = load_processes()
    
    # Find and remove process
    pid_to_remove = None
    for pid, info in processes.items():
        if info['id'] == process_id and info['user_id'] == current_user.id:
            pid_to_remove = pid
            # Stop if running
            if info['status'] == 'running' and info.get('pid'):
                process_manager.stop_process(info['pid'])
            break
    
    if pid_to_remove:
        del processes[pid_to_remove]
        save_processes(processes)
        
        # Clean up log files
        log_file = os.path.join(app.config['PROCESS_FOLDER'], f'logs_{process_id}.txt')
        if os.path.exists(log_file):
            os.remove(log_file)
        
        return jsonify({'success': True})
    
    return jsonify({'error': 'Process not found'}), 404

@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    
    all_processes = load_processes()
    all_users = load_users()
    
    return render_template('admin.html', 
                         processes=all_processes, 
                         users=all_users,
                         total_processes=len(all_processes),
                         total_users=len(all_users))

@app.route('/file-manager')
@login_required
def file_manager():
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], current_user.id)
    files = []
    
    if os.path.exists(user_folder):
        for filename in os.listdir(user_folder):
            filepath = os.path.join(user_folder, filename)
            if os.path.isfile(filepath):
                files.append({
                    'name': filename,
                    'size': os.path.getsize(filepath),
                    'modified': datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat()
                })
    
    return render_template('file_manager.html', files=files)

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], current_user.id)
    return send_from_directory(user_folder, filename, as_attachment=True)

@app.route('/logs')
@login_required
def logs_viewer():
    return render_template('logs.html')

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

if __name__ == '__main__':
    import sys
    app.run(debug=True)