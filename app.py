import os
import sys
import subprocess
import threading
import time
import signal
from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify, flash
from werkzeug.utils import secure_filename
import json
import uuid
import shutil
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-12345")
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['PROCESS_FOLDER'] = 'processes'

# Ensure required directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PROCESS_FOLDER'], exist_ok=True)

# Store running processes
processes = {}

class ManagedProcess:
    def __init__(self, pid, filename, port=None):
        self.pid = pid
        self.filename = filename
        self.port = port
        self.start_time = datetime.now()
        self.log_file = os.path.join(app.config['PROCESS_FOLDER'], f"{pid}.log")
        self.process = None
        
    def stop(self):
        if self.process:
            try:
                # Kill process group
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                self.process.terminate()
                self.process.wait(timeout=5)
            except:
                try:
                    self.process.kill()
                except:
                    pass
            finally:
                self.process = None
                
        if self.pid in processes:
            del processes[self.pid]
            
        return True

def get_requirements_from_code(code):
    """Extract import statements to guess requirements"""
    requirements = []
    lines = code.split('\n')
    
    # Common package mappings
    common_imports = {
        'flask': 'Flask',
        'django': 'Django',
        'numpy': 'numpy',
        'pandas': 'pandas',
        'requests': 'requests',
        'matplotlib': 'matplotlib',
        'tensorflow': 'tensorflow',
        'torch': 'torch',
        'sklearn': 'scikit-learn',
        'sqlalchemy': 'SQLAlchemy',
        'bs4': 'beautifulsoup4',
        'pillow': 'Pillow',
    }
    
    for line in lines:
        line = line.strip()
        if line.startswith('import ') or line.startswith('from '):
            parts = line.split()
            if len(parts) > 1:
                module = parts[1].split('.')[0]
                if module in common_imports:
                    requirements.append(common_imports[module])
    
    # Add default requirements
    if not requirements:
        requirements = ['flask']
    
    return list(set(requirements))

def install_requirements(requirements, pid):
    """Install Python packages"""
    if not requirements:
        return True
    
    try:
        # Create requirements.txt for this process
        req_file = os.path.join(app.config['PROCESS_FOLDER'], f"{pid}_requirements.txt")
        with open(req_file, 'w') as f:
            for req in requirements:
                f.write(f"{req}\n")
        
        # Install packages
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", req_file], 
                      check=True, capture_output=True)
        return True
    except Exception as e:
        print(f"Error installing requirements: {e}")
        return False

def run_python_file(filename, pid):
    """Run a Python file in a separate process"""
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    # Read file to determine requirements
    with open(filepath, 'r') as f:
        code = f.read()
    
    requirements = get_requirements_from_code(code)
    
    # Install requirements
    if not install_requirements(requirements, pid):
        return False
    
    # Create log file
    log_file = os.path.join(app.config['PROCESS_FOLDER'], f"{pid}.log")
    
    # Run the Python file
    try:
        # For web apps, we need to handle them differently
        if 'flask' in ' '.join(requirements).lower() or 'app.run' in code.lower():
            # It's a Flask app
            port = 5000 + len(processes)  # Assign a unique port
            cmd = f"cd {app.config['UPLOAD_FOLDER']} && python {filename}"
            
            # Modify the port if needed
            if 'port=' not in code:
                cmd = f"cd {app.config['UPLOAD_FOLDER']} && PORT={port} python {filename}"
            
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=open(log_file, 'a'),
                stderr=subprocess.STDOUT,
                preexec_fn=os.setsid
            )
            
            processes[pid] = ManagedProcess(pid, filename, port)
            processes[pid].process = process
            
            # Wait a bit for Flask to start
            time.sleep(3)
            return True
            
        else:
            # Regular Python script
            process = subprocess.Popen(
                [sys.executable, filepath],
                stdout=open(log_file, 'a'),
                stderr=subprocess.STDOUT,
                preexec_fn=os.setsid
            )
            
            processes[pid] = ManagedProcess(pid, filename)
            processes[pid].process = process
            return True
            
    except Exception as e:
        print(f"Error running Python file: {e}")
        with open(log_file, 'a') as f:
            f.write(f"Error: {str(e)}\n")
        return False

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload"""
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('index'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('index'))
    
    if not file.filename.endswith('.py'):
        flash('Only Python files (.py) are allowed')
        return redirect(url_for('index'))
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    # Save file
    file.save(filepath)
    
    # Generate unique ID for this process
    pid = str(uuid.uuid4())[:8]
    
    # Run the file in background thread
    thread = threading.Thread(target=run_python_file, args=(filename, pid))
    thread.daemon = True
    thread.start()
    
    flash(f'File uploaded and started with PID: {pid}')
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    """Dashboard to manage files and processes"""
    # Get all uploaded files
    files = []
    if os.path.exists(app.config['UPLOAD_FOLDER']):
        for f in os.listdir(app.config['UPLOAD_FOLDER']):
            if f.endswith('.py'):
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], f)
                files.append({
                    'name': f,
                    'size': os.path.getsize(filepath),
                    'modified': datetime.fromtimestamp(os.path.getmtime(filepath))
                })
    
    # Get running processes
    running_processes = []
    for pid, proc in processes.items():
        running_processes.append({
            'pid': pid,
            'filename': proc.filename,
            'port': proc.port,
            'start_time': proc.start_time,
            'status': 'Running' if proc.process and proc.process.poll() is None else 'Stopped'
        })
    
    return render_template('dashboard.html', files=files, processes=running_processes)

@app.route('/stop/<pid>')
def stop_process(pid):
    """Stop a running process"""
    if pid in processes:
        processes[pid].stop()
        flash(f'Process {pid} stopped successfully')
    else:
        flash('Process not found')
    
    return redirect(url_for('dashboard'))

@app.route('/start/<filename>')
def start_file(filename):
    """Start a Python file"""
    # Check if file exists
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(filepath):
        flash('File not found')
        return redirect(url_for('dashboard'))
    
    # Generate new PID
    pid = str(uuid.uuid4())[:8]
    
    # Run the file
    thread = threading.Thread(target=run_python_file, args=(filename, pid))
    thread.daemon = True
    thread.start()
    
    flash(f'File {filename} started with PID: {pid}')
    return redirect(url_for('dashboard'))

@app.route('/delete/<filename>')
def delete_file(filename):
    """Delete a file"""
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    # Stop any processes using this file
    for pid, proc in list(processes.items()):
        if proc.filename == filename:
            proc.stop()
    
    # Delete the file
    if os.path.exists(filepath):
        os.remove(filepath)
        flash(f'File {filename} deleted successfully')
    else:
        flash('File not found')
    
    return redirect(url_for('dashboard'))

@app.route('/view_log/<pid>')
def view_log(pid):
    """View log file for a process"""
    log_file = os.path.join(app.config['PROCESS_FOLDER'], f"{pid}.log")
    
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            log_content = f.read()
        return f'<pre>{log_content}</pre>'
    else:
        return 'Log file not found'

@app.route('/download/<filename>')
def download_file(filename):
    """Download a file"""
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True)
    else:
        flash('File not found')
        return redirect(url_for('dashboard'))

@app.route('/api/processes')
def api_processes():
    """API endpoint to get process status"""
    process_list = []
    for pid, proc in processes.items():
        process_list.append({
            'pid': pid,
            'filename': proc.filename,
            'port': proc.port,
            'start_time': proc.start_time.isoformat(),
            'running': proc.process and proc.process.poll() is None
        })
    
    return jsonify(process_list)

@app.route('/health')
def health_check():
    """Health check endpoint for Render"""
    return jsonify({'status': 'healthy', 'processes': len(processes)})

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(413)
def too_large(e):
    flash('File too large (max 16MB)')
    return redirect(url_for('index'))

@app.errorhandler(500)
def internal_error(e):
    flash('Internal server error')
    return redirect(url_for('index'))

# Cleanup on exit
import atexit
@atexit.register
def cleanup():
    for pid, proc in list(processes.items()):
        proc.stop()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)