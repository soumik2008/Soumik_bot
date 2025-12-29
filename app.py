from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import subprocess
import psutil
import signal
import threading
import time
from datetime import datetime
from dotenv import load_dotenv

from models import db, User, PythonFile

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Render environment configuration
if 'RENDER' in os.environ:
    # Production settings for Render
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))
    database_url = os.environ.get('DATABASE_URL', '')
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    print(f"Using PostgreSQL database: {database_url[:50]}...")
else:
    # Development settings
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_recycle': 300,
    'pool_pre_ping': True,
}
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create necessary directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('running_processes', exist_ok=True)
os.makedirs('static/css', exist_ok=True)
os.makedirs('static/js', exist_ok=True)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Global dictionary to track running processes
running_processes = {}
process_lock = threading.Lock()

class PythonProcess:
    def __init__(self, file_id, file_path, port):
        self.file_id = file_id
        self.file_path = file_path
        self.port = port
        self.process = None
        self.log_file = f"running_processes/{file_id}.log"
        self.venv_path = f"running_processes/venv_{file_id}"
        
    def start(self):
        try:
            file_obj = PythonFile.query.get(self.file_id)
            if not file_obj:
                print(f"File object not found for ID: {self.file_id}")
                return False

            # Check if file exists
            if not os.path.exists(self.file_path):
                print(f"File not found at path: {self.file_path}")
                return False

            # Create virtual environment if it doesn't exist
            if not os.path.exists(self.venv_path):
                print(f"Creating virtual environment at: {self.venv_path}")
                result = subprocess.run(
                    ["python3", "-m", "venv", self.venv_path],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                if result.returncode != 0:
                    print(f"Error creating venv: {result.stderr}")
                    return False
                print(f"Virtual environment created successfully")

            # Install requirements if they exist
            requirements_file = os.path.join(os.path.dirname(self.file_path), 'requirements.txt')
            if os.path.exists(requirements_file):
                print(f"Installing requirements from: {requirements_file}")
                pip_path = os.path.join(self.venv_path, 'bin', 'pip')
                result = subprocess.run(
                    [pip_path, "install", "-r", requirements_file],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                if result.returncode != 0:
                    print(f"Error installing requirements: {result.stderr}")
                else:
                    print(f"Requirements installed successfully")

            # Start the Python process
            python_path = os.path.join(self.venv_path, 'bin', 'python')
            print(f"Starting process with: {python_path} {self.file_path}")
            
            # Open log file
            log_file_obj = open(self.log_file, 'w')
            
            self.process = subprocess.Popen(
                [python_path, self.file_path],
                stdout=log_file_obj,
                stderr=subprocess.STDOUT,
                shell=False,
                cwd=os.path.dirname(self.file_path)
            )
            
            # Update database
            file_obj.status = 'running'
            file_obj.pid = self.process.pid
            file_obj.last_started = datetime.utcnow()
            db.session.commit()
            
            # Add to running processes
            with process_lock:
                running_processes[self.file_id] = self
            
            print(f"Process started successfully with PID: {self.process.pid}")
            return True
            
        except subprocess.TimeoutExpired:
            print("Timeout while starting process")
            return False
        except Exception as e:
            print(f"Error starting process: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def stop(self):
        try:
            if self.process and self.process.poll() is None:
                print(f"Stopping process with PID: {self.process.pid}")
                
                # Try graceful termination
                self.process.terminate()
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    # Force kill if not responding
                    print("Process not responding, forcing kill")
                    self.process.kill()
                    self.process.wait()
                
                print(f"Process stopped successfully")
            
            # Update database
            file_obj = PythonFile.query.get(self.file_id)
            if file_obj:
                file_obj.status = 'stopped'
                file_obj.pid = None
                file_obj.last_stopped = datetime.utcnow()
                db.session.commit()
            
            # Remove from running processes
            with process_lock:
                if self.file_id in running_processes:
                    del running_processes[self.file_id]
            
            return True
            
        except Exception as e:
            print(f"Error stopping process: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
    
    def is_running(self):
        return self.process and self.process.poll() is None

# Helper function to cleanup old processes
def cleanup_old_processes():
    """Clean up processes that are no longer running"""
    with process_lock:
        to_remove = []
        for file_id, process in running_processes.items():
            if not process.is_running():
                to_remove.append(file_id)
        
        for file_id in to_remove:
            file_obj = PythonFile.query.get(file_id)
            if file_obj:
                file_obj.status = 'stopped'
                file_obj.pid = None
            del running_processes[file_id]
        
        if to_remove:
            db.session.commit()
            print(f"Cleaned up {len(to_remove)} old processes")

# Routes
@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        # Validation
        if not username or not email or not password:
            flash('All fields are required')
            return redirect(url_for('register'))
        
        if len(username) < 3:
            flash('Username must be at least 3 characters')
            return redirect(url_for('register'))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters')
            return redirect(url_for('register'))
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return redirect(url_for('register'))
        
        # Create user
        user = User(
            username=username,
            email=email,
            password=generate_password_hash(password, method='sha256'),
            is_admin=(username == 'admin')
        )
        
        try:
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please login.')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Error creating account. Please try again.')
            print(f"Registration error: {e}")
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = 'remember' in request.form
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user, remember=remember)
            next_page = request.args.get('next')
            flash(f'Welcome back, {username}!')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """User logout"""
    logout_user()
    flash('You have been logged out successfully.')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    cleanup_old_processes()
    user_files = PythonFile.query.filter_by(user_id=current_user.id).order_by(PythonFile.created_at.desc()).all()
    return render_template('dashboard.html', files=user_files)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    """Upload Python file"""
    if 'python_file' not in request.files:
        flash('No file selected')
        return redirect(url_for('dashboard'))
    
    file = request.files['python_file']
    
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('dashboard'))
    
    if file and file.filename.endswith('.py'):
        filename = secure_filename(file.filename)
        unique_filename = f"{current_user.id}_{int(time.time())}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        try:
            file.save(file_path)
            
            # Check if file is valid Python
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read(100)  # Read first 100 chars to check
            except:
                os.remove(file_path)
                flash('Invalid file encoding')
                return redirect(url_for('dashboard'))
            
            python_file = PythonFile(
                filename=unique_filename,
                file_path=file_path,
                original_name=filename,
                user_id=current_user.id,
                port=8000 + current_user.id % 1000  # Ensure port is in valid range
            )
            
            db.session.add(python_file)
            db.session.commit()
            
            flash('File uploaded successfully!')
        except Exception as e:
            flash(f'Error uploading file: {str(e)}')
            print(f"Upload error: {e}")
    else:
        flash('Please upload a valid Python file (.py)')
    
    return redirect(url_for('dashboard'))

@app.route('/start_file/<int:file_id>')
@login_required
def start_file(file_id):
    """Start a Python file"""
    python_file = PythonFile.query.get_or_404(file_id)
    
    if python_file.user_id != current_user.id and not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    if python_file.status == 'running':
        flash('File is already running')
        return redirect(url_for('dashboard'))
    
    # Check if file exists
    if not os.path.exists(python_file.file_path):
        flash('File not found on server')
        return redirect(url_for('dashboard'))
    
    process = PythonProcess(file_id, python_file.file_path, python_file.port)
    if process.start():
        flash('File started successfully!')
    else:
        flash('Error starting file. Check server logs.')
    
    return redirect(url_for('dashboard'))

@app.route('/stop_file/<int:file_id>')
@login_required
def stop_file(file_id):
    """Stop a running Python file"""
    python_file = PythonFile.query.get_or_404(file_id)
    
    if python_file.user_id != current_user.id and not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    with process_lock:
        if file_id in running_processes:
            if running_processes[file_id].stop():
                flash('File stopped successfully!')
            else:
                flash('Error stopping file')
        else:
            # Try to stop using PID if process is in database
            if python_file.pid:
                try:
                    os.kill(python_file.pid, signal.SIGTERM)
                    python_file.status = 'stopped'
                    python_file.pid = None
                    db.session.commit()
                    flash('File stopped successfully!')
                except:
                    flash('File was not running')
            else:
                flash('File is not running')
    
    return redirect(url_for('dashboard'))

@app.route('/delete_file/<int:file_id>')
@login_required
def delete_file(file_id):
    """Delete a Python file"""
    python_file = PythonFile.query.get_or_404(file_id)
    
    if python_file.user_id != current_user.id and not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    # Stop if running
    with process_lock:
        if file_id in running_processes:
            running_processes[file_id].stop()
    
    try:
        # Delete file from filesystem
        if os.path.exists(python_file.file_path):
            os.remove(python_file.file_path)
        
        # Delete log file if exists
        log_file = f"running_processes/{file_id}.log"
        if os.path.exists(log_file):
            os.remove(log_file)
        
        # Delete virtual environment if exists
        venv_path = f"running_processes/venv_{file_id}"
        if os.path.exists(venv_path):
            import shutil
            shutil.rmtree(venv_path)
        
        # Delete from database
        db.session.delete(python_file)
        db.session.commit()
        
        flash('File deleted successfully!')
    except Exception as e:
        flash(f'Error deleting file: {str(e)}')
        print(f"Delete error: {e}")
        db.session.rollback()
    
    return redirect(url_for('dashboard'))

@app.route('/file_manager')
@login_required
def file_manager():
    """File manager page"""
    cleanup_old_processes()
    user_files = PythonFile.query.filter_by(user_id=current_user.id).order_by(PythonFile.created_at.desc()).all()
    return render_template('file_manager.html', files=user_files)

@app.route('/admin')
@login_required
def admin():
    """Admin panel"""
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    cleanup_old_processes()
    all_files = PythonFile.query.order_by(PythonFile.created_at.desc()).all()
    all_users = User.query.order_by(User.created_at.desc()).all()
    
    # System stats
    total_running = sum(1 for f in all_files if f.status == 'running')
    total_stopped = len(all_files) - total_running
    
    return render_template('admin.html', 
                         files=all_files, 
                         users=all_users,
                         total_running=total_running,
                         total_stopped=total_stopped)

@app.route('/api/files')
@login_required
def api_files():
    """API: Get user's files"""
    files = PythonFile.query.filter_by(user_id=current_user.id).all()
    result = []
    for file in files:
        result.append({
            'id': file.id,
            'filename': file.original_name,
            'status': file.status,
            'created_at': file.created_at.isoformat(),
            'last_started': file.last_started.isoformat() if file.last_started else None,
            'size': os.path.getsize(file.file_path) if os.path.exists(file.file_path) else 0
        })
    return jsonify(result)

@app.route('/api/start/<int:file_id>', methods=['POST'])
@login_required
def api_start_file(file_id):
    """API: Start a file"""
    python_file = PythonFile.query.get_or_404(file_id)
    
    if python_file.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    if python_file.status == 'running':
        return jsonify({'error': 'File is already running'}), 400
    
    process = PythonProcess(file_id, python_file.file_path, python_file.port)
    if process.start():
        return jsonify({'message': 'File started successfully', 'pid': process.process.pid})
    else:
        return jsonify({'error': 'Error starting file'}), 500

@app.route('/api/stop/<int:file_id>', methods=['POST'])
@login_required
def api_stop_file(file_id):
    """API: Stop a file"""
    python_file = PythonFile.query.get_or_404(file_id)
    
    if python_file.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    with process_lock:
        if file_id in running_processes:
            if running_processes[file_id].stop():
                return jsonify({'message': 'File stopped successfully'})
            else:
                return jsonify({'error': 'Error stopping file'}), 500
        else:
            return jsonify({'error': 'File is not running'}), 400

@app.route('/api/delete/<int:file_id>', methods=['DELETE'])
@login_required
def api_delete_file(file_id):
    """API: Delete a file"""
    python_file = PythonFile.query.get_or_404(file_id)
    
    if python_file.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403
    
    # Stop if running
    with process_lock:
        if file_id in running_processes:
            running_processes[file_id].stop()
    
    try:
        if os.path.exists(python_file.file_path):
            os.remove(python_file.file_path)
        
        log_file = f"running_processes/{file_id}.log"
        if os.path.exists(log_file):
            os.remove(log_file)
        
        db.session.delete(python_file)
        db.session.commit()
        
        return jsonify({'message': 'File deleted successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/view_logs/<int:file_id>')
@login_required
def view_logs(file_id):
    """View process logs"""
    python_file = PythonFile.query.get_or_404(file_id)
    
    if python_file.user_id != current_user.id and not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    log_file = f"running_processes/{file_id}.log"
    logs = ""
    
    if os.path.exists(log_file):
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                logs = f.read()
        except:
            logs = "Error reading log file"
    else:
        logs = "No logs available. The process might not have started yet."
    
    return render_template('logs.html', logs=logs, filename=python_file.original_name, file_id=file_id)

@app.route('/download_file/<int:file_id>')
@login_required
def download_file(file_id):
    """Download a Python file"""
    python_file = PythonFile.query.get_or_404(file_id)
    
    if python_file.user_id != current_user.id and not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('dashboard'))
    
    if os.path.exists(python_file.file_path):
        return send_file(
            python_file.file_path,
            as_attachment=True,
            download_name=python_file.original_name
        )
    else:
        flash('File not found')
        return redirect(url_for('dashboard'))

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

@app.errorhandler(413)
def too_large(error):
    flash('File too large. Maximum size is 16MB.')
    return redirect(url_for('dashboard'))

# Initialize database and create admin user
def init_db():
    with app.app_context():
        # Create tables
        db.create_all()
        print("Database tables created successfully!")
        
        # Create admin user if not exists
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_user = User(
                username='admin',
                email='admin@example.com',
                password=generate_password_hash('admin123', method='sha256'),
                is_admin=True
            )
            db.session.add(admin_user)
            db.session.commit()
            print("Admin user created: username='admin', password='admin123'")
        
        # Clean up any orphaned processes
        PythonFile.query.filter(PythonFile.status == 'running').update({'status': 'stopped', 'pid': None})
        db.session.commit()

# Start cleanup thread
def start_cleanup_thread():
    def cleanup_worker():
        while True:
            time.sleep(60)  # Run every minute
            with app.app_context():
                try:
                    cleanup_old_processes()
                except:
                    pass
    
    if 'RENDER' not in os.environ:  # Only in development
        thread = threading.Thread(target=cleanup_worker, daemon=True)
        thread.start()

if __name__ == '__main__':
    init_db()
    start_cleanup_thread()
    
    # Use PORT environment variable for Render
    port = int(os.environ.get('PORT', 5000))
    
    if 'RENDER' in os.environ:
        # Production on Render
        print(f"Starting production server on port {port}")
        app.run(host='0.0.0.0', port=port, debug=False)
    else:
        # Development
        print(f"Starting development server on http://localhost:{port}")
        print("Admin credentials: username='admin', password='admin123'")
        app.run(host='0.0.0.0', port=port, debug=True)