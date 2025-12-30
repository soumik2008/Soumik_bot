import os
import subprocess
import threading
import time
import signal
import sys
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from werkzeug.utils import secure_filename
import json
import psutil
import uuid
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Configuration
UPLOAD_FOLDER = 'uploads'
HOSTED_FILES_FOLDER = 'hosted_files'
ALLOWED_EXTENSIONS = {'py'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['HOSTED_FILES_FOLDER'] = HOSTED_FILES_FOLDER

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(HOSTED_FILES_FOLDER, exist_ok=True)

# Global dictionary to track running processes
running_processes = {}

# Add Jinja2 filter for converting timestamps
@app.template_filter('timestamp_to_datetime')
def timestamp_to_datetime_filter(timestamp):
    if timestamp:
        try:
            dt = datetime.fromtimestamp(float(timestamp))
            return dt.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return "Invalid timestamp"
    return "N/A"

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_imports(filepath):
    """Extract imports from Python file"""
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        
        imports = set()
        lines = content.split('\n')
        
        for line in lines:
            line = line.strip()
            # Skip comments and empty lines
            if line.startswith('#') or not line:
                continue
                
            if line.startswith('import '):
                parts = line.split('import ')[1].split()
                if parts:
                    module = parts[0].split('.')[0]
                    # Skip relative imports
                    if not module.startswith('.'):
                        imports.add(module)
            elif line.startswith('from '):
                parts = line.split('from ')[1].split(' import')[0]
                module = parts.strip().split('.')[0]
                # Skip relative imports
                if not module.startswith('.'):
                    imports.add(module)
        
        return imports
    except Exception as e:
        print(f"Error extracting imports: {e}")
        return set()

def install_requirements(imports):
    """Install required modules"""
    # Common built-in modules that don't need installation
    builtin_modules = {
        'os', 'sys', 'json', 'time', 'datetime', 'math', 'random',
        're', 'collections', 'itertools', 'functools', 'threading',
        'subprocess', 'hashlib', 'base64', 'uuid', 'pathlib', 'typing',
        'flask', 'werkzeug', 'psutil'  # Our app modules
    }
    
    # Filter out built-in modules
    imports_to_install = imports - builtin_modules
    
    installed_modules = []
    failed_modules = []
    
    if imports_to_install:
        print(f"Installing requirements: {imports_to_install}")
        for module in imports_to_install:
            try:
                # Check if module is already installed
                subprocess.check_call([sys.executable, '-c', f"import {module}"])
                print(f"{module} is already installed")
                installed_modules.append(f"{module} (already installed)")
            except:
                try:
                    # Try to install the module
                    subprocess.check_call([sys.executable, '-m', 'pip', 'install', module, '--quiet'])
                    print(f"Successfully installed {module}")
                    installed_modules.append(module)
                except subprocess.CalledProcessError as e:
                    print(f"Failed to install {module}: {e}")
                    failed_modules.append(module)
                except Exception as e:
                    print(f"Error installing {module}: {e}")
                    failed_modules.append(module)
    
    return installed_modules, failed_modules

def run_python_file(file_id, filepath, hosted_file_data):
    """Run the Python file in a separate process"""
    try:
        # Extract and install requirements
        imports = extract_imports(filepath)
        installed, failed = install_requirements(imports)
        
        # Update metadata with installation results
        hosted_file_data['installed_modules'] = installed
        hosted_file_data['failed_modules'] = failed
        
        # Run the file with output capture
        process = subprocess.Popen(
            [sys.executable, '-u', filepath],  # -u for unbuffered output
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        running_processes[file_id] = {
            'process': process,
            'filepath': filepath,
            'start_time': time.time()
        }
        
        hosted_file_data['status'] = 'running'
        hosted_file_data['pid'] = process.pid
        hosted_file_data['start_time'] = time.time()
        hosted_file_data['installed_modules'] = installed
        hosted_file_data['failed_modules'] = failed
        
        # Update metadata file
        metadata_path = os.path.join(app.config['HOSTED_FILES_FOLDER'], f"{file_id}.json")
        with open(metadata_path, 'w') as f:
            json.dump(hosted_file_data, f)
        
        # Function to capture output in real-time
        def capture_output():
            output_lines = []
            error_lines = []
            
            # Read stdout and stderr
            while True:
                # Check if process is still running
                if process.poll() is not None:
                    # Process ended, read remaining output
                    stdout, stderr = process.communicate()
                    if stdout:
                        output_lines.append(stdout)
                    if stderr:
                        error_lines.append(stderr)
                    break
                
                # Try to read from stdout
                stdout_line = process.stdout.readline()
                if stdout_line:
                    output_lines.append(stdout_line)
                    # Update output in real-time (simplified approach)
                    hosted_file_data['last_output'] = ''.join(output_lines)
                    with open(metadata_path, 'w') as f:
                        json.dump(hosted_file_data, f)
                
                # Try to read from stderr
                stderr_line = process.stderr.readline()
                if stderr_line:
                    error_lines.append(stderr_line)
                    hosted_file_data['last_error'] = ''.join(error_lines)
                    with open(metadata_path, 'w') as f:
                        json.dump(hosted_file_data, f)
                
                time.sleep(0.1)
            
            # Final update after process ends
            hosted_file_data['status'] = 'stopped'
            hosted_file_data['end_time'] = time.time()
            hosted_file_data['last_output'] = ''.join(output_lines)
            hosted_file_data['last_error'] = ''.join(error_lines)
            
            with open(metadata_path, 'w') as f:
                json.dump(hosted_file_data, f)
            
            # Remove from running processes
            if file_id in running_processes:
                del running_processes[file_id]
        
        # Start output capture in a separate thread
        capture_thread = threading.Thread(target=capture_output)
        capture_thread.daemon = True
        capture_thread.start()
        
        return True
    except Exception as e:
        print(f"Error running Python file: {e}")
        # Update metadata with error
        hosted_file_data['status'] = 'error'
        hosted_file_data['last_error'] = str(e)
        metadata_path = os.path.join(app.config['HOSTED_FILES_FOLDER'], f"{file_id}.json")
        with open(metadata_path, 'w') as f:
            json.dump(hosted_file_data, f)
        return False

def stop_process(file_id):
    """Stop a running process"""
    if file_id in running_processes:
        process = running_processes[file_id]['process']
        
        # Try to terminate gracefully
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            # Force kill if not terminated
            process.kill()
            process.wait()
        
        # Update metadata
        metadata_path = os.path.join(app.config['HOSTED_FILES_FOLDER'], f"{file_id}.json")
        if os.path.exists(metadata_path):
            with open(metadata_path, 'r') as f:
                hosted_file_data = json.load(f)
            
            hosted_file_data['status'] = 'stopped'
            hosted_file_data['end_time'] = time.time()
            
            with open(metadata_path, 'w') as f:
                json.dump(hosted_file_data, f)
        
        # Remove from running processes
        del running_processes[file_id]
        return True
    return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('index'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('index'))
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_id = str(uuid.uuid4())[:8]
        
        # Save uploaded file
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"{file_id}_{filename}")
        file.save(filepath)
        
        # Extract imports to show what will be installed
        imports = extract_imports(filepath)
        
        # Create hosted file metadata
        hosted_file_data = {
            'id': file_id,
            'filename': filename,
            'original_filename': file.filename,
            'upload_time': time.time(),
            'filepath': filepath,
            'status': 'uploaded',
            'pid': None,
            'start_time': None,
            'end_time': None,
            'last_output': '',
            'last_error': '',
            'detected_imports': list(imports),
            'installed_modules': [],
            'failed_modules': []
        }
        
        # Save metadata
        metadata_path = os.path.join(app.config['HOSTED_FILES_FOLDER'], f"{file_id}.json")
        with open(metadata_path, 'w') as f:
            json.dump(hosted_file_data, f)
        
        flash(f'File uploaded successfully! File ID: {file_id}')
        return redirect(url_for('file_detail', file_id=file_id))
    
    flash('Invalid file type. Only .py files are allowed.')
    return redirect(url_for('index'))

@app.route('/files')
def list_files():
    files = []
    
    # Get all metadata files
    for filename in os.listdir(app.config['HOSTED_FILES_FOLDER']):
        if filename.endswith('.json'):
            metadata_path = os.path.join(app.config['HOSTED_FILES_FOLDER'], filename)
            try:
                with open(metadata_path, 'r') as f:
                    file_data = json.load(f)
                    
                    # Check if file still exists
                    if os.path.exists(file_data.get('filepath', '')):
                        files.append(file_data)
                    else:
                        # Clean up orphaned metadata
                        os.remove(metadata_path)
            except Exception as e:
                print(f"Error loading metadata {filename}: {e}")
                continue
    
    # Sort by upload time (newest first)
    files.sort(key=lambda x: x.get('upload_time', 0), reverse=True)
    
    return render_template('files.html', files=files)

@app.route('/file/<file_id>')
def file_detail(file_id):
    metadata_path = os.path.join(app.config['HOSTED_FILES_FOLDER'], f"{file_id}.json")
    
    if not os.path.exists(metadata_path):
        flash('File not found')
        return redirect(url_for('list_files'))
    
    with open(metadata_path, 'r') as f:
        file_data = json.load(f)
    
    # Check if file still exists
    if not os.path.exists(file_data.get('filepath', '')):
        flash('File not found on disk')
        return redirect(url_for('list_files'))
    
    # Check if process is actually running
    if file_data['status'] == 'running' and file_data.get('pid'):
        try:
            process = psutil.Process(file_data['pid'])
            if not process.is_running():
                file_data['status'] = 'stopped'
                with open(metadata_path, 'w') as f:
                    json.dump(file_data, f)
        except psutil.NoSuchProcess:
            file_data['status'] = 'stopped'
            with open(metadata_path, 'w') as f:
                json.dump(file_data, f)
        except:
            pass
    
    # Read file content for preview
    file_content = ""
    if os.path.exists(file_data['filepath']):
        try:
            with open(file_data['filepath'], 'r') as f:
                file_content = f.read()
        except:
            file_content = "Unable to read file content"
    
    return render_template('file_detail.html', file=file_data, file_content=file_content)

@app.route('/start/<file_id>')
def start_file(file_id):
    metadata_path = os.path.join(app.config['HOSTED_FILES_FOLDER'], f"{file_id}.json")
    
    if not os.path.exists(metadata_path):
        flash('File not found')
        return redirect(url_for('list_files'))
    
    with open(metadata_path, 'r') as f:
        file_data = json.load(f)
    
    # Check if file exists
    if not os.path.exists(file_data['filepath']):
        flash('File not found on disk')
        return redirect(url_for('file_detail', file_id=file_id))
    
    if file_data['status'] == 'running':
        flash('File is already running')
    else:
        success = run_python_file(file_id, file_data['filepath'], file_data)
        if success:
            flash('File started successfully. Modules are being installed automatically.')
        else:
            flash('Failed to start file')
    
    return redirect(url_for('file_detail', file_id=file_id))

@app.route('/stop/<file_id>')
def stop_file(file_id):
    if stop_process(file_id):
        flash('File stopped successfully')
    else:
        flash('File was not running or could not be stopped')
    
    return redirect(url_for('file_detail', file_id=file_id))

@app.route('/delete/<file_id>')
def delete_file(file_id):
    metadata_path = os.path.join(app.config['HOSTED_FILES_FOLDER'], f"{file_id}.json")
    
    if os.path.exists(metadata_path):
        with open(metadata_path, 'r') as f:
            file_data = json.load(f)
        
        # Stop if running
        if file_data['status'] == 'running':
            stop_process(file_id)
        
        # Delete uploaded file
        if os.path.exists(file_data['filepath']):
            os.remove(file_data['filepath'])
        
        # Delete metadata
        os.remove(metadata_path)
        
        flash('File deleted successfully')
    else:
        flash('File not found')
    
    return redirect(url_for('list_files'))

@app.route('/download/<file_id>')
def download_file(file_id):
    metadata_path = os.path.join(app.config['HOSTED_FILES_FOLDER'], f"{file_id}.json")
    
    if not os.path.exists(metadata_path):
        flash('File not found')
        return redirect(url_for('list_files'))
    
    with open(metadata_path, 'r') as f:
        file_data = json.load(f)
    
    if os.path.exists(file_data['filepath']):
        return send_file(
            file_data['filepath'],
            as_attachment=True,
            download_name=file_data['original_filename']
        )
    
    flash('File not found on disk')
    return redirect(url_for('list_files'))

@app.route('/view_output/<file_id>')
def view_output(file_id):
    metadata_path = os.path.join(app.config['HOSTED_FILES_FOLDER'], f"{file_id}.json")
    
    if not os.path.exists(metadata_path):
        return "File not found", 404
    
    with open(metadata_path, 'r') as f:
        file_data = json.load(f)
    
    output = file_data.get('last_output', 'No output available')
    error = file_data.get('last_error', '')
    
    result = f"=== Output for {file_data['original_filename']} ===\n\n"
    result += f"Status: {file_data.get('status', 'unknown')}\n"
    
    if file_data.get('start_time'):
        result += f"Started: {datetime.fromtimestamp(file_data['start_time']).strftime('%Y-%m-%d %H:%M:%S')}\n"
    
    if file_data.get('end_time'):
        result += f"Ended: {datetime.fromtimestamp(file_data['end_time']).strftime('%Y-%m-%d %H:%M:%S')}\n"
    
    result += f"\n{'='*50}\nOUTPUT:\n{'='*50}\n{output}\n"
    
    if error:
        result += f"\n{'='*50}\nERRORS:\n{'='*50}\n{error}\n"
    
    if file_data.get('installed_modules'):
        result += f"\n{'='*50}\nINSTALLED MODULES:\n{'='*50}\n"
        for module in file_data['installed_modules']:
            result += f"- {module}\n"
    
    if file_data.get('failed_modules'):
        result += f"\n{'='*50}\nFAILED TO INSTALL:\n{'='*50}\n"
        for module in file_data['failed_modules']:
            result += f"- {module}\n"
    
    return f"<pre>{result}</pre>"

@app.route('/view_code/<file_id>')
def view_code(file_id):
    metadata_path = os.path.join(app.config['HOSTED_FILES_FOLDER'], f"{file_id}.json")
    
    if not os.path.exists(metadata_path):
        return "File not found", 404
    
    with open(metadata_path, 'r') as f:
        file_data = json.load(f)
    
    if os.path.exists(file_data['filepath']):
        with open(file_data['filepath'], 'r') as f:
            code = f.read()
        
        result = f"=== Source Code: {file_data['original_filename']} ===\n\n"
        result += code
        
        return f"<pre>{result}</pre>"
    
    return "File not found on disk", 404

@app.route('/install_status/<file_id>')
def install_status(file_id):
    metadata_path = os.path.join(app.config['HOSTED_FILES_FOLDER'], f"{file_id}.json")
    
    if not os.path.exists(metadata_path):
        return "File not found", 404
    
    with open(metadata_path, 'r') as f:
        file_data = json.load(f)
    
    result = f"=== Installation Status for {file_data['original_filename']} ===\n\n"
    
    if file_data.get('detected_imports'):
        result += f"Detected imports:\n"
        for imp in file_data['detected_imports']:
            result += f"- {imp}\n"
    
    if file_data.get('installed_modules'):
        result += f"\nSuccessfully installed:\n"
        for module in file_data['installed_modules']:
            result += f"- {module}\n"
    
    if file_data.get('failed_modules'):
        result += f"\nFailed to install:\n"
        for module in file_data['failed_modules']:
            result += f"- {module}\n"
    
    if not file_data.get('installed_modules') and not file_data.get('failed_modules'):
        result += "\nNo modules needed installation (all were built-in or already installed)\n"
    
    return f"<pre>{result}</pre>"

@app.route('/health')
def health_check():
    return "OK", 200

@app.route('/cleanup')
def cleanup():
    """Clean up orphaned files (for maintenance)"""
    count = 0
    
    # Check all metadata files
    for filename in os.listdir(app.config['HOSTED_FILES_FOLDER']):
        if filename.endswith('.json'):
            metadata_path = os.path.join(app.config['HOSTED_FILES_FOLDER'], filename)
            try:
                with open(metadata_path, 'r') as f:
                    file_data = json.load(f)
                
                # Check if file exists
                if not os.path.exists(file_data.get('filepath', '')):
                    os.remove(metadata_path)
                    count += 1
            except:
                os.remove(metadata_path)
                count += 1
    
    # Clean up old files in uploads folder (older than 1 day)
    for filename in os.listdir(app.config['UPLOAD_FOLDER']):
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.isfile(filepath):
            # Check if file is older than 1 day
            if time.time() - os.path.getmtime(filepath) > 86400:
                # Check if metadata exists
                file_id = filename.split('_')[0]
                metadata_path = os.path.join(app.config['HOSTED_FILES_FOLDER'], f"{file_id}.json")
                if not os.path.exists(metadata_path):
                    os.remove(filepath)
                    count += 1
    
    return f"Cleaned up {count} orphaned files", 200

# Error handlers
@app.errorhandler(413)
def too_large(e):
    flash('File is too large. Maximum size is 16MB.')
    return redirect(url_for('index'))

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', error="Page not found"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', error="Internal server error"), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)