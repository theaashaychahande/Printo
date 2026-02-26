import os
import secrets
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from supabase import create_client, Client
from datetime import datetime

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'default-key-for-dev')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# Supabase Setup
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Ensure upload directory exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Flask-Login User Model
class User(UserMixin):
    def __init__(self, id, email, role):
        self.id = str(id)
        self.email = email
        self.role = role

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    # Retrieve user from profiles table in Supabase
    try:
        response = supabase.table('profiles').select('*').eq('id', user_id).execute()
        if response.data:
            user_data = response.data[0]
            return User(user_data['id'], user_data['email'], user_data['role'])
    except Exception as e:
        print(f"Error loading user: {e}")
    return None

# --- Routes ---

@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('student_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password')
        
        # Testing Backdoor Bypass
        test_accounts = {
            os.getenv('TEST_ADMIN_EMAIL'): os.getenv('TEST_ADMIN_PASSWORD'),
            os.getenv('TEST_STUDENT_EMAIL'): os.getenv('TEST_STUDENT_PASSWORD')
        }
        
        if email in test_accounts and password == test_accounts[email]:
            try:
                # Directly fetch profile from Supabase
                profile_res = supabase.table('profiles').select('*').eq('email', email).execute()
                if profile_res.data:
                    user_data = profile_res.data[0]
                    user = User(user_data['id'], user_data['email'], user_data['role'])
                    login_user(user)
                    flash(f'Login Successful (Bypass - {user_data["role"]})', 'success')
                    return redirect(url_for('index'))
                else:
                    flash('Test account profile not found in Supabase!', 'error')
            except Exception as e:
                flash(f'Bypass failed: {str(e)}', 'error')
            return redirect(url_for('login'))

        # Standard OTP Flow
        try:
            res = supabase.auth.sign_in_with_otp({"email": email})
            session['auth_email'] = email
            flash('OTP sent to your email! Please check and verify.', 'success')
            return redirect(url_for('verify_otp'))
        except Exception as e:
            flash(f'Error sending OTP: {str(e)}', 'error')
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Registration is now the same as login with Supabase OTP
    # But we can keep it for UI if desired
    if request.method == 'POST':
        email = request.form.get('email')
        try:
            res = supabase.auth.sign_in_with_otp({"email": email})
            session['auth_email'] = email
            flash('OTP sent! Verify to create your account.', 'success')
            return redirect(url_for('verify_otp'))
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
            
    return render_template('register.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify_otp():
    email = session.get('auth_email')
    if not email:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        token = request.form.get('otp')
        try:
            res = supabase.auth.verify_otp({"email": email, "token": token, "type": "email"})
            if res.user:
                # Get or create profile/role (handled by DB trigger mostly)
                # But we load it here to login
                profile_res = supabase.table('profiles').select('*').eq('id', res.user.id).execute()
                if profile_res.data:
                    user_data = profile_res.data[0]
                    user = User(user_data['id'], user_data['email'], user_data['role'])
                    login_user(user)
                    session.pop('auth_email', None)
                    return redirect(url_for('index'))
                else:
                    flash('Account created! Please login again if dashboard doesn\'t load.', 'info')
                    return redirect(url_for('login'))
        except Exception as e:
            flash(f'Verification failed: {str(e)}', 'error')
            
    return render_template('verify.html', email=email)

@app.route('/logout')
@login_required
def logout():
    supabase.auth.sign_out()
    logout_user()
    return redirect(url_for('login'))

# --- Student Routes ---

@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        return redirect(url_for('admin_dashboard'))
    
    # Get wallet balance
    wallet_res = supabase.table('wallets').select('balance').eq('user_id', current_user.id).execute()
    balance = float(wallet_res.data[0]['balance']) if wallet_res.data else 0.0
    
    # Get jobs
    jobs_res = supabase.table('print_jobs').select('*').eq('user_id', current_user.id).order('created_at', desc=True).execute()
    jobs = jobs_res.data
    for job in jobs:
        job['created_at'] = datetime.fromisoformat(job['created_at'].replace('Z', '+00:00'))
    
    return render_template('student/dashboard.html', balance=balance, jobs=jobs)

@app.route('/student/topup', methods=['GET', 'POST'])
@login_required
def topup_request():
    if request.method == 'POST':
        amount = float(request.form.get('amount'))
        try:
            supabase.table('topup_requests').insert({
                "user_id": current_user.id,
                "amount": amount,
                "status": "pending"
            }).execute()
            flash('Top-up request submitted!', 'success')
            return redirect(url_for('student_dashboard'))
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
        
    return render_template('student/topup.html')

@app.route('/student/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('student_dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('student_dashboard'))

    if file:
        filename = secure_filename(file.filename)
        unique_filename = f"{secrets.token_hex(4)}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)

        color = request.form.get('color')
        sides = request.form.get('sides')
        copies = int(request.form.get('copies', 1))
        pages = 1 
        rate = 1 if color == 'bw' else 5
        cost = pages * rate * copies

        # Check balance
        wallet_res = supabase.table('wallets').select('balance').eq('user_id', current_user.id).execute()
        balance = wallet_res.data[0]['balance'] if wallet_res.data else 0.0
        
        if balance < cost:
            flash(f'Insufficient balance! Needed: ₹{cost}', 'error')
            os.remove(file_path)
            return redirect(url_for('student_dashboard'))

        token = f"T-{secrets.token_hex(3).upper()}"
        
        # Deduct balance and insert job
        try:
            supabase.table('wallets').update({"balance": balance - cost}).eq('user_id', current_user.id).execute()
            supabase.table('print_jobs').insert({
                "user_id": current_user.id,
                "filename": filename,
                "file_path": file_path,
                "options": {'color': color, 'sides': sides, 'copies': copies},
                "cost": cost,
                "token_number": token,
                "status": "queued"
            }).execute()
            flash(f'Job submitted! Token: {token}', 'success')
        except Exception as e:
            flash(f'Transaction failed: {str(e)}', 'error')
            
        return redirect(url_for('student_dashboard'))

# --- Admin Routes ---

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return redirect(url_for('student_dashboard'))
    
    pending_jobs = supabase.table('print_jobs').select('*, profiles(email)').eq('status', 'queued').order('created_at').execute().data
    recent_jobs = supabase.table('print_jobs').select('*, profiles(email)').neq('status', 'queued').order('created_at', desc=True).limit(10).execute().data
    
    for job in pending_jobs + recent_jobs:
        job['created_at'] = datetime.fromisoformat(job['created_at'].replace('Z', '+00:00'))
    
    topup_requests = supabase.table('topup_requests').select('*, profiles(email)').eq('status', 'pending').execute().data
    
    # Simple count approximations
    total_prints = supabase.table('print_jobs').select('id', count='exact').execute().count
    active_tokens = len(pending_jobs)
    
    return render_template('admin/dashboard.html', 
                           pending_jobs=pending_jobs, 
                           recent_jobs=recent_jobs, 
                           topup_requests=topup_requests,
                           total_prints=total_prints,
                           active_tokens=active_tokens)

@app.route('/admin/approve_topup/<int:request_id>', methods=['POST'])
@login_required
def approve_topup(request_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
        
    try:
        topup_res = supabase.table('topup_requests').select('*').eq('id', request_id).execute()
        if topup_res.data:
            topup = topup_res.data[0]
            if topup['status'] == 'pending':
                # Update status
                supabase.table('topup_requests').update({"status": "approved"}).eq('id', request_id).execute()
                # Update wallet
                wallet_res = supabase.table('wallets').select('balance').eq('user_id', topup['user_id']).execute()
                new_balance = (wallet_res.data[0]['balance'] if wallet_res.data else 0.0) + topup['amount']
                supabase.table('wallets').update({"balance": new_balance}).eq('user_id', topup['user_id']).execute()
                flash('Top-up approved!', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
        
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/complete_job/<int:job_id>', methods=['POST'])
@login_required
def complete_job(job_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
        
    supabase.table('print_jobs').update({"status": "printed"}).eq('id', job_id).execute()
    flash('Job marked as printed', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/batch_print', methods=['POST'])
@login_required
def batch_print():
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
        
    supabase.table('print_jobs').update({"status": "printed"}).eq('status', 'queued').execute()
    flash('Processed all jobs in batch!', 'success')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
