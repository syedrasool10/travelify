from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from flask_cors import CORS
import random
import smtplib
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'your_very_secret_key_change_this_12345'

# Enhanced session configuration
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

CORS(app, supports_credentials=True)

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'travelifydb'

try:
    mysql = MySQL(app)
    print("✅ MySQL connected successfully")
except Exception as e:
    print(f"❌ MySQL connection failed: {e}")

# Email Configuration
SENDER_EMAIL = 'syed07rasool007@gmail.com'
SENDER_PASSWORD = 'bijk pxcc lkqu rstp'

def generate_otp(length=6):
    """Generate random 6-digit OTP"""
    return ''.join(random.choices('0123456789', k=length))

def send_otp_email(receiver_email, otp):
    """Send OTP via email"""
    subject = 'TRAVELIFY - Your OTP Verification Code'
    message = f"""Subject: {subject}

Hello,

Your OTP for TRAVELIFY registration is: {otp}

This OTP is valid for 10 minutes.

If you didn't request this, please ignore this email.

Best regards,
TRAVELIFY Team
"""
    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, receiver_email, message)
        print(f"✅ OTP {otp} sent successfully to {receiver_email}")
        return True
    except Exception as e:
        print(f'❌ Email send error: {e}')
        return False

@app.route('/')
def index():
    """Redirect to home or login"""
    try:
        if 'user' in session:
            return redirect(url_for('home'))
        return redirect(url_for('login'))
    except Exception as e:
        print(f"❌ Index error: {e}")
        return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration"""
    if request.method == 'GET':
        return render_template('register.html')
    
    try:
        data = request.get_json(force=True)
        full_name = data.get('fullName', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()
        phone = data.get('phone', '').strip()

        print(f"📝 Registration attempt for: {email}")

        if not all([full_name, email, password, phone]):
            return jsonify({'success': False, 'error': 'All fields are required'}), 400

        cursor = mysql.connection.cursor()
        cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
        if cursor.fetchone():
            cursor.close()
            print(f"⚠️ Email already registered: {email}")
            return jsonify({'success': False, 'error': 'Email already registered'}), 400

        otp = generate_otp()
        session.permanent = True
        session['temp_registration'] = {
            'full_name': full_name,
            'email': email,
            'password': password,
            'phone': phone,
            'otp': otp,
            'otp_time': datetime.now().isoformat()
        }
        session.modified = True
        
        cursor.close()
        
        print(f"🔐 Generated OTP: {otp} for {email}")
        
        if send_otp_email(email, otp):
            return jsonify({
                'success': True,
                'message': 'OTP sent to your email. Please verify.',
                'redirect': '/otp'
            }), 200
        else:
            return jsonify({'success': False, 'error': 'Failed to send OTP. Please try again.'}), 500
            
    except Exception as e:
        print(f"❌ Registration error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': 'Server error. Please try again.'}), 500

@app.route('/otp', methods=['GET'])
def otp_page():
    """Display OTP verification page"""
    try:
        if 'temp_registration' not in session:
            flash('Please register first', 'error')
            return redirect(url_for('register'))
        
        email = session['temp_registration']['email']
        return render_template('otp.html', email=email)
    except Exception as e:
        print(f"❌ OTP page error: {e}")
        return redirect(url_for('register'))

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    """Verify OTP and create user account"""
    try:
        data = request.get_json(force=True)
        entered_otp = str(data.get('otp', '')).strip()
        
        if 'temp_registration' not in session:
            return jsonify({'success': False, 'error': 'Session expired. Please register again.'}), 400
        
        temp_data = session['temp_registration']
        stored_otp = str(temp_data['otp']).strip()
        otp_time = datetime.fromisoformat(temp_data['otp_time'])
        
        if datetime.now() - otp_time > timedelta(minutes=10):
            session.pop('temp_registration', None)
            return jsonify({'success': False, 'error': 'OTP expired. Please register again.'}), 400
        
        if entered_otp != stored_otp:
            return jsonify({'verified': False, 'success': False, 'error': 'Invalid OTP'}), 401
        
        cursor = mysql.connection.cursor()
        cursor.execute(
            """INSERT INTO users (full_name, email, password, phone, otp_verified, created_at) 
               VALUES (%s, %s, %s, %s, %s, %s)""",
            (temp_data['full_name'], temp_data['email'], temp_data['password'], 
             temp_data['phone'], True, datetime.now())
        )
        mysql.connection.commit()
        cursor.close()
        
        print(f"✅ User account created for: {temp_data['email']}")
        session.pop('temp_registration', None)
        
        return jsonify({
            'verified': True,
            'success': True,
            'message': 'Registration successful! Please login.',
            'redirect': '/login'
        }), 200
        
    except Exception as e:
        print(f"❌ Verification error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': 'Verification failed.'}), 500

@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    """Resend OTP to user email"""
    try:
        if 'temp_registration' not in session:
            return jsonify({'success': False, 'error': 'Session expired'}), 400
        
        temp_data = session['temp_registration']
        email = temp_data['email']
        new_otp = generate_otp()
        
        temp_data['otp'] = new_otp
        temp_data['otp_time'] = datetime.now().isoformat()
        session['temp_registration'] = temp_data
        session.modified = True
        
        if send_otp_email(email, new_otp):
            return jsonify({'success': True, 'message': 'New OTP sent!'}), 200
        else:
            return jsonify({'success': False, 'error': 'Failed to resend OTP'}), 500
    except Exception as e:
        print(f"❌ Resend error: {e}")
        return jsonify({'success': False, 'error': 'Failed to resend'}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login"""
    if request.method == 'GET':
        return render_template('login.html')
    
    try:
        data = request.get_json(force=True)
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()
        
        print(f"🔐 Login attempt for: {email}")
        
        if not email or not password:
            return jsonify({'success': False, 'error': 'Email and password required'}), 400
        
        cursor = mysql.connection.cursor()
        cursor.execute(
            "SELECT id, full_name, password, otp_verified FROM users WHERE email=%s",
            (email,)
        )
        result = cursor.fetchone()
        cursor.close()
        
        if not result:
            print(f"❌ User not found: {email}")
            return jsonify({'success': False, 'error': 'User not found. Please register.'}), 404
        
        user_id, full_name, stored_password, otp_verified = result
        
        if not otp_verified:
            return jsonify({'success': False, 'error': 'Please verify your email first'}), 403
        
        if password != stored_password:
            print(f"❌ Invalid password for: {email}")
            return jsonify({'success': False, 'error': 'Invalid password'}), 401
        
        # Clear any old session data
        session.clear()
        session.permanent = True
        session['user'] = {
            'id': user_id,
            'email': email,
            'full_name': full_name
        }
        session.modified = True
        
        print(f"✅ Login successful for: {email}")
        print(f"✅ Session created with user: {session.get('user')}")
        
        return jsonify({
            'success': True,
            'message': 'Login successful!',
            'redirect': '/home'
        }), 200
        
    except Exception as e:
        print(f"❌ Login error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': 'Server error. Please try again.'}), 500

@app.route('/home')
def home():
    """Home page - requires login"""
    try:
        print(f"🏠 Home page accessed")
        print(f"📋 Session keys: {list(session.keys())}")
        print(f"👤 User in session: {session.get('user')}")
        
        if 'user' not in session:
            print("❌ No user in session, redirecting to login")
            flash('Please login first', 'error')
            return redirect(url_for('login'))
        
        user = session['user']
        print(f"✅ Rendering home page for: {user.get('full_name')}")
        return render_template('home.html', user=user)
    except Exception as e:
        print(f"❌ Home page error: {e}")
        import traceback
        traceback.print_exc()
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    """Logout user"""
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/help')
def help_page():
    return render_template('help.html')
@app.route('/bus')
def bus():
    return render_template('bus.html')
@app.route('/searchmovie')
def searchmovie():
    return render_template('searchmovie.html')
@app.route('/movie')
def movie():
    return render_template('movie.html')
@app.route('/seat')
def seat():
    return render_template('seat.html')
@app.route('/qr')
def moviepayment():
    return render_template('qr.html')
@app.route('/available')
def available():
    return render_template('available.html')
@app.route('/train')
def train():
    return render_template('train.html')
@app.route('/trainlist')
def trainlist():
    return render_template('trainlist.html')
@app.route('/flight')
def flight():
    return render_template('flight.html')
@app.route('/flightlist')
def flightlist():
    return render_template('flightlist.html')
@app.route('/hotel')
def hotel():
    return render_template('hotel.html')
@app.route('/hotellist')
def hotellist():
    return render_template('hotellist.html')
# Error handlers
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    print(f"❌ 500 Error: {e}")
    return "Internal Server Error", 500

if __name__ == '__main__':
    print("=" * 50)
    print("🚀 Starting TRAVELIFY Flask Server...")
    print("=" * 50)
    try:
        app.run(debug=True, port=5000, host='127.0.0.1', use_reloader=True)
    except Exception as e:
        print(f"❌ Server startup error: {e}")
