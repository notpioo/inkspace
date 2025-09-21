import json
import os
import base64
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename
import secrets

app = Flask(__name__)
app.secret_key = os.environ.get('SESSION_SECRET', 'fallback-dev-key')
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)  # needed for url_for to generate with https

@app.context_processor
def inject_user_data():
    return {
        'load_users': load_users
    }

# Database file paths
USERS_DB = 'data/users.json'
NOTES_DB = 'data/notes.json'

def init_database():
    """Initialize JSON database files if they don't exist"""
    os.makedirs('data', exist_ok=True)

    if not os.path.exists(USERS_DB):
        with open(USERS_DB, 'w') as f:
            json.dump({}, f)

    if not os.path.exists(NOTES_DB):
        with open(NOTES_DB, 'w') as f:
            json.dump({}, f)

def load_users():
    """Load users from JSON file"""
    try:
        with open(USERS_DB, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_users(users):
    """Save users to JSON file"""
    with open(USERS_DB, 'w') as f:
        json.dump(users, f, indent=2)

def load_notes():
    """Load notes from JSON file"""
    try:
        with open(NOTES_DB, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_notes(notes):
    """Save notes to JSON file"""
    with open(NOTES_DB, 'w') as f:
        json.dump(notes, f, indent=2)

def caesar_cipher(text, shift, encrypt=True):
    """Caesar cipher encryption/decryption"""
    if not encrypt:
        shift = -shift

    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            result += char
    return result

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password harus minimal 8 karakter"

    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

    if not (has_upper and has_lower and has_digit and has_special):
        return False, "Password harus mengandung huruf besar, huruf kecil, angka, dan karakter khusus"

    return True, ""

@app.route('/')
def index():
    """Home page - display public notes like social media"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Check app lock
    users = load_users()
    user = users.get(session['user_id'])
    if user and user.get('app_lock_enabled') and not session.get('app_unlocked'):
        return redirect(url_for('app_lock'))

    notes = load_notes()
    all_public_notes = []

    # Collect all public notes from all users
    for author_id, user_notes in notes.items():
        author = users.get(author_id, {})
        author_name = author.get('name', 'Unknown User')
        
        for note in user_notes:
            # Only show public notes (not locked)
            if note.get('is_public', False) and not note.get('is_locked', True):
                # Decrypt content for display
                decrypted_note = note.copy()
                if decrypted_note.get('encrypted'):
                    decrypted_note['content'] = caesar_cipher(decrypted_note['content'], 3, encrypt=False)
                
                # Add author information
                decrypted_note['author_id'] = author_id
                decrypted_note['author_name'] = author_name
                
                # Initialize likes if not exists
                if 'likes' not in decrypted_note:
                    decrypted_note['likes'] = []
                decrypted_note['like_count'] = len(decrypted_note['likes'])
                
                all_public_notes.append(decrypted_note)

    # Sort by creation date (newest first)
    all_public_notes.sort(key=lambda x: x.get('created_at', ''), reverse=True)

    return render_template('home.html', notes=all_public_notes, user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        users = load_users()
        for user_id, user in users.items():
            if user['email'] == email and check_password_hash(user['password'], password):
                session['user_id'] = user_id
                session['app_unlocked'] = not user.get('app_lock_enabled', False)
                return redirect(url_for('index'))

        flash('Email atau password salah', 'error')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validation
        if not all([name, email, password, confirm_password]):
            flash('Semua field harus diisi', 'error')
            return render_template('register.html')

        if password != confirm_password:
            flash('Password dan konfirmasi password tidak cocok', 'error')
            return render_template('register.html')

        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message, 'error')
            return render_template('register.html')

        users = load_users()

        # Check if email already exists
        for user in users.values():
            if user['email'] == email:
                flash('Email sudah terdaftar', 'error')
                return render_template('register.html')

        # Create new user
        user_id = str(len(users) + 1)
        users[user_id] = {
            'name': name,
            'email': email,
            'password': generate_password_hash(password),
            'app_lock_enabled': False,
            'app_lock_pin': '',
            'created_at': datetime.now().isoformat()
        }

        save_users(users)
        flash('Registrasi berhasil! Silakan login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    return redirect(url_for('login'))

@app.route('/note', methods=['GET', 'POST'])
def note():
    """Create new note"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Check app lock
    users = load_users()
    user = users.get(session['user_id'])
    if user and user.get('app_lock_enabled') and not session.get('app_unlocked'):
        return redirect(url_for('app_lock'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        is_locked = 'is_locked' in request.form
        is_public = 'is_public' in request.form

        if not title or not content:
            flash('Judul dan isi catatan harus diisi', 'error')
            return render_template('note.html', user=user)

        # Handle PIN for locked notes
        note_pin = None
        if is_locked:
            pin_option = request.form.get('pin_option', 'app_pin')

            if pin_option == 'custom_pin':
                note_pin = request.form.get('note_pin', '')
                if len(note_pin) != 4 or not note_pin.isdigit():
                    flash('PIN catatan harus 4 digit angka', 'error')
                    return render_template('note.html', user=user)
                note_pin = generate_password_hash(note_pin)
            elif pin_option == 'app_pin':
                if not user or not user.get('app_lock_pin'):
                    flash('Anda belum mengatur PIN App Lock. Silakan atur di Profile atau pilih PIN khusus.', 'error')
                    return render_template('note.html', user=user)
                note_pin = 'use_app_pin'  # Special marker to use app PIN

        notes = load_notes()
        if session['user_id'] not in notes:
            notes[session['user_id']] = []

        # Encrypt content with Caesar cipher
        encrypted_content = caesar_cipher(content, 3, encrypt=True)

        new_note = {
            'id': len(notes[session['user_id']]) + 1,
            'title': title,
            'content': encrypted_content,
            'encrypted': True,
            'is_locked': is_locked,
            'note_pin': note_pin,
            'created_at': datetime.now().isoformat(),
            'is_public': is_public # Add public flag
        }

        notes[session['user_id']].append(new_note)
        save_notes(notes)

        flash('Catatan berhasil disimpan!', 'success')
        return redirect(url_for('index'))

    return render_template('note.html', user=user)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    """User profile and settings"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Check app lock
    users = load_users()
    user = users.get(session['user_id'])
    if user and user.get('app_lock_enabled') and not session.get('app_unlocked'):
        return redirect(url_for('app_lock'))

    if request.method == 'POST' and user:
        action = request.form.get('action')

        if action == 'edit_profile':
            # Update profile information
            profile_name = request.form.get('profile_name', '').strip()
            profile_bio = request.form.get('profile_bio', '').strip()
            
            if profile_name:
                user['name'] = profile_name
            if profile_bio:
                user['bio'] = profile_bio
            
            save_users(users)
            flash('Profile berhasil diperbarui', 'success')

        elif action == 'upload_photo':
            # Handle profile photo upload
            if 'profile_photo' not in request.files:
                flash('No file selected', 'error')
                # Quick stats calculation for error return
                notes = load_notes()
                user_notes = notes.get(session['user_id'], [])
                public_notes_list = [note for note in user_notes if note.get('is_public', False)]
                total_likes = sum(len(note.get('likes', [])) for note in public_notes_list)
                stats = {'public_posts': len(public_notes_list), 'likes': total_likes}
                return render_template('profile.html', user=user, stats=stats, public_notes=public_notes_list)
            
            file = request.files['profile_photo']
            if file.filename == '':
                flash('No file selected', 'error')
                # Quick stats calculation for error return
                notes = load_notes()
                user_notes = notes.get(session['user_id'], [])
                public_notes_list = [note for note in user_notes if note.get('is_public', False)]
                total_likes = sum(len(note.get('likes', [])) for note in public_notes_list)
                stats = {'public_posts': len(public_notes_list), 'likes': total_likes}
                return render_template('profile.html', user=user, stats=stats, public_notes=public_notes_list)
            
            # Check file size (5MB limit)
            file.seek(0, os.SEEK_END)
            file_length = file.tell()
            if file_length > 5 * 1024 * 1024:  # 5MB
                flash('File size too large. Maximum 5MB allowed.', 'error')
                # Quick stats calculation for error return
                notes = load_notes()
                user_notes = notes.get(session['user_id'], [])
                public_notes_list = [note for note in user_notes if note.get('is_public', False)]
                total_likes = sum(len(note.get('likes', [])) for note in public_notes_list)
                stats = {'public_posts': len(public_notes_list), 'likes': total_likes}
                return render_template('profile.html', user=user, stats=stats, public_notes=public_notes_list)
            
            file.seek(0)  # Reset file pointer
            
            # Check file type
            allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
            filename = secure_filename(file.filename)
            file_ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
            
            if file_ext not in allowed_extensions:
                flash('Invalid file type. Please upload PNG, JPG, JPEG, or GIF.', 'error')
                # Quick stats calculation for error return
                notes = load_notes()
                user_notes = notes.get(session['user_id'], [])
                public_notes_list = [note for note in user_notes if note.get('is_public', False)]
                total_likes = sum(len(note.get('likes', [])) for note in public_notes_list)
                stats = {'public_posts': len(public_notes_list), 'likes': total_likes}
                return render_template('profile.html', user=user, stats=stats, public_notes=public_notes_list)
            
            # Read and encode file as base64
            file_data = file.read()
            file_base64 = base64.b64encode(file_data).decode('utf-8')
            
            # Save to user profile
            user['profile_photo'] = file_base64
            user['profile_photo_type'] = file_ext
            save_users(users)
            flash('Profile photo updated successfully!', 'success')

        elif action == 'remove_photo':
            # Remove profile photo
            if 'profile_photo' in user:
                del user['profile_photo']
            if 'profile_photo_type' in user:
                del user['profile_photo_type']
            save_users(users)
            flash('Profile photo removed successfully!', 'success')

        elif action == 'toggle_app_lock':
            if user.get('app_lock_enabled', False):
                # Disable app lock (keep PIN)
                user['app_lock_enabled'] = False
                flash('App lock dinonaktifkan', 'success')
            else:
                # Enable app lock (use existing PIN or create new one)
                if user.get('app_lock_pin'):
                    # Use existing PIN
                    user['app_lock_enabled'] = True
                    flash('App lock diaktifkan dengan PIN yang sudah ada', 'success')
                else:
                    # Need to create new PIN
                    app_lock_pin = request.form.get('app_lock_pin', '')
                    if len(app_lock_pin) != 4 or not app_lock_pin.isdigit():
                        flash('PIN harus 4 digit angka', 'error')
                        # Quick stats calculation for error return
                        notes = load_notes()
                        user_notes = notes.get(session['user_id'], [])
                        public_notes_list = [note for note in user_notes if note.get('is_public', False)]
                        total_likes = sum(len(note.get('likes', [])) for note in public_notes_list)
                        stats = {'public_posts': len(public_notes_list), 'likes': total_likes}
                        return render_template('profile.html', user=user, stats=stats, public_notes=public_notes_list)

                    user['app_lock_enabled'] = True
                    user['app_lock_pin'] = generate_password_hash(app_lock_pin)
                    flash('App lock diaktifkan dengan PIN baru', 'success')

            save_users(users)

        elif action == 'edit_pin':
            current_pin = request.form.get('current_pin', '')
            new_pin = request.form.get('new_pin', '')
            confirm_pin = request.form.get('confirm_pin', '')

            # Validate current PIN
            if not user.get('app_lock_pin') or not check_password_hash(user['app_lock_pin'], current_pin):
                flash('PIN saat ini salah', 'error')
                # Quick stats calculation for error return
                notes = load_notes()
                user_notes = notes.get(session['user_id'], [])
                public_notes_list = [note for note in user_notes if note.get('is_public', False)]
                total_likes = sum(len(note.get('likes', [])) for note in public_notes_list)
                stats = {'public_posts': len(public_notes_list), 'likes': total_likes}
                return render_template('profile.html', user=user, stats=stats, public_notes=public_notes_list)

            # Validate new PIN
            if len(new_pin) != 4 or not new_pin.isdigit():
                flash('PIN baru harus 4 digit angka', 'error')
                # Quick stats calculation for error return
                notes = load_notes()
                user_notes = notes.get(session['user_id'], [])
                public_notes_list = [note for note in user_notes if note.get('is_public', False)]
                total_likes = sum(len(note.get('likes', [])) for note in public_notes_list)
                stats = {'public_posts': len(public_notes_list), 'likes': total_likes}
                return render_template('profile.html', user=user, stats=stats, public_notes=public_notes_list)

            if new_pin != confirm_pin:
                flash('Konfirmasi PIN baru tidak cocok', 'error')
                # Quick stats calculation for error return
                notes = load_notes()
                user_notes = notes.get(session['user_id'], [])
                public_notes_list = [note for note in user_notes if note.get('is_public', False)]
                total_likes = sum(len(note.get('likes', [])) for note in public_notes_list)
                stats = {'public_posts': len(public_notes_list), 'likes': total_likes}
                return render_template('profile.html', user=user, stats=stats, public_notes=public_notes_list)

            # Update PIN
            user['app_lock_pin'] = generate_password_hash(new_pin)
            save_users(users)
            flash('PIN berhasil diubah', 'success')

    # Calculate user statistics
    notes = load_notes()
    user_notes = notes.get(session['user_id'], [])
    
    # Get only public notes and decrypt them
    public_notes_list = []
    for note in user_notes:
        if note.get('is_public', False):
            decrypted_note = note.copy()
            if decrypted_note.get('encrypted'):
                decrypted_note['content'] = caesar_cipher(decrypted_note['content'], 3, encrypt=False)
            public_notes_list.append(decrypted_note)
    
    # Count total likes received from public posts
    total_likes = sum(len(note.get('likes', [])) for note in public_notes_list)
    
    stats = {
        'public_posts': len(public_notes_list),
        'likes': total_likes
    }
    
    return render_template('profile.html', user=user, stats=stats, public_notes=public_notes_list)

@app.route('/view_note/<int:note_id>', methods=['GET', 'POST'])
def view_note(note_id):
    """View individual note with privacy lock enforcement"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Check app lock
    users = load_users()
    user = users.get(session['user_id'])
    if user and user.get('app_lock_enabled') and not session.get('app_unlocked'):
        return redirect(url_for('app_lock'))

    notes = load_notes()
    user_notes = notes.get(session['user_id'], [])

    # Find the specific note
    note = None
    for n in user_notes:
        if n.get('id') == note_id:
            note = n
            break

    if not note:
        flash('Catatan tidak ditemukan', 'error')
        return redirect(url_for('index'))

    # Handle relock request
    if request.method == 'POST':
        confirm = request.form.get('confirm')
        if confirm == 'no':
            # User wants to relock the note
            if f'note_unlocked_{note_id}' in session:
                del session[f'note_unlocked_{note_id}']
            return redirect(url_for('index'))

    # Check if note is locked and user hasn't confirmed
    if note.get('is_locked') and not session.get(f'note_unlocked_{note_id}'):
        if request.method == 'POST':
            confirm = request.form.get('confirm')
            if confirm == 'yes':
                # Check PIN if required
                if note.get('note_pin'):
                    entered_pin = request.form.get('note_pin', '')

                    if note['note_pin'] == 'use_app_pin':
                        # Use app lock PIN
                        if not user or not user.get('app_lock_pin') or not check_password_hash(user['app_lock_pin'], entered_pin):
                            flash('PIN App Lock salah', 'error')
                            return render_template('confirm_view.html', note=note, requires_pin=True, pin_type='app')
                    else:
                        # Use custom note PIN
                        if not check_password_hash(note['note_pin'], entered_pin):
                            flash('PIN catatan salah', 'error')
                            return render_template('confirm_view.html', note=note, requires_pin=True, pin_type='custom')

                session[f'note_unlocked_{note_id}'] = True
            else:
                return redirect(url_for('index'))
        else:
            # Determine if PIN is required and what type
            requires_pin = bool(note.get('note_pin'))
            pin_type = 'app' if note.get('note_pin') == 'use_app_pin' else 'custom'
            return render_template('confirm_view.html', note=note, requires_pin=requires_pin, pin_type=pin_type)

    # Decrypt note content for display
    if note.get('encrypted'):
        note['content'] = caesar_cipher(note['content'], 3, encrypt=False)

    return render_template('view_note.html', note=note)

@app.route('/edit_note/<int:note_id>', methods=['GET', 'POST'])
def edit_note(note_id):
    """Edit existing note with PIN verification for locked notes"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Check app lock
    users = load_users()
    user = users.get(session['user_id'])
    if user and user.get('app_lock_enabled') and not session.get('app_unlocked'):
        return redirect(url_for('app_lock'))

    notes = load_notes()
    user_notes = notes.get(session['user_id'], [])

    # Find the specific note
    note = None
    note_index = None
    for i, n in enumerate(user_notes):
        if n.get('id') == note_id:
            note = n
            note_index = i
            break

    if not note:
        flash('Catatan tidak ditemukan', 'error')
        return redirect(url_for('index'))

    # Check if note is locked and requires PIN verification
    if note.get('is_locked') and not session.get(f'edit_note_unlocked_{note_id}'):
        if request.method == 'POST':
            action = request.form.get('action')

            if action == 'verify_pin':
                entered_pin = request.form.get('note_pin', '')

                if note.get('note_pin'):
                    if note['note_pin'] == 'use_app_pin':
                        # Use app lock PIN
                        if not user or not user.get('app_lock_pin') or not check_password_hash(user['app_lock_pin'], entered_pin):
                            flash('PIN App Lock salah', 'error')
                            return render_template('verify_edit_pin.html', note=note, pin_type='app')
                    else:
                        # Use custom note PIN
                        if not check_password_hash(note['note_pin'], entered_pin):
                            flash('PIN catatan salah', 'error')
                            return render_template('verify_edit_pin.html', note=note, pin_type='custom')

                    session[f'edit_note_unlocked_{note_id}'] = True
                else:
                    session[f'edit_note_unlocked_{note_id}'] = True
            else:
                return redirect(url_for('index'))
        else:
            # Determine PIN type
            pin_type = 'app' if note.get('note_pin') == 'use_app_pin' else 'custom'
            requires_pin = bool(note.get('note_pin'))
            return render_template('verify_edit_pin.html', note=note, pin_type=pin_type, requires_pin=requires_pin)

    # Handle form submission for editing
    if request.method == 'POST' and request.form.get('action') == 'update':
        title = request.form['title']
        content = request.form['content']
        is_locked = 'is_locked' in request.form

        if not title or not content:
            flash('Judul dan isi catatan harus diisi', 'error')
            # Decrypt note content for display
            if note.get('encrypted'):
                note['content'] = caesar_cipher(note['content'], 3, encrypt=False)
            return render_template('edit_note.html', note=note, user=user)

        # Handle PIN for locked notes
        note_pin = note.get('note_pin')  # Keep existing PIN by default
        if is_locked:
            pin_option = request.form.get('pin_option', 'keep_existing')

            if pin_option == 'custom_pin':
                new_pin = request.form.get('note_pin', '')
                if len(new_pin) != 4 or not new_pin.isdigit():
                    flash('PIN catatan harus 4 digit angka', 'error')
                    if note.get('encrypted'):
                        note['content'] = caesar_cipher(note['content'], 3, encrypt=False)
                    return render_template('edit_note.html', note=note, user=user)
                note_pin = generate_password_hash(new_pin)
            elif pin_option == 'app_pin':
                if not user or not user.get('app_lock_pin'):
                    flash('Anda belum mengatur PIN App Lock. Silakan atur di Profile atau pilih PIN khusus.', 'error')
                    if note.get('encrypted'):
                        note['content'] = caesar_cipher(note['content'], 3, encrypt=False)
                    return render_template('edit_note.html', note=note, user=user)
                note_pin = 'use_app_pin'
        else:
            note_pin = None

        # Encrypt content with Caesar cipher
        encrypted_content = caesar_cipher(content, 3, encrypt=True)

        # Update note
        user_notes[note_index] = {
            'id': note['id'],
            'title': title,
            'content': encrypted_content,
            'encrypted': True,
            'is_locked': is_locked,
            'note_pin': note_pin,
            'created_at': note['created_at'],
            'updated_at': datetime.now().isoformat(),
            'is_public': is_locked # Update public flag, assuming it should be tied to lock status or handled differently if independent
        }

        notes[session['user_id']] = user_notes
        save_notes(notes)

        # Clear edit unlock session
        if f'edit_note_unlocked_{note_id}' in session:
            del session[f'edit_note_unlocked_{note_id}']

        flash('Catatan berhasil diperbarui!', 'success')
        return redirect(url_for('index'))

    # Decrypt note content for editing
    if note.get('encrypted'):
        note['content'] = caesar_cipher(note['content'], 3, encrypt=False)

    return render_template('edit_note.html', note=note, user=user)

@app.route('/delete_note/<int:note_id>', methods=['GET', 'POST'])
def delete_note(note_id):
    """Delete note with PIN verification for locked notes"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Check app lock
    users = load_users()
    user = users.get(session['user_id'])
    if user and user.get('app_lock_enabled') and not session.get('app_unlocked'):
        return redirect(url_for('app_lock'))

    notes = load_notes()
    user_notes = notes.get(session['user_id'], [])

    # Find the specific note
    note = None
    note_index = None
    for i, n in enumerate(user_notes):
        if n.get('id') == note_id:
            note = n
            note_index = i
            break

    if not note:
        flash('Catatan tidak ditemukan', 'error')
        return redirect(url_for('index'))

    # Check if note is locked and requires PIN verification
    if note.get('is_locked') and not session.get(f'delete_note_unlocked_{note_id}'):
        if request.method == 'POST':
            action = request.form.get('action')

            if action == 'verify_pin':
                entered_pin = request.form.get('note_pin', '')

                if note.get('note_pin'):
                    if note['note_pin'] == 'use_app_pin':
                        # Use app lock PIN
                        if not user or not user.get('app_lock_pin') or not check_password_hash(user['app_lock_pin'], entered_pin):
                            flash('PIN App Lock salah', 'error')
                            return render_template('verify_delete_pin.html', note=note, pin_type='app')
                    else:
                        # Use custom note PIN
                        if not check_password_hash(note['note_pin'], entered_pin):
                            flash('PIN catatan salah', 'error')
                            return render_template('verify_delete_pin.html', note=note, pin_type='custom')

                    session[f'delete_note_unlocked_{note_id}'] = True
                else:
                    session[f'delete_note_unlocked_{note_id}'] = True
            else:
                return redirect(url_for('index'))
        else:
            # Determine PIN type
            pin_type = 'app' if note.get('note_pin') == 'use_app_pin' else 'custom'
            requires_pin = bool(note.get('note_pin'))
            return render_template('verify_delete_pin.html', note=note, pin_type=pin_type, requires_pin=requires_pin)

    # Handle delete confirmation
    if request.method == 'POST' and request.form.get('action') == 'confirm_delete':
        # Delete the note
        user_notes.pop(note_index)
        notes[session['user_id']] = user_notes
        save_notes(notes)

        # Clear delete unlock session
        if f'delete_note_unlocked_{note_id}' in session:
            del session[f'delete_note_unlocked_{note_id}']

        flash('Catatan berhasil dihapus!', 'success')
        return redirect(url_for('index'))

    return render_template('confirm_delete.html', note=note)

@app.route('/my_notes')
def my_notes():
    """Display user's personal notes"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Check app lock
    users = load_users()
    user = users.get(session['user_id'])
    if user and user.get('app_lock_enabled') and not session.get('app_unlocked'):
        return redirect(url_for('app_lock'))

    notes = load_notes()
    user_notes = notes.get(session['user_id'], [])

    # Decrypt notes for display, but not locked ones
    for note in user_notes:
        if note.get('encrypted') and not note.get('is_locked'):
            note['content'] = caesar_cipher(note['content'], 3, encrypt=False)
        elif note.get('is_locked'):
            # Keep locked notes encrypted, set placeholder
            note['content_preview'] = 'Catatan ini terkunci. Klik untuk membuka.'

    return render_template('my_notes.html', notes=user_notes, user=user)

@app.route('/like_note/<int:note_id>/<author_id>', methods=['POST'])
def like_note(note_id, author_id):
    """Toggle like status for a note"""
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    notes = load_notes()
    if author_id not in notes:
        return jsonify({'error': 'Note not found'}), 404

    # Find the note
    note = None
    note_index = None
    for i, n in enumerate(notes[author_id]):
        if n.get('id') == note_id:
            note = n
            note_index = i
            break

    if not note:
        return jsonify({'error': 'Note not found'}), 404

    # Initialize likes if not exists
    if 'likes' not in note:
        note['likes'] = []

    user_id = session['user_id']
    
    # Toggle like
    if user_id in note['likes']:
        note['likes'].remove(user_id)
        liked = False
    else:
        note['likes'].append(user_id)
        liked = True

    # Update note in database
    notes[author_id][note_index] = note
    save_notes(notes)

    return jsonify({
        'liked': liked,
        'like_count': len(note['likes'])
    })

@app.route('/app_lock', methods=['GET', 'POST'])
def app_lock():
    """App lock screen"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    users = load_users()
    user = users.get(session['user_id'])

    if not user or not user.get('app_lock_enabled'):
        return redirect(url_for('index'))

    if request.method == 'POST' and user:
        pin = request.form['pin']

        if user.get('app_lock_pin') and check_password_hash(user['app_lock_pin'], pin):
            session['app_unlocked'] = True
            return redirect(url_for('index'))
        else:
            flash('PIN salah', 'error')

    return render_template('app_lock.html')

@app.route('/publish_notes', methods=['GET', 'POST'])
def publish_notes():
    """Show unpublished notes for publishing"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Check app lock
    users = load_users()
    user = users.get(session['user_id'])
    if user and user.get('app_lock_enabled') and not session.get('app_unlocked'):
        return redirect(url_for('app_lock'))

    notes = load_notes()
    user_notes = notes.get(session['user_id'], [])

    if request.method == 'POST':
        selected_note_ids = request.form.getlist('selected_notes')
        if selected_note_ids:
            # Update selected notes to be public
            for i, note in enumerate(user_notes):
                if str(note['id']) in selected_note_ids:
                    user_notes[i]['is_public'] = True
            
            notes[session['user_id']] = user_notes
            save_notes(notes)
            
            flash(f'{len(selected_note_ids)} catatan berhasil dipublikasikan!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Pilih minimal satu catatan untuk dipublikasikan', 'error')

    # Get unpublished notes (not public)
    unpublished_notes = []
    for note in user_notes:
        if not note.get('is_public', False):
            # Decrypt content for display
            decrypted_note = note.copy()
            if decrypted_note.get('encrypted'):
                decrypted_note['content'] = caesar_cipher(decrypted_note['content'], 3, encrypt=False)
            unpublished_notes.append(decrypted_note)

    return render_template('publish_notes.html', notes=unpublished_notes, user=user)

@app.route('/get_profile_photo/<user_id>')
def get_profile_photo(user_id):
    """Serve user's profile photo"""
    users = load_users()
    user = users.get(user_id)
    
    if not user or 'profile_photo' not in user:
        return '', 404
    
    try:
        # Decode base64 image
        image_data = base64.b64decode(user['profile_photo'])
        file_type = user.get('profile_photo_type', 'jpg')
        
        # Set correct MIME type
        mime_type = f'image/{file_type}'
        if file_type == 'jpg':
            mime_type = 'image/jpeg'
        
        return Response(image_data, mimetype=mime_type)
    except:
        return '', 404

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    """App settings page"""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Check app lock
    users = load_users()
    user = users.get(session['user_id'])
    if user and user.get('app_lock_enabled') and not session.get('app_unlocked'):
        return redirect(url_for('app_lock'))

    if request.method == 'POST' and user:
        action = request.form.get('action')

        if action == 'toggle_app_lock':
            if user.get('app_lock_enabled', False):
                # Disable app lock (keep PIN)
                user['app_lock_enabled'] = False
                flash('App lock dinonaktifkan', 'success')
            else:
                # Enable app lock (use existing PIN or create new one)
                if user.get('app_lock_pin'):
                    # Use existing PIN
                    user['app_lock_enabled'] = True
                    flash('App lock diaktifkan dengan PIN yang sudah ada', 'success')
                else:
                    # Need to create new PIN
                    app_lock_pin = request.form.get('app_lock_pin', '')
                    if len(app_lock_pin) != 4 or not app_lock_pin.isdigit():
                        flash('PIN harus 4 digit angka', 'error')
                        return render_template('settings.html', user=user)

                    user['app_lock_enabled'] = True
                    user['app_lock_pin'] = generate_password_hash(app_lock_pin)
                    flash('App lock diaktifkan dengan PIN baru', 'success')

            save_users(users)

        elif action == 'edit_pin':
            current_pin = request.form.get('current_pin', '')
            new_pin = request.form.get('new_pin', '')
            confirm_pin = request.form.get('confirm_pin', '')

            # Validate current PIN
            if not user.get('app_lock_pin') or not check_password_hash(user['app_lock_pin'], current_pin):
                flash('PIN saat ini salah', 'error')
                return render_template('settings.html', user=user)

            # Validate new PIN
            if len(new_pin) != 4 or not new_pin.isdigit():
                flash('PIN baru harus 4 digit angka', 'error')
                return render_template('settings.html', user=user)

            if new_pin != confirm_pin:
                flash('Konfirmasi PIN baru tidak cocok', 'error')
                return render_template('settings.html', user=user)

            # Update PIN
            user['app_lock_pin'] = generate_password_hash(new_pin)
            save_users(users)
            flash('PIN berhasil diubah', 'success')

    return render_template('settings.html', user=user)

if __name__ == '__main__':
    init_database()
    app.run(host='0.0.0.0', port=5000, debug=True)