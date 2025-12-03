from flask import Flask, render_template, request, redirect, url_for, flash, session
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = "your_secret_key_here"  # Replace with a strong random key

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Serializer for generating timed tokens for password reset
serializer = URLSafeTimedSerializer(app.secret_key)


def send_reset_email(destination, reset_url):
    """Development helper: prints reset URL to server console.
    If you configure SMTP server settings, replace this implementation to actually send email.
    """
    # In production: use SMTP or an email service (SendGrid/Mailgun) here.
    print('\n[Password Reset] Sending reset link to:', destination)
    print(reset_url)
    print('')

# -------------------- Helper Functions --------------------

def log_activity(user_id, action, book_id=None, book_title=None, list_name=None):
    """Log user activity for the activity feed."""
    activity = UserActivity(user_id=user_id, action=action, book_id=book_id, book_title=book_title, list_name=list_name)
    db.session.add(activity)
    db.session.commit()

# -------------------- Models --------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    favorites = db.relationship('Favorite', backref='user', lazy=True)
    want_to_read = db.relationship('WantToRead', backref='user', lazy=True)
    read_books = db.relationship('AlreadyRead', backref='user', lazy=True)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    authors = db.Column(db.String(255))
    description = db.Column(db.Text)
    category = db.Column(db.String(100))
    publisher = db.Column(db.String(100))
    publish_date = db.Column(db.String(50))
    price = db.Column(db.String(50))
    image_url = db.Column(db.String(500))
    is_bestseller = db.Column(db.Boolean, default=False)
    sales_millions = db.Column(db.Integer)  # Approximate sales in millions
    average_rating = db.Column(db.Float)  # Average rating
    num_pages = db.Column(db.Integer)  # Number of pages
    ratings_count = db.Column(db.Integer)  # Number of ratings

class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    book = db.relationship('Book')


# New lists: WantToRead and AlreadyRead
class WantToRead(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    book = db.relationship('Book')


class AlreadyRead(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    book = db.relationship('Book')


# Custom lists created by users
class CustomList(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=db.func.now())
    books = db.relationship('ListBook', backref='custom_list', lazy=True, cascade='all, delete-orphan')


class ListBook(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    list_id = db.Column(db.Integer, db.ForeignKey('custom_list.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    book = db.relationship('Book')


# Book Diary - Track when users read books
class BookDiary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    book = db.relationship('Book')
    entry_date = db.Column(db.Date, nullable=False)  # Day, Month, Year when book was read
    notes = db.Column(db.Text)  # Optional notes about the book
    created_at = db.Column(db.DateTime, default=db.func.now())


# User Activity Log - Track user actions
class UserActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)  # e.g., "added_to_favorites", "created_list"
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'))
    book_title = db.Column(db.String(255))  # Book title at time of action
    list_name = db.Column(db.String(100))  # List name if applicable
    timestamp = db.Column(db.DateTime, default=db.func.now())

# -------------------- Routes --------------------

@app.route('/', methods=['GET'])
def home():
    search_query = request.args.get('search')
    category_filter = request.args.get('category')

    query = Book.query

    if search_query:
        query = query.filter(
            (Book.title.ilike(f"%{search_query}%")) |
            (Book.authors.ilike(f"%{search_query}%"))
        )

    if category_filter:
        # Use case-insensitive partial matching so button labels match DB categories more broadly
        query = query.filter(Book.category.ilike(f"%{category_filter}%"))

    if search_query or category_filter:
        books = query.limit(50).all()
    else:
        books = query.limit(12).all()

    categories = Book.query.with_entities(Book.category).distinct().all()

    # Get best-selling books
    bestsellers = Book.query.filter_by(is_bestseller=True).order_by(Book.sales_millions.desc()).limit(6).all()

    # Prepare genre buttons (12 common genres to show under search bar)
    genres = [
        "Fiction",
        "Fantasy",
        "Science Fiction",
        "Mystery/Crime/Thriller",
        "Romance",
        "Biography/Autobiography/Memoir",
        "Non-Fiction",
        "Self-Help/Personal Development",
        "History",
        "Religion/Spirituality",
        "Psychology",
        "Young Adult (YA)"
    ]

    # Get favorite book ids for logged-in user
    fav_ids = []
    if 'user_id' in session:
        fav_ids = [f.book_id for f in Favorite.query.filter_by(user_id=session['user_id']).all()]
    # Recent diary entries for homepage (not a full list)
    diary_entries = []
    if 'user_id' in session:
        diary_entries = BookDiary.query.filter_by(user_id=session['user_id']).order_by(BookDiary.entry_date.desc()).limit(5).all()

    return render_template('index.html', books=books, categories=categories, bestsellers=bestsellers, fav_ids=fav_ids, search_query=search_query, category_filter=category_filter, genres=genres, diary_entries=diary_entries)

# -------------------- User Authentication --------------------

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "error")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash("Logged in successfully!", "success")
            return redirect(url_for('home'))
        else:
            flash("Invalid username or password", "error")
            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()

        # The app currently stores only username, not email. We accept username here.
        user = User.query.filter_by(username=identifier).first()
        if not user:
            # If user doesn't exist, show generic message to avoid leaking usernames
            flash('If an account with that username exists, you will be redirected to reset the password.', 'info')
            return redirect(url_for('login'))

        # User exists — redirect directly to the reset page for that username.
        # NOTE: This bypasses email verification intentionally per user request.
        return redirect(url_for('reset_direct', username=user.username))

    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        data = serializer.loads(token, salt='password-reset-salt', max_age=86400)  # 24 hours
        user_id = data.get('user_id')
    except SignatureExpired:
        flash('This reset link has expired. Please request a new one.', 'error')
        return redirect(url_for('forgot_password'))
    except BadSignature:
        flash('Invalid reset token. Please request a new password reset.', 'error')
        return redirect(url_for('forgot_password'))

    user = User.query.get(user_id)
    if not user:
        flash('Invalid user. Please request a new password reset.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('password', '').strip()
        confirm = request.form.get('confirm_password', '').strip()
        if not new_password or new_password != confirm:
            flash('Passwords do not match or are empty.', 'error')
            return redirect(url_for('reset_password', token=token))

        user.password = generate_password_hash(new_password)
        db.session.commit()
        flash('Password updated successfully. Please log in with your new password.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


@app.route('/reset_direct/<username>', methods=['GET', 'POST'])
def reset_direct(username):
    # Direct username-based reset (no email). This will immediately allow a password change
    # for the given username if it exists. Use with caution — this reveals account existence.
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('Invalid username. Please request a password reset again.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('password', '').strip()
        confirm = request.form.get('confirm_password', '').strip()
        if not new_password or new_password != confirm:
            flash('Passwords do not match or are empty.', 'error')
            return redirect(url_for('reset_direct', username=username))

        user.password = generate_password_hash(new_password)
        db.session.commit()
        flash('Password updated successfully. Please log in with your new password.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_direct.html', username=username)


@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully", "success")
    return redirect(url_for('home'))

# -------------------- Favorites --------------------

@app.route('/add_favorite/<int:book_id>')
def add_favorite(book_id):
    if 'user_id' not in session:
        flash("You must be logged in to add favorites.", "error")
        return redirect(url_for('login'))

    existing = Favorite.query.filter_by(user_id=session['user_id'], book_id=book_id).first()
    if not existing:
        book = Book.query.get(book_id)
        fav = Favorite(user_id=session['user_id'], book_id=book_id)
        db.session.add(fav)
        db.session.commit()
        log_activity(session['user_id'], 'added_to_favorites', book_id, book.title if book else None)
        flash("Book added to favorites!", "success")
    else:
        flash("Book is already in favorites.", "info")

    return redirect(url_for('home'))


@app.route('/view_favorites')
def view_favorites():
    if 'user_id' not in session:
        flash("You must be logged in to view favorites.", "error")
        return redirect(url_for('login'))

    fav_books = [f.book for f in Favorite.query.filter_by(user_id=session['user_id']).all()]
    return render_template('favorites.html', books=fav_books)


@app.route('/remove_favorite/<int:book_id>')
def remove_favorite(book_id):
    if 'user_id' not in session:
        flash("You must be logged in to remove favorites.", "error")
        return redirect(url_for('login'))

    fav = Favorite.query.filter_by(user_id=session['user_id'], book_id=book_id).first()
    if fav:
        db.session.delete(fav)
        db.session.commit()
        flash("Book removed from favorites.", "success")
    else:
        flash("Book not found in favorites.", "error")

    return redirect(url_for('view_favorites'))


# -------------------- Want To Read --------------------
@app.route('/add_want/<int:book_id>')
def add_want(book_id):
    if 'user_id' not in session:
        flash("You must be logged in to add books.", "error")
        return redirect(url_for('login'))

    existing = WantToRead.query.filter_by(user_id=session['user_id'], book_id=book_id).first()
    if not existing:
        book = Book.query.get(book_id)
        entry = WantToRead(user_id=session['user_id'], book_id=book_id)
        db.session.add(entry)
        db.session.commit()
        log_activity(session['user_id'], 'added_to_want_to_read', book_id, book.title if book else None)
        flash("Book added to Want to Read!", "success")
    else:
        flash("Book is already in your Want to Read list.", "info")

    return redirect(url_for('home'))


@app.route('/view_want_to_read')
def view_want_to_read():
    if 'user_id' not in session:
        flash("You must be logged in to view this list.", "error")
        return redirect(url_for('login'))

    books = [e.book for e in WantToRead.query.filter_by(user_id=session['user_id']).all()]
    return render_template('want_to_read.html', books=books)


@app.route('/remove_want/<int:book_id>')
def remove_want(book_id):
    if 'user_id' not in session:
        flash("You must be logged in to remove books.", "error")
        return redirect(url_for('login'))

    entry = WantToRead.query.filter_by(user_id=session['user_id'], book_id=book_id).first()
    if entry:
        db.session.delete(entry)
        db.session.commit()
        flash("Book removed from Want to Read.", "success")
    else:
        flash("Book not found in your Want to Read list.", "error")

    return redirect(url_for('view_want_to_read'))


# -------------------- Already Read --------------------
@app.route('/add_read/<int:book_id>')
def add_read(book_id):
    if 'user_id' not in session:
        flash("You must be logged in to add books.", "error")
        return redirect(url_for('login'))

    existing = AlreadyRead.query.filter_by(user_id=session['user_id'], book_id=book_id).first()
    if not existing:
        book = Book.query.get(book_id)
        entry = AlreadyRead(user_id=session['user_id'], book_id=book_id)
        db.session.add(entry)
        db.session.commit()
        log_activity(session['user_id'], 'marked_as_read', book_id, book.title if book else None)
        flash("Book marked as read!", "success")
    else:
        flash("Book is already marked as read.", "info")

    return redirect(url_for('home'))


@app.route('/view_read')
def view_read():
    if 'user_id' not in session:
        flash("You must be logged in to view this list.", "error")
        return redirect(url_for('login'))

    books = [e.book for e in AlreadyRead.query.filter_by(user_id=session['user_id']).all()]
    return render_template('read.html', books=books)


@app.route('/remove_read/<int:book_id>')
def remove_read(book_id):
    if 'user_id' not in session:
        flash("You must be logged in to remove books.", "error")
        return redirect(url_for('login'))

    entry = AlreadyRead.query.filter_by(user_id=session['user_id'], book_id=book_id).first()
    if entry:
        db.session.delete(entry)
        db.session.commit()
        flash("Book removed from Read list.", "success")
    else:
        flash("Book not found in your Read list.", "error")

    return redirect(url_for('view_read'))


# -------------------- My Lists (Custom & Built-in) --------------------

@app.route('/my_lists')
def my_lists():
    if 'user_id' not in session:
        flash("You must be logged in to view your lists.", "error")
        return redirect(url_for('login'))

    custom_lists = CustomList.query.filter_by(user_id=session['user_id']).all()
    fav_books = [f.book for f in Favorite.query.filter_by(user_id=session['user_id']).all()]
    want_books = [e.book for e in WantToRead.query.filter_by(user_id=session['user_id']).all()]
    read_books = [e.book for e in AlreadyRead.query.filter_by(user_id=session['user_id']).all()]
    fav_count = len(fav_books)
    want_count = len(want_books)
    read_count = len(read_books)
    
    # Get active tab from query parameter, default to 'favorites'
    active_tab = request.args.get('tab', 'favorites')

    return render_template('my_lists.html', 
                          custom_lists=custom_lists,
                          fav_books=fav_books,
                          want_books=want_books,
                          read_books=read_books,
                          fav_count=fav_count,
                          want_count=want_count,
                          read_count=read_count,
                          active_tab=active_tab)


@app.route('/create_list', methods=['GET', 'POST'])
def create_list():
    if 'user_id' not in session:
        flash("You must be logged in to create a list.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()

        if not name:
            flash("List name is required.", "error")
            return redirect(url_for('create_list'))

        existing = CustomList.query.filter_by(user_id=session['user_id'], name=name).first()
        if existing:
            flash("You already have a list with this name.", "error")
            return redirect(url_for('create_list'))

        new_list = CustomList(user_id=session['user_id'], name=name, description=description)
        db.session.add(new_list)
        db.session.commit()
        log_activity(session['user_id'], 'created_list', list_name=name)
        flash(f"List '{name}' created successfully!", "success")
        return redirect(url_for('my_lists'))

    return render_template('create_list.html')


@app.route('/view_custom_list/<int:list_id>')
def view_custom_list(list_id):
    if 'user_id' not in session:
        flash("You must be logged in to view this list.", "error")
        return redirect(url_for('login'))

    custom_list = CustomList.query.get_or_404(list_id)
    
    # Check if user owns this list
    if custom_list.user_id != session['user_id']:
        flash("You don't have permission to view this list.", "error")
        return redirect(url_for('my_lists'))

    books = [lb.book for lb in custom_list.books]
    return render_template('view_custom_list.html', list=custom_list, books=books)


@app.route('/add_to_custom_list/<int:book_id>/<int:list_id>')
def add_to_custom_list(book_id, list_id):
    if 'user_id' not in session:
        flash("You must be logged in.", "error")
        return redirect(url_for('login'))

    custom_list = CustomList.query.get_or_404(list_id)
    
    # Check if user owns this list
    if custom_list.user_id != session['user_id']:
        flash("You don't have permission to edit this list.", "error")
        return redirect(url_for('home'))

    existing = ListBook.query.filter_by(list_id=list_id, book_id=book_id).first()
    if not existing:
        entry = ListBook(list_id=list_id, book_id=book_id)
        db.session.add(entry)
        db.session.commit()
        flash(f"Book added to '{custom_list.name}'!", "success")
    else:
        flash("Book is already in this list.", "info")

    return redirect(url_for('view_custom_list', list_id=list_id))


@app.route('/remove_from_custom_list/<int:book_id>/<int:list_id>')
def remove_from_custom_list(book_id, list_id):
    if 'user_id' not in session:
        flash("You must be logged in.", "error")
        return redirect(url_for('login'))

    custom_list = CustomList.query.get_or_404(list_id)
    
    # Check if user owns this list
    if custom_list.user_id != session['user_id']:
        flash("You don't have permission to edit this list.", "error")
        return redirect(url_for('my_lists'))

    entry = ListBook.query.filter_by(list_id=list_id, book_id=book_id).first()
    if entry:
        db.session.delete(entry)
        db.session.commit()
        flash("Book removed from list.", "success")
    else:
        flash("Book not found in this list.", "error")

    return redirect(url_for('view_custom_list', list_id=list_id))


@app.route('/delete_list/<int:list_id>')
def delete_list(list_id):
    if 'user_id' not in session:
        flash("You must be logged in.", "error")
        return redirect(url_for('login'))

    custom_list = CustomList.query.get_or_404(list_id)
    
    # Check if user owns this list
    if custom_list.user_id != session['user_id']:
        flash("You don't have permission to delete this list.", "error")
        return redirect(url_for('my_lists'))

    list_name = custom_list.name
    db.session.delete(custom_list)
    db.session.commit()
    flash(f"List '{list_name}' deleted.", "success")
    return redirect(url_for('my_lists'))


# -------------------- Book Diary --------------------

@app.route('/add_to_diary/<int:book_id>', methods=['GET', 'POST'])
def add_to_diary(book_id):
    if 'user_id' not in session:
        flash("You must be logged in to use the diary.", "error")
        return redirect(url_for('login'))

    book = Book.query.get_or_404(book_id)

    if request.method == 'POST':
        day = request.form.get('day')
        month = request.form.get('month')
        year = request.form.get('year')
        notes = request.form.get('notes', '').strip()

        try:
            entry_date = datetime(int(year), int(month), int(day)).date()
        except (ValueError, TypeError):
            flash("Invalid date. Please enter a valid day, month, and year.", "error")
            return redirect(url_for('add_to_diary', book_id=book_id))

        # Check if entry already exists
        existing = BookDiary.query.filter_by(user_id=session['user_id'], book_id=book_id, entry_date=entry_date).first()
        if existing:
            flash("You already have a diary entry for this book on this date.", "info")
            return redirect(url_for('add_to_diary', book_id=book_id))

        entry = BookDiary(user_id=session['user_id'], book_id=book_id, entry_date=entry_date, notes=notes)
        db.session.add(entry)
        db.session.commit()
        log_activity(session['user_id'], 'added_to_diary', book_id, book.title)
        flash(f"'{book.title}' added to your diary!", "success")
        return redirect(url_for('view_diary'))

    return render_template('add_to_diary.html', book=book)


@app.route('/view_diary')
def view_diary():
    if 'user_id' not in session:
        flash("You must be logged in to view your diary.", "error")
        return redirect(url_for('login'))

    # Get all diary entries for this user, sorted by date (newest first)
    entries = BookDiary.query.filter_by(user_id=session['user_id']).order_by(BookDiary.entry_date.desc()).all()
    return render_template('view_diary.html', entries=entries)


@app.route('/remove_diary_entry/<int:entry_id>')
def remove_diary_entry(entry_id):
    if 'user_id' not in session:
        flash("You must be logged in.", "error")
        return redirect(url_for('login'))

    entry = BookDiary.query.get_or_404(entry_id)
    
    # Check if user owns this entry
    if entry.user_id != session['user_id']:
        flash("You don't have permission to delete this entry.", "error")
        return redirect(url_for('view_diary'))

    book_title = entry.book.title
    db.session.delete(entry)
    db.session.commit()
    flash(f"Diary entry for '{book_title}' removed.", "success")
    return redirect(url_for('view_diary'))


# -------------------- User Profile --------------------

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash("You must be logged in to view your profile.", "error")
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    
    # Get activity feed (last 15 activities)
    activities = UserActivity.query.filter_by(user_id=session['user_id']).order_by(UserActivity.timestamp.desc()).limit(15).all()
    
    # Get statistics
    fav_count = Favorite.query.filter_by(user_id=session['user_id']).count()
    want_count = WantToRead.query.filter_by(user_id=session['user_id']).count()
    read_count = AlreadyRead.query.filter_by(user_id=session['user_id']).count()
    diary_count = BookDiary.query.filter_by(user_id=session['user_id']).count()
    list_count = CustomList.query.filter_by(user_id=session['user_id']).count()

    return render_template('profile.html', 
                          user=user, 
                          activities=activities,
                          fav_count=fav_count,
                          want_count=want_count,
                          read_count=read_count,
                          diary_count=diary_count,
                          list_count=list_count)


@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        flash("You must be logged in to edit your profile.", "error")
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        new_username = request.form.get('username', '').strip()
        new_password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        # Check if new username is already taken (by another user)
        if new_username and new_username != user.username:
            existing = User.query.filter_by(username=new_username).first()
            if existing:
                flash("Username already taken.", "error")
                return redirect(url_for('edit_profile'))
            user.username = new_username

        # Change password if provided
        if new_password:
            if new_password != confirm_password:
                flash("Passwords do not match.", "error")
                return redirect(url_for('edit_profile'))
            if len(new_password) < 4:
                flash("Password must be at least 4 characters.", "error")
                return redirect(url_for('edit_profile'))
            user.password = generate_password_hash(new_password)

        db.session.commit()
        log_activity(session['user_id'], 'updated_profile')
        flash("Profile updated successfully!", "success")
        return redirect(url_for('profile'))

    return render_template('edit_profile.html', user=user)


# -------------------- Book Details --------------------

def find_similar_books(book, limit=6):
    """Find similar books based on author, category, or title patterns."""
    similar = []
    
    # 1. Find books by the same author
    if book.authors:
        author_books = Book.query.filter(
            Book.authors.ilike(f"%{book.authors}%"),
            Book.id != book.id
        ).limit(limit).all()
        similar.extend(author_books)
    
    # 2. Find books in the same category
    if book.category and len(similar) < limit:
        category_books = Book.query.filter(
            Book.category == book.category,
            Book.id != book.id,
            ~Book.id.in_([b.id for b in similar])  # Avoid duplicates
        ).limit(limit - len(similar)).all()
        similar.extend(category_books)
    
    # 3. If still need more, find books with similar words in title (for series detection)
    if len(similar) < limit:
        title_words = book.title.split()
        for word in title_words:
            if len(word) > 3:  # Only meaningful words
                title_books = Book.query.filter(
                    Book.title.ilike(f"%{word}%"),
                    Book.id != book.id,
                    ~Book.id.in_([b.id for b in similar])
                ).limit(limit - len(similar)).all()
                similar.extend(title_books)
                if len(similar) >= limit:
                    break
    
    return similar[:limit]


def aggregate_recommendations_from_sources(source_books, exclude_ids=None, limit=12):
    """Aggregate similar books for a list of source books.
    Returns a list of (book, score, reasons) where score is frequency-based and reasons list matching sources.
    """
    from collections import Counter, defaultdict

    if exclude_ids is None:
        exclude_ids = set()

    counter = Counter()
    reasons = defaultdict(list)

    for src in source_books:
        sims = find_similar_books(src, limit=8)
        for s in sims:
            if s.id in exclude_ids or s.id == src.id:
                continue
            counter[s.id] += 1
            reasons[s.id].append(src.title)

    # Build list of (book, score, reasons) sorted by score then by title
    results = []
    for book_id, score in counter.most_common():
        book = Book.query.get(book_id)
        if book:
            results.append((book, score, reasons[book_id]))
        if len(results) >= limit:
            break

    return results


@app.route('/book/<int:book_id>')
def book_detail(book_id):
    book = Book.query.get_or_404(book_id)
    similar_books = find_similar_books(book)
    custom_lists = []
    if 'user_id' in session:
        custom_lists = CustomList.query.filter_by(user_id=session['user_id']).all()
    return render_template('book_detail.html', book=book, similar_books=similar_books, custom_lists=custom_lists)


@app.route('/recommend/diary')
def recommend_from_diary():
    if 'user_id' not in session:
        flash("You must be logged in to see recommendations.", "error")
        return redirect(url_for('login'))

    # Get last 5 diary entries
    entries = BookDiary.query.filter_by(user_id=session['user_id']).order_by(BookDiary.entry_date.desc()).limit(5).all()
    if not entries:
        flash("No diary entries found. Add some diary entries to get personalized recommendations.", "info")
        return redirect(url_for('profile'))

    source_books = [e.book for e in entries if e.book]

    # Exclude already seen books (favorites, read, diary entries)
    seen_ids = set()
    seen_ids.update([f.book_id for f in Favorite.query.filter_by(user_id=session['user_id']).all()])
    seen_ids.update([r.book_id for r in AlreadyRead.query.filter_by(user_id=session['user_id']).all()])
    seen_ids.update([e.book_id for e in BookDiary.query.filter_by(user_id=session['user_id']).all()])

    recs = aggregate_recommendations_from_sources(source_books, exclude_ids=seen_ids, limit=12)

    return render_template('recommendations.html', title='Recommendations — From Your Diary', recs=recs)


@app.route('/recommend/favorites')
def recommend_from_favorites():
    if 'user_id' not in session:
        flash("You must be logged in to see recommendations.", "error")
        return redirect(url_for('login'))

    favs = Favorite.query.filter_by(user_id=session['user_id']).all()
    if not favs:
        flash("No favorites found. Add some favorite books to get personalized recommendations.", "info")
        return redirect(url_for('profile'))

    source_books = [f.book for f in favs if f.book]

    seen_ids = set()
    seen_ids.update([f.book_id for f in Favorite.query.filter_by(user_id=session['user_id']).all()])
    seen_ids.update([r.book_id for r in AlreadyRead.query.filter_by(user_id=session['user_id']).all()])
    seen_ids.update([e.book_id for e in BookDiary.query.filter_by(user_id=session['user_id']).all()])

    recs = aggregate_recommendations_from_sources(source_books, exclude_ids=seen_ids, limit=12)

    return render_template('recommendations.html', title='Recommendations — From Your Favorites', recs=recs)


@app.route('/recommend')
def recommend_hub():
    # Hub page to let users choose recommendation source
    if 'user_id' not in session:
        flash("You must be logged in to see recommendations.", "error")
        return redirect(url_for('login'))

    return render_template('recommend_hub.html')

# -------------------- Run App --------------------

if __name__ == '__main__':
    app.run(debug=True)
