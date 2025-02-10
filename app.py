from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from slugify import slugify
import markdown2
import os

app = Flask(__name__)
app.config.from_object('config.Config')

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    posts = db.relationship('Post', backref='author', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(200), unique=True, nullable=False)
    content = db.Column(db.Text, nullable=False)
    image_path = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __init__(self, *args, **kwargs):
        if not 'slug' in kwargs:
            kwargs['slug'] = slugify(kwargs.get('title', ''))
        super().__init__(*args, **kwargs)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    sort_by = request.args.get('sort', 'created_at')
    order = request.args.get('order', 'desc')
    
    if sort_by not in ['title', 'created_at']:
        sort_by = 'created_at'
    
    query = Post.query
    if sort_by == 'title':
        query = query.order_by(Post.title.asc() if order == 'asc' else Post.title.desc())
    else:
        query = query.order_by(Post.created_at.asc() if order == 'asc' else Post.created_at.desc())
    
    posts = query.all()
    return render_template('home.html', posts=posts)

@app.route('/post/<slug>')
def post(slug):
    post = Post.query.filter_by(slug=slug).first_or_404()
    content = markdown2.markdown(post.content)
    return render_template('post.html', post=post, content=content)

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        image = request.files.get('image')
        
        if image:
            filename = secure_filename(image.filename)
            # Save with relative path for database
            image_path = os.path.join('uploads', filename)
            # Use absolute path for saving file
            abs_image_path = os.path.join(app.static_folder, image_path)
            image.save(abs_image_path)
        else:
            image_path = None
            
        post = Post(
            title=title,
            content=content,
            image_path=image_path,
            user_id=current_user.id
        )
        
        db.session.add(post)
        db.session.commit()
        
        return redirect(url_for('post', slug=post.slug))
    
    return render_template('create.html')

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    post = Post.query.get_or_404(id)
    
    if post.author != current_user and not current_user.is_admin:
        abort(403)
        
    if request.method == 'POST':
        post.title = request.form.get('title')
        post.content = request.form.get('content')
        post.updated_at = datetime.utcnow()
        
        image = request.files.get('image')
        if image:
            filename = secure_filename(image.filename)
            # Save with relative path for database
            image_path = os.path.join('uploads', filename)
            # Use absolute path for saving file
            abs_image_path = os.path.join(app.static_folder, image_path)
            image.save(abs_image_path)
            post.image_path = image_path
            
        db.session.commit()
        return redirect(url_for('post', slug=post.slug))
        
    return render_template('edit.html', post=post)

@app.route('/delete/<int:id>')
@login_required
def delete(id):
    post = Post.query.get_or_404(id)
    
    if post.author != current_user and not current_user.is_admin:
        abort(403)
        
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('home'))

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))
        
        flash('Invalid username or password')
    return render_template('auth/login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# Admin routes
@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        abort(403)
    return render_template('admin/dashboard.html')

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

if __name__ == '__main__':
    # Create required directories
    uploads_dir = os.path.join(app.static_folder, 'uploads')
    os.makedirs(uploads_dir, exist_ok=True)
    
    with app.app_context():
        db.create_all()
        # Create default admin user if it doesn't exist
        admin = User.query.filter_by(username='nosferatu').first()
        if not admin:
            admin = User(username='nosferatu', is_admin=True)
            admin.set_password('C0untDr4cul4@666')
            db.session.add(admin)
            db.session.commit()
    
    app.run(debug=True) 