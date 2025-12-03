# app.py

# --- IMPORTS & SETUP ---
import os
import random 
from io import StringIO 
from flask import Flask, render_template, url_for, redirect, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash 
from sqlalchemy import exc, func 

try:
    import pandas as pd 
except ImportError:
    pd = None 

# --- CONFIGURATION ---
DATASET_FILENAME = 'leetcode_dataset - lc.csv' 
app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = 'your_super_secret_key_here' 
basedir = os.path.abspath(os.path.dirname(__file__))
# OLD LINE:
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')

# NEW LINE:
# This checks if the cloud database URL exists; if not, it falls back to SQLite (for local testing)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# --- DATABASE MODELS ---

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    level = db.Column(db.String(50), default='New')

    def __repr__(self):
        return f'<User {self.username}>'

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(500), nullable=False)
    difficulty = db.Column(db.String(50), nullable=False)
    topic = db.Column(db.String(100))
    leetcode_url = db.Column(db.String(255)) 

    def __repr__(self):
        return f'<Question {self.id} ({self.difficulty})>'

class TestResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    is_correct = db.Column(db.Boolean, default=False)
    
    user = db.relationship('User', backref=db.backref('results', lazy=True))
    question = db.relationship('Question', backref=db.backref('results_data', lazy=True))
    
    __table_args__ = (
        db.UniqueConstraint('user_id', 'question_id', name='_user_question_uc'),
    )

class Practice(db.Model): # Model to track completion status
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    is_done = db.Column(db.Boolean, default=True) 

    __table_args__ = (
        db.UniqueConstraint('user_id', 'question_id', name='_user_practice_uc_v2'),
    )

# --- CORE LOGIC FUNCTIONS ---

def simulate_grading(difficulty):
    """Simulates grading based on question difficulty."""
    if difficulty == 'Easy':
        return (random.random() < 0.9)
    elif difficulty == 'Medium':
        return (random.random() < 0.6)
    elif difficulty == 'Hard':
        return (random.random() < 0.3)
    return False


def predict_coding_level(user_id):
    """The Prediction Model: Calculates level based on aggregate test scores."""
    
    all_results = TestResult.query.filter_by(user_id=user_id).all()
    
    if not all_results:
        return 'New'

    scores = {'Easy': {'correct': 0, 'total': 0},
              'Medium': {'correct': 0, 'total': 0},
              'Hard': {'correct': 0, 'total': 0}}
              
    for result in all_results:
        if result.question: 
            difficulty = result.question.difficulty
            scores[difficulty]['total'] += 1
            if result.is_correct:
                scores[difficulty]['correct'] += 1
        
    def get_percent(d):
        return scores[d]['correct'] / scores[d]['total'] if scores[d]['total'] > 0 else 0

    easy_percent = get_percent('Easy')
    medium_percent = get_percent('Medium')
    hard_percent = get_percent('Hard')

    # Level Assignment Logic
    if hard_percent >= 0.5 and medium_percent >= 0.7:
        level = 'Advanced'
    elif medium_percent >= 0.6 and easy_percent >= 0.8:
        level = 'Intermediate'
    elif easy_percent >= 0.7:
        level = 'Beginner'
    else:
        level = 'Struggling Beginner'

    return level


def fetch_recommendations(level, num_questions=5):
    """
    Suggests practice questions based on the user's predicted level.
    It EXCLUDES questions the user has already marked as done.
    """
    
    user_id = session.get('user_id')
    # Get IDs of questions already practiced
    practiced_qids = [p.question_id for p in Practice.query.filter_by(user_id=user_id, is_done=True).all()]
    
    if level in ['Beginner', 'Struggling Beginner', 'New']:
        target_difficulties = ['Easy', 'Medium']
        order_by_difficulty = [('Medium', 3), ('Easy', 2)] 
        
    elif level == 'Intermediate':
        target_difficulties = ['Medium', 'Hard']
        order_by_difficulty = [('Hard', 3), ('Medium', 2)]
        
    elif level == 'Advanced':
        target_difficulties = ['Hard', 'Medium']
        order_by_difficulty = [('Hard', 4), ('Medium', 1)]
        
    else: 
        target_difficulties = ['Easy']
        order_by_difficulty = [('Easy', num_questions)]

    recommendations = []
    
    for difficulty, count in order_by_difficulty:
        if len(recommendations) < num_questions:
            questions_to_fetch = count if (len(recommendations) + count <= num_questions) else (num_questions - len(recommendations))
            
            # CRITICAL: Exclude already practiced questions
            available_questions = Question.query.filter(
                Question.difficulty == difficulty,
                Question.id.notin_(practiced_qids)
            ).order_by(db.func.random()).limit(questions_to_fetch).all()
            
            recommendations.extend(available_questions)

    random.shuffle(recommendations)
    return recommendations[:num_questions]


def seed_questions():
    """Reads the external CSV file and populates the database."""
    
    if pd is None:
        print("CRITICAL ERROR: Pandas library not available. Cannot seed questions from CSV file.")
        return
        
    try:
        if Question.query.count() == 0:
            
            df = pd.read_csv(DATASET_FILENAME) 
            questions = []
            
            for index, row in df.iterrows():
                difficulty = row['difficulty'].strip()
                
                topics_str = row['related_topics']
                topic = "General"
                if pd.notna(topics_str): 
                    topic = topics_str.split(',')[0].strip().replace('[', '').replace(']', '').replace("'", '')
                    if not topic: topic = "General"
                
                new_question = Question(
                    text=row['title'], 
                    difficulty=difficulty,
                    topic=topic,
                    leetcode_url=row['url'] 
                )
                questions.append(new_question)
                
            db.session.bulk_save_objects(questions)
            db.session.commit()
            print(f"--- Database seeded with {len(questions)} questions from {DATASET_FILENAME}. ---")
        else:
            print("--- Question bank already contains data. Skipping seed. ---")
            
    except FileNotFoundError:
        print(f"CRITICAL ERROR: CSV file '{DATASET_FILENAME}' not found in the root directory. Cannot seed database.")
    except exc.OperationalError as e:
        print(f"Database Error during seeding: {e}")
    except Exception as e:
        print(f"CRITICAL UNKNOWN ERROR during seeding: {e}")


# --- ROUTES (URL Handlers) ---

@app.route('/')
def index():
    return render_template('index.html', logged_in='user_id' in session)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Both username and password are required.', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose a different one.', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login'))
            
    return render_template('login.html')


@app.route('/logout')
def logout():
    """Handles user logout by clearing the session."""
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    """
    Displays user level and practice recommendations.
    Determines if the user is ready for a re-test.
    """
    if 'user_id' not in session:
        flash('Please log in to access your dashboard.', 'error')
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    current_user = User.query.get(user_id) 
    
    if current_user is None:
        session.pop('user_id', None)
        return redirect(url_for('login'))
    
    current_user.level = predict_coding_level(user_id)
    db.session.commit()
    
    # 1. Get Recommendations (Excluding practiced ones)
    recommendations = fetch_recommendations(current_user.level)
    
    # 2. Check if user is ready to re-test
    # User is ready if there are NO recommendations left at their current level
    is_ready_for_retest = len(recommendations) == 0 and current_user.level != 'New'
    
    # 3. Get practice status for rendering checkboxes
    practiced_qids = [p.question_id for p in Practice.query.filter_by(user_id=user_id, is_done=True).all()]
    
    return render_template('dashboard.html', 
                           user=current_user, 
                           recommendations=recommendations,
                           practiced_qids=practiced_qids,
                           is_ready_for_retest=is_ready_for_retest) # <-- Passing the re-test flag


@app.route('/take_test', methods=['GET', 'POST'])
def take_test():
    """Handles test display (GET) and submission/scoring (POST)."""
    if 'user_id' not in session:
        flash('Please log in to start a test.', 'error')
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    
    # --- POST HANDLING (SUBMISSION) ---
    if request.method == 'POST':
        total_correct = 0
        feedback_messages = []
        
        for key, answer in request.form.items():
            if key.startswith('answer_'):
                question_id = int(key.split('_')[1])
                question = Question.query.get(question_id)
                
                if question:
                    is_correct = simulate_grading(question.difficulty) 
                    
                    if is_correct:
                        total_correct += 1
                        feedback_messages.append(f"Q{question_id} ({question.difficulty}): Correct! ✅")
                    else:
                        feedback_messages.append(f"Q{question_id} ({question.difficulty}): Incorrect ❌. Focus on {question.topic} basics.")
                    
                    # Save the result to the TestResult table
                    new_result = TestResult(
                        user_id=user_id,
                        question_id=question_id,
                        is_correct=is_correct
                    )
                    db.session.add(new_result)
        
        db.session.commit()
        
        flash(f'Test submitted! You answered {total_correct} questions correctly.', 'success')
        for msg in feedback_messages:
            flash(msg, 'info') 
        
        return redirect(url_for('results'))

    # --- GET HANDLING (DISPLAY TEST) - Repetition Guard Logic ---
    else: 
        asked_qids = [r.question_id for r in TestResult.query.filter_by(user_id=user_id).all()]
        
        test_q_easy = 1
        test_q_medium = 1
        test_q_hard = 1
        test_questions = []

        available_easy = Question.query.filter(Question.difficulty == 'Easy', Question.id.notin_(asked_qids)).order_by(db.func.random()).limit(test_q_easy).all()
        test_questions.extend(available_easy)

        available_medium = Question.query.filter(Question.difficulty == 'Medium', Question.id.notin_(asked_qids)).order_by(db.func.random()).limit(test_q_medium).all()
        test_questions.extend(available_medium)
        
        available_hard = Question.query.filter(Question.difficulty == 'Hard', Question.id.notin_(asked_qids)).order_by(db.func.random()).limit(test_q_hard).all()
        test_questions.extend(available_hard)
        
        if len(test_questions) == 0:
            flash('Error: You have completed all unique questions in the bank!', 'error')
        elif len(test_questions) < (test_q_easy + test_q_medium + test_q_hard):
            flash('Warning: Not enough unique questions available for a full test. Practice more!', 'warning')

        random.shuffle(test_questions)
        
        return render_template('test_page.html', questions=test_questions)


@app.route('/results')
def results():
    """Displays user's predicted level and detailed performance."""
    if 'user_id' not in session:
        flash('Please log in to view results.', 'error')
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    current_user = User.query.get(user_id)
    
    level = current_user.level
    
    # Fetch all test results associated with the current user for display
    all_test_results = TestResult.query.filter_by(user_id=user_id).all()
    
    return render_template('results.html', 
                           level=level, 
                           latest_results=all_test_results)


@app.route('/mark_practice_done', methods=['POST'])
def mark_practice_done():
    """Handles the form submission from the dashboard to mark questions as practiced."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session.get('user_id')
    practiced_qids = request.form.getlist('practiced_q_id')
    
    count_marked = 0
    
    for qid_str in practiced_qids:
        qid = int(qid_str)
        practice_record = Practice.query.filter_by(user_id=user_id, question_id=qid).first()
        
        if not practice_record:
            # Create a new record if it doesn't exist
            new_record = Practice(user_id=user_id, question_id=qid, is_done=True)
            db.session.add(new_record)
            count_marked += 1
        elif not practice_record.is_done:
            # Update the status if it exists but wasn't marked done
            practice_record.is_done = True
            count_marked += 1
            
    db.session.commit()

    flash(f"Successfully marked {count_marked} questions as practiced! Check dashboard for re-test options.", 'success')
    return redirect(url_for('dashboard'))


# --- RUN THE APPLICATION ---

# --- RUN THE APPLICATION ---

# This function runs once when the app starts (works for both Gunicorn and local)
def initialize_database():
    with app.app_context():
        try:
            db.create_all()
            print("Database tables created successfully.")
            seed_questions()
            print("Database seeded successfully.")
        except Exception as e:
            print(f"Error initializing database: {e}")

# Run initialization immediately
initialize_database()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')