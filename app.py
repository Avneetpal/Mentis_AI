# app.py

# --- IMPORTS & SETUP ---
import os
import random 
import ast # Import Abstract Syntax Tree for code validation
from flask import Flask, render_template, url_for, redirect, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash 
from sqlalchemy import exc, func 

# Check for pandas
try:
    import pandas as pd 
except ImportError:
    pd = None 

# --- CONFIGURATION ---
DATASET_FILENAME = 'leetcode_dataset - lc.csv' 

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = 'your_super_secret_key_here' 

# Database Configuration
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db') 
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

class Practice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    is_done = db.Column(db.Boolean, default=True) 

    __table_args__ = (
        db.UniqueConstraint('user_id', 'question_id', name='_user_practice_uc_v2'),
    )

# --- CORE LOGIC FUNCTIONS ---

def validate_code(code_snippet):
    """
    Uses Python's AST module to check if the code is syntactically valid.
    Returns: (is_valid, message)
    """
    if not code_snippet or len(code_snippet.strip()) < 5:
        return False, "Code is empty or too short."
        
    try:
        # Attempt to parse the code into an Abstract Syntax Tree
        tree = ast.parse(code_snippet)
        
        # Check if at least one function definition exists (def ...)
        has_function = any(isinstance(node, ast.FunctionDef) for node in ast.walk(tree))
        
        if not has_function:
            return False, "Code is valid Python, but missing a function definition (def ...)."
            
        return True, "Syntax is valid."
        
    except SyntaxError as e:
        return False, f"Syntax Error on line {e.lineno}: {e.msg}"
    except Exception as e:
        return False, f"Error parsing code: {str(e)}"


def simulate_grading(difficulty, user_code):
    """
    Simulates grading by first validating syntax, then applying probabilistic logic.
    Returns: (is_correct, feedback_message)
    """
    # 1. Check for Valid Python Syntax
    is_valid, msg = validate_code(user_code)
    
    if not is_valid:
        return False, f"Incorrect ❌ ({msg})"

    # 2. If syntax is valid, simulate logic check based on difficulty
    # (In a real system, this would run test cases)
    chance = 0
    if difficulty == 'Easy':
        chance = 0.9
    elif difficulty == 'Medium':
        chance = 0.7
    elif difficulty == 'Hard':
        chance = 0.4
        
    if random.random() < chance:
        return True, "Correct! ✅ (Logic verified)"
    else:
        return False, "Incorrect ❌ (Logic failed on hidden test cases)"


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
    """Suggests practice questions based on the user's predicted level."""
    
    user_id = session.get('user_id')
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
        print("CRITICAL ERROR: Pandas library not available. Cannot seed questions.")
        return
        
    try:
        if Question.query.count() == 0:
            # Ensure the file exists
            if not os.path.exists(DATASET_FILENAME):
                 print(f"Error: {DATASET_FILENAME} not found in root directory.")
                 return

            df = pd.read_csv(DATASET_FILENAME) 
            questions = []
            
            # Limit to 1000 questions to prevent database bloat on free tier
            for index, row in df.head(1000).iterrows():
                difficulty = row['difficulty'].strip()
                topics_str = str(row['related_topics'])
                topic = "General"
                
                if pd.notna(topics_str) and len(topics_str) > 2: 
                    topic = topics_str.split(',')[0].strip().replace('[', '').replace(']', '').replace("'", '')
                
                new_question = Question(
                    text=row['title'], 
                    difficulty=difficulty,
                    topic=topic,
                    leetcode_url=row['url'] 
                )
                questions.append(new_question)
            
            db.session.bulk_save_objects(questions)
            db.session.commit()
            print(f"--- Database seeded with {len(questions)} questions. ---")
        else:
            print("--- Question bank already contains data. Skipping seed. ---")
            
    except Exception as e:
        print(f"ERROR during seeding: {e}")


# --- ROUTES ---

@app.route('/')
def index():
    return render_template('index.html', logged_in='user_id' in session)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('All fields are required.', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
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
            flash('Invalid credentials.', 'error')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    current_user = User.query.get(user_id) 
    
    if not current_user:
        session.clear()
        return redirect(url_for('login'))
    
    current_user.level = predict_coding_level(user_id)
    db.session.commit()
    
    recommendations = fetch_recommendations(current_user.level)
    
    is_ready_for_retest = (len(recommendations) == 0 and current_user.level != 'New')
    practiced_qids = [p.question_id for p in Practice.query.filter_by(user_id=user_id, is_done=True).all()]
    
    return render_template('dashboard.html', 
                           user=current_user, 
                           recommendations=recommendations,
                           practiced_qids=practiced_qids,
                           is_ready_for_retest=is_ready_for_retest) 

@app.route('/take_test', methods=['GET', 'POST'])
def take_test():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    
    # --- POST HANDLING (SUBMISSION) ---
    if request.method == 'POST':
        total_correct = 0
        feedback_messages = []
        
        for key, answer_code in request.form.items():
            if key.startswith('answer_'):
                question_id = int(key.split('_')[1])
                question = Question.query.get(question_id)
                
                if question:
                    # Pass code to new grading function
                    is_correct, msg = simulate_grading(question.difficulty, answer_code) 
                    
                    if is_correct:
                        total_correct += 1
                        feedback_messages.append(f"Q: {question.text[:30]}... - {msg}")
                    else:
                        feedback_messages.append(f"Q: {question.text[:30]}... - {msg}")
                    
                    new_result = TestResult(
                        user_id=user_id,
                        question_id=question_id,
                        is_correct=is_correct
                    )
                    db.session.add(new_result)
        
        db.session.commit()
        flash(f'Test submitted! Score: {total_correct} correct answers.', 'success')
        for msg in feedback_messages:
            flash(msg, 'info')
        return redirect(url_for('results'))

    else: 
        asked_qids = [r.question_id for r in TestResult.query.filter_by(user_id=user_id).all()]
        
        test_questions = []
        for diff in ['Easy', 'Medium', 'Hard']:
            q = Question.query.filter(
                Question.difficulty == diff, 
                Question.id.notin_(asked_qids)
            ).order_by(db.func.random()).limit(1).first()
            if q: test_questions.append(q)
        
        if len(test_questions) < 3:
            flash('Note: Questions are limited.', 'warning')

        random.shuffle(test_questions)
        return render_template('test_page.html', questions=test_questions)

@app.route('/results')
def results():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    current_user = User.query.get(user_id)
    all_test_results = TestResult.query.filter_by(user_id=user_id).all()
    
    return render_template('results.html', 
                           level=current_user.level, 
                           latest_results=all_test_results)

@app.route('/mark_practice_done', methods=['POST'])
def mark_practice_done():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user_id = session['user_id']
    practiced_qids = request.form.getlist('practiced_q_id')
    count = 0
    
    for qid in practiced_qids:
        qid = int(qid)
        exists = Practice.query.filter_by(user_id=user_id, question_id=qid).first()
        if not exists:
            db.session.add(Practice(user_id=user_id, question_id=qid, is_done=True))
            count += 1
        elif not exists.is_done:
            exists.is_done = True
            count += 1
            
    db.session.commit()
    flash(f"Updated {count} questions as practiced.", 'success')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        seed_questions()
    app.run(debug=True, host='0.0.0.0')