from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cloudsprint_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cloudsprint.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'), nullable=True)
    
    # Relationships
    assignments = db.relationship('Assignment', backref='assigned_user', lazy=True)
    timelogs = db.relationship('Timelog', backref='user', lazy=True)
    reviews_received = db.relationship('PerformanceReview', 
                                      foreign_keys='PerformanceReview.user_id',
                                      backref='reviewed_user', lazy=True)
    reviews_given = db.relationship('PerformanceReview', 
                                   foreign_keys='PerformanceReview.reviewer_id',
                                   backref='reviewer', lazy=True)
    chats = db.relationship('Teamchat', backref='sender', lazy=True)
    notifications = db.relationship('Notification', backref='user', lazy=True)
    feedback = db.relationship('Feedback', backref='user', lazy=True)
    files = db.relationship('File', backref='uploader', lazy=True)
    comments = db.relationship('Comment', backref='user', lazy=True)
    progress_reports = db.relationship('ProgressReport', backref='submitter', lazy=True)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    
    # Relationships
    users = db.relationship('User', backref='team', lazy=True)
    chats = db.relationship('Teamchat', backref='team', lazy=True)
    
    def __repr__(self):
        return f'<Team {self.name}>'

class Client(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    company = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    
    # Relationships
    projects = db.relationship('Project', backref='client', lazy=True)
    
    def __repr__(self):
        return f'<Client {self.name} - {self.company}>'

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='Initiated')  # Initiated, In Progress, On Hold, Execution Completed
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    
    # Relationships
    tasks = db.relationship('Task', backref='project', lazy=True)
    assignments = db.relationship('Assignment', backref='project', lazy=True)
    timelogs = db.relationship('Timelog', backref='project', lazy=True)
    feedback = db.relationship('Feedback', backref='project', lazy=True)
    budgets = db.relationship('Budget', backref='project', lazy=True)
    schedules = db.relationship('Schedule', backref='project', lazy=True)
    meetings = db.relationship('Meeting', backref='project', lazy=True)
    milestones = db.relationship('Milestone', backref='project', lazy=True)
    risk_assessments = db.relationship('RiskAssessment', backref='project', lazy=True)
    status_updates = db.relationship('ProjectStatus', backref='project', lazy=True)
    resources = db.relationship('Resource', backref='project', lazy=True)
    progress_reports = db.relationship('ProgressReport', backref='project', lazy=True)
    files = db.relationship('File', backref='project', lazy=True)
    
    def __repr__(self):
        return f'<Project {self.name}>'

class TaskCategory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=True)
    
    # Relationships
    tasks = db.relationship('Task', backref='category', lazy=True)
    
    def __repr__(self):
        return f'<TaskCategory {self.name}>'

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), nullable=False, default='Not Started')  # Not Started, In Progress, On Hold, Completed
    deadline = db.Column(db.DateTime, nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('task_category.id'), nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    # Relationships
    timelogs = db.relationship('Timelog', backref='task', lazy=True)
    comments = db.relationship('Comment', backref='task', lazy=True)
    
    def __repr__(self):
        return f'<Task {self.title}>'

class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    assigned_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Assignment {self.role}>'

class Timelog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    hours = db.Column(db.Float, nullable=False)
    date = db.Column(db.Date, nullable=False)
    description = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f'<Timelog {self.user_id} - {self.hours} hours>'

class PerformanceReview(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reviewer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    review_date = db.Column(db.DateTime, default=datetime.utcnow)
    rating = db.Column(db.Integer, nullable=False)  # 1-5 scale
    comments = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f'<PerformanceReview for User {self.user_id}>'

class Teamchat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Teamchat {self.id}>'

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    notification_type = db.Column(db.String(50), nullable=False)  # task, meeting, update
    
    def __repr__(self):
        return f'<Notification {self.id}>'

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 1-5 scale
    submission_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Feedback {self.id}>'

class Budget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    total_budget = db.Column(db.Float, nullable=False)
    used_amount = db.Column(db.Float, default=0)
    remaining_amount = db.Column(db.Float, nullable=False)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Budget {self.id} - ${self.total_budget}>'

class Schedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    
    def __repr__(self):
        return f'<Schedule {self.title}>'

class Meeting(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    agenda = db.Column(db.Text, nullable=False)
    date_time = db.Column(db.DateTime, nullable=False)
    duration = db.Column(db.Integer, nullable=False)  # In minutes
    participants = db.Column(db.Text, nullable=False)  # Comma separated user_ids
    reminder = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<Meeting {self.title}>'

class Milestone(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    deadline = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='Not Started')  # Not Started, In Progress, Completed
    
    def __repr__(self):
        return f'<Milestone {self.title}>'

class RiskAssessment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    risk_title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # Low, Medium, Very High
    mitigation_plan = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Active')  # Active, Mitigated, Closed
    
    def __repr__(self):
        return f'<RiskAssessment {self.risk_title}>'

class ProjectStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    update_date = db.Column(db.DateTime, default=datetime.utcnow)
    comments = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f'<ProjectStatus {self.status}>'

class Resource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    resource_type = db.Column(db.String(20), nullable=False)  # Material, Equipment
    quantity = db.Column(db.Integer, nullable=False)
    availability = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<Resource {self.name}>'

class ProgressReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    report_date = db.Column(db.DateTime, default=datetime.utcnow)
    progress_rate = db.Column(db.Float, nullable=False)  # Percentage
    details = db.Column(db.Text, nullable=False)
    submitted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def __repr__(self):
        return f'<ProgressReport {self.id}>'

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    file_path = db.Column(db.String(200), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationships
    fileshares = db.relationship('Fileshare', backref='file', lazy=True)
    
    def __repr__(self):
        return f'<File {self.filename}>'

class Fileshare(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)
    shared_with = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    share_date = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Fileshare {self.id}>'

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Comment {self.id}>'

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('register'))
        
        # Create new user
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        
        # Make the first registered user an admin
        if User.query.count() == 0:
            new_user.is_admin = True
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('is_admin', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    # Get assigned tasks for the user
    tasks = Task.query.filter_by(assigned_to=user.id).all()
    
    # Get projects the user is assigned to
    assignments = Assignment.query.filter_by(user_id=user.id).all()
    project_ids = [a.project_id for a in assignments]
    projects = Project.query.filter(Project.id.in_(project_ids)).all()
    
    # Get notifications
    notifications = Notification.query.filter_by(user_id=user.id, is_read=False).order_by(Notification.timestamp.desc()).limit(5).all()
    
    return render_template('dashboard.html', user=user, tasks=tasks, projects=projects, notifications=notifications)

# Admin Routes
@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session or not session['is_admin']:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()
    clients = Client.query.all()
    projects = Project.query.all()
    
    return render_template('admin/dashboard.html', users=users, clients=clients, projects=projects)

@app.route('/admin/clients', methods=['GET', 'POST'])
def admin_clients():
    if 'user_id' not in session or not session['is_admin']:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        name = request.form['name']
        company = request.form['company']
        email = request.form['email']
        phone = request.form['phone']
        
        new_client = Client(name=name, company=company, email=email, phone=phone)
        db.session.add(new_client)
        db.session.commit()
        
        flash('Client added successfully', 'success')
        return redirect(url_for('admin_clients'))
    
    clients = Client.query.all()
    return render_template('admin/clients.html', clients=clients)

@app.route('/admin/clients/edit/<int:client_id>', methods=['GET', 'POST'])
def edit_client(client_id):
    if 'user_id' not in session or not session['is_admin']:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    client = Client.query.get_or_404(client_id)
    
    if request.method == 'POST':
        client.name = request.form['name']
        client.company = request.form['company']
        client.email = request.form['email']
        client.phone = request.form['phone']
        
        db.session.commit()
        flash('Client updated successfully', 'success')
        return redirect(url_for('admin_clients'))
    
    return render_template('admin/edit_client.html', client=client)

@app.route('/admin/clients/delete/<int:client_id>')
def delete_client(client_id):
    if 'user_id' not in session or not session['is_admin']:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    client = Client.query.get_or_404(client_id)
    
    # Check if client has associated projects
    if client.projects:
        flash('Cannot delete client with associated projects', 'danger')
        return redirect(url_for('admin_clients'))
    
    db.session.delete(client)
    db.session.commit()
    flash('Client deleted successfully', 'success')
    return redirect(url_for('admin_clients'))

@app.route('/admin/teams', methods=['GET', 'POST'])
def admin_teams():
    if 'user_id' not in session or not session['is_admin']:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        
        new_team = Team(name=name, description=description)
        db.session.add(new_team)
        db.session.commit()
        
        flash('Team created successfully', 'success')
        return redirect(url_for('admin_teams'))
    
    teams = Team.query.all()
    return render_template('admin/teams.html', teams=teams)

@app.route('/admin/teams/edit/<int:team_id>', methods=['GET', 'POST'])
def edit_team(team_id):
    if 'user_id' not in session or not session['is_admin']:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    team = Team.query.get_or_404(team_id)
    users = User.query.all()
    
    if request.method == 'POST':
        team.name = request.form['name']
        team.description = request.form['description']
        
        # Handle team members
        selected_users = request.form.getlist('team_members')
        
        # Remove all users from team first
        for user in User.query.filter_by(team_id=team.id).all():
            user.team_id = None
        
        # Add selected users to team
        for user_id in selected_users:
            user = User.query.get(user_id)
            if user:
                user.team_id = team.id
        
        db.session.commit()
        flash('Team updated successfully', 'success')
        return redirect(url_for('admin_teams'))
    
    team_members = User.query.filter_by(team_id=team.id).all()
    return render_template('admin/edit_team.html', team=team, users=users, team_members=team_members)

@app.route('/admin/teams/delete/<int:team_id>')
def delete_team(team_id):
    if 'user_id' not in session or not session['is_admin']:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    team = Team.query.get_or_404(team_id)
    
    # Remove team association from users
    for user in User.query.filter_by(team_id=team.id).all():
        user.team_id = None
    
    db.session.delete(team)
    db.session.commit()
    flash('Team deleted successfully', 'success')
    return redirect(url_for('admin_teams'))

@app.route('/admin/projects', methods=['GET', 'POST'])
def admin_projects():
    if 'user_id' not in session or not session['is_admin']:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%d')
        end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%d')
        status = request.form['status']
        client_id = request.form['client_id']
        
        new_project = Project(
            name=name,
            description=description,
            start_date=start_date,
            end_date=end_date,
            status=status,
            client_id=client_id
        )
        db.session.add(new_project)
        db.session.commit()
        
        # Create a project status entry
        project_status = ProjectStatus(
            project_id=new_project.id,
            status=status,
            comments="Initial project status"
        )
        db.session.add(project_status)
        db.session.commit()
        
        flash('Project created successfully', 'success')
        return redirect(url_for('admin_projects'))
    
    projects = Project.query.all()
    clients = Client.query.all()
    return render_template('admin/projects.html', projects=projects, clients=clients)

@app.route('/admin/projects/edit/<int:project_id>', methods=['GET', 'POST'])
def edit_project(project_id):
    if 'user_id' not in session or not session['is_admin']:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    project = Project.query.get_or_404(project_id)
    clients = Client.query.all()
    
    if request.method == 'POST':
        project.name = request.form['name']
        project.description = request.form['description']
        project.start_date = datetime.strptime(request.form['start_date'], '%Y-%m-%d')
        project.end_date = datetime.strptime(request.form['end_date'], '%Y-%m-%d')
        new_status = request.form['status']
        project.status = new_status
        project.client_id = request.form['client_id']
        
        # Update project status
        project_status = ProjectStatus(
            project_id=project.id,
            status=new_status,
            comments="Status updated by admin"
        )
        db.session.add(project_status)
        
        db.session.commit()
        flash('Project updated successfully', 'success')
        return redirect(url_for('admin_projects'))
    
    return render_template('admin/edit_project.html', project=project, clients=clients)

@app.route('/admin/projects/delete/<int:project_id>')
def delete_project(project_id):
    if 'user_id' not in session or not session['is_admin']:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    project = Project.query.get_or_404(project_id)
    
    # Delete all associated records (cascade delete not implemented in SQLAlchemy by default)
    Task.query.filter_by(project_id=project.id).delete()
    Assignment.query.filter_by(project_id=project.id).delete()
    Timelog.query.filter_by(project_id=project.id).delete()
    Feedback.query.filter_by(project_id=project.id).delete()
    Budget.query.filter_by(project_id=project.id).delete()
    Schedule.query.filter_by(project_id=project.id).delete()
    Meeting.query.filter_by(project_id=project.id).delete()
    Milestone.query.filter_by(project_id=project.id).delete()
    RiskAssessment.query.filter_by(project_id=project.id).delete()
    ProjectStatus.query.filter_by(project_id=project.id).delete()
    Resource.query.filter_by(project_id=project.id).delete()
    ProgressReport.query.filter_by(project_id=project.id).delete()
    
    # Delete files and fileshares
    files = File.query.filter_by(project_id=project.id).all()
    for file in files:
        Fileshare.query.filter_by(file_id=file.id).delete()
        # Delete actual file from filesystem
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file.file_path))
        except:
            pass
    File.query.filter_by(project_id=project.id).delete()
    
    db.session.delete(project)
    db.session.commit()
    flash('Project deleted successfully', 'success')
    return redirect(url_for('admin_projects'))

@app.route('/admin/users', methods=['GET', 'POST'])
def admin_users():
    if 'user_id' not in session or not session['is_admin']:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        is_admin = 'is_admin' in request.form
        team_id = request.form['team_id'] if request.form['team_id'] else None
        
        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('admin_users'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return redirect(url_for('admin_users'))
        
        # Create new user
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password, is_admin=is_admin, team_id=team_id)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('User created successfully', 'success')
        return redirect(url_for('admin_users'))
    
    users = User.query.all()
    teams = Team.query.all()
    return render_template('admin/users.html', users=users, teams=teams)

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'user_id' not in session or not session['is_admin']:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    teams = Team.query.all()
    
    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        
        if request.form['password']:
            user.password = generate_password_hash(request.form['password'])
            
        user.is_admin = 'is_admin' in request.form
        user.team_id = request.form['team_id'] if request.form['team_id'] else None
        
        db.session.commit()
        flash('User updated successfully', 'success')
        return redirect(url_for('admin_users'))
    
    return render_template('admin/edit_user.html', user=user, teams=teams)

@app.route('/admin/users/delete/<int:user_id>')
def delete_user(user_id):
    if 'user_id' not in session or not session['is_admin']:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    # Prevent self-deletion
    if user_id == session['user_id']:
        flash('Cannot delete your own account', 'danger')
        return redirect(url_for('admin_users'))
    
    user = User.query.get_or_404(user_id)
    
    # Delete all related data
    Assignment.query.filter_by(user_id=user_id).delete()
    Timelog.query.filter_by(user_id=user_id).delete()
    PerformanceReview.query.filter(
        (PerformanceReview.user_id == user_id) | (PerformanceReview.reviewer_id == user_id)
    ).delete()
    Teamchat.query.filter_by(sender_id=user_id).delete()
    Notification.query.filter_by(user_id=user_id).delete()
    Feedback.query.filter_by(user_id=user_id).delete()
    ProgressReport.query.filter_by(submitted_by=user_id).delete()
    Fileshare.query.filter_by(shared_with=user_id).delete()
    Comment.query.filter_by(user_id=user_id).delete()
    
    # Reassign tasks
    for task in Task.query.filter_by(assigned_to=user_id).all():
        task.assigned_to = None
    
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/performance_reviews', methods=['GET', 'POST'])
def admin_performance_reviews():
    if 'user_id' not in session or not session['is_admin']:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        user_id = request.form['user_id']
        reviewer_id = session['user_id']
        rating = int(request.form['rating'])
        comments = request.form['comments']
        
        new_review = PerformanceReview(
            user_id=user_id,
            reviewer_id=reviewer_id,
            rating=rating,
            comments=comments
        )
        
        db.session.add(new_review)
        db.session.commit()
        
        # Notify user of new performance review
        notification = Notification(
            user_id=user_id,
            message="You have received a new performance review",
            notification_type="update"
        )
        db.session.add(notification)
        db.session.commit()
        
        flash('Performance review submitted successfully', 'success')
        return redirect(url_for('admin_performance_reviews'))
    
    users = User.query.all()
    reviews = PerformanceReview.query.order_by(PerformanceReview.review_date.desc()).all()
    return render_template('admin/performance_reviews.html', users=users, reviews=reviews)

# Project Routes
@app.route('/projects')
def projects():
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    if session.get('is_admin'):
        # Admins can see all projects
        projects = Project.query.all()
    else:
        # Regular users can see projects they're assigned to
        assignments = Assignment.query.filter_by(user_id=user_id).all()
        project_ids = [a.project_id for a in assignments]
        projects = Project.query.filter(Project.id.in_(project_ids)).all()
    
    return render_template('projects/index.html', projects=projects)

@app.route('/projects/<int:project_id>')
def project_details(project_id):
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    project = Project.query.get_or_404(project_id)
    
    # Check access permission
    if not session.get('is_admin'):
        assignments = Assignment.query.filter_by(user_id=session['user_id'], project_id=project_id).first()
        if not assignments:
            flash('You do not have access to this project', 'danger')
            return redirect(url_for('projects'))
    
    tasks = Task.query.filter_by(project_id=project_id).all()
    budget = Budget.query.filter_by(project_id=project_id).first()
    milestones = Milestone.query.filter_by(project_id=project_id).order_by(Milestone.deadline).all()
    risk_assessments = RiskAssessment.query.filter_by(project_id=project_id).all()
    team_members = User.query.join(Assignment).filter(Assignment.project_id == project_id).all()
    progress_reports = ProgressReport.query.filter_by(project_id=project_id).order_by(ProgressReport.report_date.desc()).all()
    files = File.query.filter_by(project_id=project_id).all()
    status_updates = ProjectStatus.query.filter_by(project_id=project_id).order_by(ProjectStatus.update_date.desc()).all()
    
    return render_template('projects/details.html', 
                          project=project, 
                          tasks=tasks, 
                          budget=budget, 
                          milestones=milestones, 
                          risk_assessments=risk_assessments,
                          team_members=team_members,
                          progress_reports=progress_reports,
                          files=files,
                          status_updates=status_updates)

@app.route('/projects/<int:project_id>/tasks', methods=['GET', 'POST'])
def project_tasks(project_id):
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    project = Project.query.get_or_404(project_id)
    
    # Check access permission
    if not session.get('is_admin'):
        assignments = Assignment.query.filter_by(user_id=session['user_id'], project_id=project_id).first()
        if not assignments:
            flash('You do not have access to this project', 'danger')
            return redirect(url_for('projects'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        status = request.form['status']
        deadline = datetime.strptime(request.form['deadline'], '%Y-%m-%d')
        category_id = request.form['category_id']
        assigned_to = request.form['assigned_to'] if request.form['assigned_to'] else None
        
        new_task = Task(
            title=title,
            description=description,
            status=status,
            deadline=deadline,
            project_id=project_id,
            category_id=category_id,
            assigned_to=assigned_to
        )
        
        db.session.add(new_task)
        db.session.commit()
        
        # Create notification for assigned user
        if assigned_to:
            notification = Notification(
                user_id=assigned_to,
                message=f"You have been assigned a new task: {title}",
                notification_type="task"
            )
            db.session.add(notification)
            db.session.commit()
        
        flash('Task created successfully', 'success')
        return redirect(url_for('project_tasks', project_id=project_id))
    
    tasks = Task.query.filter_by(project_id=project_id).all()
    categories = TaskCategory.query.all()
    
    # Get all team members assigned to this project
    team_members = User.query.join(Assignment).filter(Assignment.project_id == project_id).all()
    
    return render_template('projects/tasks.html', 
                          project=project, 
                          tasks=tasks, 
                          categories=categories,
                          team_members=team_members)

@app.route('/tasks/<int:task_id>', methods=['GET', 'POST'])
def task_details(task_id):
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    task = Task.query.get_or_404(task_id)
    project = Project.query.get(task.project_id)
    
    # Check access permission
    if not session.get('is_admin'):
        assignments = Assignment.query.filter_by(user_id=session['user_id'], project_id=task.project_id).first()
        if not assignments and task.assigned_to != session['user_id']:
            flash('You do not have access to this task', 'danger')
            return redirect(url_for('projects'))
    
    # Handle comment submission
    if request.method == 'POST' and 'comment' in request.form:
        comment_text = request.form['comment']
        
        new_comment = Comment(
            task_id=task_id,
            user_id=session['user_id'],
            content=comment_text
        )
        
        db.session.add(new_comment)
        db.session.commit()
        
        # Notify other team members who commented on this task
        for comment in Comment.query.filter_by(task_id=task_id).all():
            if comment.user_id != session['user_id']:
                notification = Notification(
                    user_id=comment.user_id,
                    message=f"New comment on task '{task.title}' by {session['username']}",
                    notification_type="task"
                )
                db.session.add(notification)
        
        db.session.commit()
        flash('Comment added successfully', 'success')
        return redirect(url_for('task_details', task_id=task_id))
    
    # Handle task status update
    if request.method == 'POST' and 'status' in request.form:
        task.status = request.form['status']
        db.session.commit()
        
        # Notify team members if task is completed
        if task.status == 'Completed':
            for assignment in Assignment.query.filter_by(project_id=task.project_id).all():
                if assignment.user_id != session['user_id']:
                    notification = Notification(
                        user_id=assignment.user_id,
                        message=f"Task '{task.title}' has been completed by {session['username']}",
                        notification_type="task"
                    )
                    db.session.add(notification)
            db.session.commit()
        
        flash('Task status updated successfully', 'success')
        return redirect(url_for('task_details', task_id=task_id))
    
    comments = Comment.query.filter_by(task_id=task_id).order_by(Comment.timestamp.desc()).all()
    timelogs = Timelog.query.filter_by(task_id=task_id).order_by(Timelog.date.desc()).all()
    
    return render_template('tasks/details.html', 
                          task=task, 
                          project=project, 
                          comments=comments,
                          timelogs=timelogs)

@app.route('/tasks/<int:task_id>/edit', methods=['GET', 'POST'])
def edit_task(task_id):
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    task = Task.query.get_or_404(task_id)
    project = Project.query.get(task.project_id)
    
    # Check access permission
    if not session.get('is_admin'):
        assignments = Assignment.query.filter_by(user_id=session['user_id'], project_id=task.project_id).first()
        if not assignments and task.assigned_to != session['user_id']:
            flash('You do not have access to this task', 'danger')
            return redirect(url_for('projects'))
    
    if request.method == 'POST':
        task.title = request.form['title']
        task.description = request.form['description']
        task.status = request.form['status']
        task.deadline = datetime.strptime(request.form['deadline'], '%Y-%m-%d')
        task.category_id = request.form['category_id']
        
        # If assigned_to has changed, create notification
        old_assigned_to = task.assigned_to
        new_assigned_to = request.form['assigned_to'] if request.form['assigned_to'] else None
        
        if new_assigned_to and str(old_assigned_to) != str(new_assigned_to):
            notification = Notification(
                user_id=new_assigned_to,
                message=f"You have been assigned a task: {task.title}",
                notification_type="task"
            )
            db.session.add(notification)
        
        task.assigned_to = new_assigned_to
        
        db.session.commit()
        flash('Task updated successfully', 'success')
        return redirect(url_for('task_details', task_id=task_id))
    
    categories = TaskCategory.query.all()
    team_members = User.query.join(Assignment).filter(Assignment.project_id == task.project_id).all()
    
    return render_template('tasks/edit.html', 
                          task=task, 
                          project=project, 
                          categories=categories,
                          team_members=team_members)

@app.route('/tasks/<int:task_id>/timelog', methods=['GET', 'POST'])
def task_timelog(task_id):
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    task = Task.query.get_or_404(task_id)
    
    if request.method == 'POST':
        hours = float(request.form['hours'])
        date = datetime.strptime(request.form['date'], '%Y-%m-%d')
        description = request.form['description']
        
        new_timelog = Timelog(
            user_id=session['user_id'],
            project_id=task.project_id,
            task_id=task_id,
            hours=hours,
            date=date,
            description=description
        )
        
        db.session.add(new_timelog)
        db.session.commit()
        flash('Time logged successfully', 'success')
        return redirect(url_for('task_details', task_id=task_id))
    
    timelogs = Timelog.query.filter_by(task_id=task_id, user_id=session['user_id']).order_by(Timelog.date.desc()).all()
    return render_template('tasks/timelog.html', task=task, timelogs=timelogs)

@app.route('/timesheet')
def timesheet():
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    timelogs = Timelog.query.filter_by(user_id=user.id).order_by(Timelog.date.desc()).all()
    
    return render_template('timesheet.html', user=user, timelogs=timelogs)

@app.route('/projects/<int:project_id>/milestones', methods=['GET', 'POST'])
def project_milestones(project_id):
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    project = Project.query.get_or_404(project_id)
    
    # Check access permission
    if not session.get('is_admin'):
        assignments = Assignment.query.filter_by(user_id=session['user_id'], project_id=project_id).first()
        if not assignments:
            flash('You do not have access to this project', 'danger')
            return redirect(url_for('projects'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        deadline = datetime.strptime(request.form['deadline'], '%Y-%m-%d')
        status = request.form['status']
        
        new_milestone = Milestone(
            project_id=project_id,
            title=title,
            description=description,
            deadline=deadline,
            status=status
        )
        
        db.session.add(new_milestone)
        db.session.commit()
        
        # Notify team members of new milestone
        for assignment in Assignment.query.filter_by(project_id=project_id).all():
            notification = Notification(
                user_id=assignment.user_id,
                message=f"New milestone '{title}' added to project '{project.name}'",
                notification_type="update"
            )
            db.session.add(notification)
        
        db.session.commit()
        flash('Milestone created successfully', 'success')
        return redirect(url_for('project_milestones', project_id=project_id))
    
    milestones = Milestone.query.filter_by(project_id=project_id).order_by(Milestone.deadline).all()
    return render_template('projects/milestones.html', project=project, milestones=milestones)

@app.route('/projects/<int:project_id>/milestones/<int:milestone_id>/edit', methods=['GET', 'POST'])
def edit_milestone(project_id, milestone_id):
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    milestone = Milestone.query.get_or_404(milestone_id)
    project = Project.query.get_or_404(project_id)
    
    # Check access permission
    if not session.get('is_admin'):
        assignments = Assignment.query.filter_by(user_id=session['user_id'], project_id=project_id).first()
        if not assignments:
            flash('You do not have access to this project', 'danger')
            return redirect(url_for('projects'))
    
    if request.method == 'POST':
        milestone.title = request.form['title']
        milestone.description = request.form['description']
        milestone.deadline = datetime.strptime(request.form['deadline'], '%Y-%m-%d')
        milestone.status = request.form['status']
        
        db.session.commit()
        
        # Notify team members if milestone is completed
        if milestone.status == 'Completed':
            for assignment in Assignment.query.filter_by(project_id=project_id).all():
                notification = Notification(
                    user_id=assignment.user_id,
                    message=f"Milestone '{milestone.title}' in project '{project.name}' has been completed",
                    notification_type="update"
                )
                db.session.add(notification)
            db.session.commit()
        
        flash('Milestone updated successfully', 'success')
        return redirect(url_for('project_milestones', project_id=project_id))
    
    return render_template('projects/edit_milestone.html', project=project, milestone=milestone)

@app.route('/projects/<int:project_id>/risk', methods=['GET', 'POST'])
def project_risks(project_id):
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    project = Project.query.get_or_404(project_id)
    
    # Check access permission
    if not session.get('is_admin'):
        assignments = Assignment.query.filter_by(user_id=session['user_id'], project_id=project_id).first()
        if not assignments:
            flash('You do not have access to this project', 'danger')
            return redirect(url_for('projects'))
    
    if request.method == 'POST':
        risk_title = request.form['risk_title']
        description = request.form['description']
        severity = request.form['severity']
        mitigation_plan = request.form['mitigation_plan']
        status = request.form['status']
        
        new_risk = RiskAssessment(
            project_id=project_id,
            risk_title=risk_title,
            description=description,
            severity=severity,
            mitigation_plan=mitigation_plan,
            status=status
        )
        
        db.session.add(new_risk)
        db.session.commit()
        
        # Notify team members of new risk
        for assignment in Assignment.query.filter_by(project_id=project_id).all():
            notification = Notification(
                user_id=assignment.user_id,
                message=f"New risk '{risk_title}' identified in project '{project.name}'",
                notification_type="update"
            )
            db.session.add(notification)
        
        db.session.commit()
        flash('Risk assessment created successfully', 'success')
        return redirect(url_for('project_risks', project_id=project_id))
    
    risks = RiskAssessment.query.filter_by(project_id=project_id).all()
    return render_template('projects/risks.html', project=project, risks=risks)

@app.route('/projects/<int:project_id>/risk/task/<int:task_id>', methods=['GET', 'POST'])
def task_risk_assessment(project_id, task_id):
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    project = Project.query.get_or_404(project_id)
    task = Task.query.get_or_404(task_id)
    
    if not session.get('is_admin'):
        assignments = Assignment.query.filter_by(user_id=session['user_id'], project_id=project_id).first()
        if not assignments:
            flash('Unauthorized access', 'danger')
            return redirect(url_for('projects'))
    
    if request.method == 'POST':
        risk_title = f"Task {task.id} Risk: {request.form['risk_title']}"
        description = request.form['description']
        severity = request.form['severity']
        mitigation_plan = request.form['mitigation_plan']
        status = request.form['status']
        
        new_risk = RiskAssessment(
            project_id=project_id,
            risk_title=risk_title,
            description=description,
            severity=severity,
            mitigation_plan=mitigation_plan,
            status=status
        )
        
        db.session.add(new_risk)
        db.session.commit()
        
        # Notify team members
        for assignment in Assignment.query.filter_by(project_id=project_id).all():
            notification = Notification(
                user_id=assignment.user_id,
                message=f"New risk '{risk_title}' identified for task '{task.title}' in project '{project.name}'",
                notification_type="update"
            )
            db.session.add(notification)
        
        db.session.commit()
        flash('Risk assessment created successfully', 'success')
        return redirect(url_for('project_risks', project_id=project_id))
    
    risks = RiskAssessment.query.filter_by(project_id=project_id, risk_title=f"Task {task_id} Risk").all()
    return render_template('projects/task_risk.html', project=project, task=task, risks=risks)

@app.route('/projects/<int:project_id>/resources', methods=['GET', 'POST'])
def project_resources(project_id):
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    project = Project.query.get_or_404(project_id)
    
    # Check access permission
    if not session.get('is_admin'):
        assignments = Assignment.query.filter_by(user_id=session['user_id'], project_id=project_id).first()
        if not assignments:
            flash('You do not have access to this project', 'danger')
            return redirect(url_for('projects'))
    
    if request.method == 'POST':
        name = request.form['name']
        resource_type = request.form['resource_type']
        quantity = int(request.form['quantity'])
        availability = 'availability' in request.form
        
        new_resource = Resource(
            project_id=project_id,
            name=name,
            resource_type=resource_type,
            quantity=quantity,
            availability=availability
        )
        
        db.session.add(new_resource)
        db.session.commit()
        flash('Resource added successfully', 'success')
        return redirect(url_for('project_resources', project_id=project_id))
    
    resources = Resource.query.filter_by(project_id=project_id).all()
    return render_template('projects/resources.html', project=project, resources=resources)

@app.route('/projects/<int:project_id>/progress_report', methods=['GET', 'POST'])
def project_progress_report(project_id):
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    project = Project.query.get_or_404(project_id)
    
    # Check access permission
    if not session.get('is_admin'):
        assignments = Assignment.query.filter_by(user_id=session['user_id'], project_id=project_id).first()
        if not assignments:
            flash('You do not have access to this project', 'danger')
            return redirect(url_for('projects'))
    
    if request.method == 'POST':
        progress_rate = float(request.form['progress_rate'])
        details = request.form['details']
        
        new_report = ProgressReport(
            project_id=project_id,
            progress_rate=progress_rate,
            details=details,
            submitted_by=session['user_id']
        )
        
        db.session.add(new_report)
        db.session.commit()
        
        # Update project status if necessary
        if progress_rate >= 100:
            project.status = 'Execution Completed'
            status_update = ProjectStatus(
                project_id=project_id,
                status='Execution Completed',
                comments="Project marked as completed due to progress report"
            )
            db.session.add(status_update)
        
        # Notify team members
        for assignment in Assignment.query.filter_by(project_id=project_id).all():
            if assignment.user_id != session['user_id']:
                notification = Notification(
                    user_id=assignment.user_id,
                    message=f"New progress report submitted for project '{project.name}'",
                    notification_type="update"
                )
                db.session.add(notification)
        
        db.session.commit()
        flash('Progress report submitted successfully', 'success')
        return redirect(url_for('project_details', project_id=project_id))
    
    return render_template('projects/progress_report.html', project=project)

@app.route('/projects/<int:project_id>/budget', methods=['GET', 'POST'])
def project_budget(project_id):
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    project = Project.query.get_or_404(project_id)
    
    # Check access permission
    if not session.get('is_admin'):
        assignments = Assignment.query.filter_by(user_id=session['user_id'], project_id=project_id).first()
        if not assignments:
            flash('You do not have access to this project', 'danger')
            return redirect(url_for('projects'))
    
    budget = Budget.query.filter_by(project_id=project_id).first()
    
    if request.method == 'POST':
        total_budget = float(request.form['total_budget'])
        used_amount = float(request.form['used_amount'])
        remaining_amount = total_budget - used_amount
        
        if budget:
            budget.total_budget = total_budget
            budget.used_amount = used_amount
            budget.remaining_amount = remaining_amount
            budget.last_updated = datetime.utcnow()
        else:
            new_budget = Budget(
                project_id=project_id,
                total_budget=total_budget,
                used_amount=used_amount,
                remaining_amount=remaining_amount
            )
            db.session.add(new_budget)
        
        # Notify team members of budget update
        for assignment in Assignment.query.filter_by(project_id=project_id).all():
            notification = Notification(
                user_id=assignment.user_id,
                message=f"Budget updated for project '{project.name}'",
                notification_type="update"
            )
            db.session.add(notification)
        
        db.session.commit()
        flash('Budget updated successfully', 'success')
        return redirect(url_for('project_details', project_id=project_id))
    
    return render_template('projects/budget.html', project=project, budget=budget)

@app.route('/projects/<int:project_id>/files', methods=['GET', 'POST'])
def project_files(project_id):
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    project = Project.query.get_or_404(project_id)
    
    # Check access permission
    if not session.get('is_admin'):
        assignments = Assignment.query.filter_by(user_id=session['user_id'], project_id=project_id).first()
        if not assignments:
            flash('You do not have access to this project', 'danger')
            return redirect(url_for('projects'))
    
    if request.method == 'POST' and 'file' in request.files:
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        
        if file:
            # Secure the filename
            filename = secure_filename(file.filename)
            # Create a unique file path to avoid overwriting
            file_path = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], file_path))
            
            # Get file extension
            file_type = os.path.splitext(filename)[1].strip('.').lower()
            
            new_file = File(
                filename=filename,
                file_path=file_path,
                file_type=file_type,
                project_id=project_id,
                uploaded_by=session['user_id']
            )
            
            db.session.add(new_file)
            db.session.commit()
            
            # Share with selected users
            if 'share_with' in request.form:
                shared_users = request.form.getlist('share_with')
                for user_id in shared_users:
                    file_share = Fileshare(
                        file_id=new_file.id,
                        shared_with=user_id
                    )
                    db.session.add(file_share)
                    # Notify shared user
                    notification = Notification(
                        user_id=user_id,
                        message=f"A file '{filename}' has been shared with you in project '{project.name}'",
                        notification_type="update"
                    )
                    db.session.add(notification)
                
                db.session.commit()
            
            flash('File uploaded successfully', 'success')
            return redirect(url_for('project_files', project_id=project_id))
    
    files = File.query.filter_by(project_id=project_id).all()
    team_members = User.query.join(Assignment).filter(Assignment.project_id == project_id).all()
    
    # Get shared files for current user
    fileshares = Fileshare.query.filter_by(shared_with=session['user_id']).all()
    shared_file_ids = [fs.file_id for fs in fileshares]
    shared_files = File.query.filter(File.id.in_(shared_file_ids)).all()
    
    return render_template('projects/files.html', 
                          project=project, 
                          files=files, 
                          team_members=team_members,
                          shared_files=shared_files)

@app.route('/projects/<int:project_id>/files/summary', methods=['GET'])
def file_summary(project_id):
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    project = Project.query.get_or_404(project_id)
    
    if not session.get('is_admin'):
        assignments = Assignment.query.filter_by(user_id=session['user_id'], project_id=project_id).first()
        if not assignments:
            flash('Unauthorized access', 'danger')
            return redirect(url_for('projects'))
    
    files = File.query.filter_by(project_id=project_id).all()
    file_count = len(files)
    total_size = sum(os.path.getsize(os.path.join(app.config['UPLOAD_FOLDER'], f.file_path)) for f in files if os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], f.file_path)))
    
    return render_template('projects/file_summary.html', project=project, file_count=file_count, total_size=total_size)

@app.route('/download/<path:filename>')
def download_file(filename):
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    # Verify that the user has access to the file
    file = File.query.filter_by(file_path=filename).first_or_404()
    
    if not session.get('is_admin'):
        # Check if user is on the project
        assignment = Assignment.query.filter_by(user_id=session['user_id'], project_id=file.project_id).first()
        # Or if the file was shared with them
        fileshare = Fileshare.query.filter_by(file_id=file.id, shared_with=session['user_id']).first()
        
        if not assignment and not fileshare and file.uploaded_by != session['user_id']:
            flash('You do not have access to this file', 'danger')
            return redirect(url_for('dashboard'))
    
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/meetings', methods=['GET', 'POST'])
def meetings():
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    user_id = str(session['user_id'])
    
    if request.method == 'POST' and session.get('is_admin'):
        project_id = request.form['project_id']
        title = request.form['title']
        agenda = request.form['agenda']
        date_time = datetime.strptime(f"{request.form['date']} {request.form['time']}", '%Y-%m-%d %H:%M')
        duration = int(request.form['duration'])
        participants = ','.join(request.form.getlist('participants'))
        reminder = 'reminder' in request.form
        
        new_meeting = Meeting(
            project_id=project_id,
            title=title,
            agenda=agenda,
            date_time=date_time,
            duration=duration,
            participants=participants,
            reminder=reminder
        )
        
        db.session.add(new_meeting)
        db.session.commit()
        
        # Create notifications for participants
        for participant_id in request.form.getlist('participants'):
            notification = Notification(
                user_id=participant_id,
                message=f"New meeting scheduled: {title} on {date_time.strftime('%Y-%m-%d %H:%M')}",
                notification_type="meeting"
            )
            db.session.add(notification)
        
        db.session.commit()
        flash('Meeting scheduled successfully', 'success')
        return redirect(url_for('meetings'))
    
    # Get meetings where the user is a participant
    all_meetings = Meeting.query.all()
    user_meetings = []
    
    for meeting in all_meetings:
        participants = meeting.participants.split(',')
        if user_id in participants:
            user_meetings.append(meeting)
    
    # For admins creating meetings
    projects = []
    users = []
    if session.get('is_admin'):
        projects = Project.query.all()
        users = User.query.all()
    
    return render_template('meetings/index.html', 
                          meetings=user_meetings,
                          projects=projects, 
                          users=users)

@app.route('/meetings/schedule/<int:project_id>', methods=['GET', 'POST'])
def schedule_meeting(project_id):
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    project = Project.query.get_or_404(project_id)
    
    if not session.get('is_admin') and session['user_id'] not in [a.user_id for a in Assignment.query.filter_by(project_id=project_id).all()]:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('projects'))
    
    if request.method == 'POST':
        title = request.form['title']
        agenda = request.form['agenda']
        date_time = datetime.strptime(f"{request.form['date']} {request.form['time']}", '%Y-%m-%d %H:%M')
        duration = int(request.form['duration'])
        participants = ','.join(request.form.getlist('participants'))
        reminder = 'reminder' in request.form
        
        new_meeting = Meeting(
            project_id=project_id,
            title=title,
            agenda=agenda,
            date_time=date_time,
            duration=duration,
            participants=participants,
            reminder=reminder
        )
        
        db.session.add(new_meeting)
        db.session.commit()
        
        for participant_id in request.form.getlist('participants'):
            notification = Notification(
                user_id=participant_id,
                message=f"Meeting scheduled: {title} on {date_time.strftime('%Y-%m-%d %H:%M')}",
                notification_type="meeting"
            )
            db.session.add(notification)
        
        db.session.commit()
        flash('Meeting scheduled successfully', 'success')
        return redirect(url_for('meetings'))
    
    users = User.query.all()
    return render_template('meetings/schedule.html', project=project, users=users)

@app.route('/notifications')
def notifications():
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    notifications = Notification.query.filter_by(user_id=user_id).order_by(Notification.timestamp.desc()).all()
    
    return render_template('notifications.html', notifications=notifications)

@app.route('/mark_notification/<int:notification_id>')
def mark_notification(notification_id):
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    notification = Notification.query.get_or_404(notification_id)
    
    if notification.user_id != session['user_id']:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    notification.is_read = True
    db.session.commit()
    
    return redirect(url_for('notifications'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        if 'current_password' in request.form and request.form['current_password']:
            # User wants to change password
            if check_password_hash(user.password, request.form['current_password']):
                user.password = generate_password_hash(request.form['new_password'])
                flash('Password updated successfully', 'success')
            else:
                flash('Current password is incorrect', 'danger')
        
        # Update other details
        user.username = request.form['username']
        user.email = request.form['email']
        
        db.session.commit()
        flash('Profile updated successfully', 'success')
        return redirect(url_for('profile'))
    
    return render_template('profile.html', user=user)

@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    if not user.team_id:
        flash('You are not assigned to a team yet', 'warning')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        message = request.form['message']
        
        new_chat = Teamchat(
            team_id=user.team_id,
            sender_id=user.id,
            message=message
        )
        
        db.session.add(new_chat)
        db.session.commit()
        
        # Notify team members
        team_members = User.query.filter_by(team_id=user.team_id).all()
        for member in team_members:
            if member.id != user.id:
                notification = Notification(
                    user_id=member.id,
                    message=f"New message in team chat from {user.username}",
                    notification_type="update"
                )
                db.session.add(notification)
        
        db.session.commit()
        return redirect(url_for('chat'))
    
    team = Team.query.get(user.team_id)
    chats = Teamchat.query.filter_by(team_id=user.team_id).order_by(Teamchat.timestamp).all()
    
    return render_template('chat.html', team=team, chats=chats, user=user)

@app.route('/admin/projects/assign/<int:project_id>', methods=['GET', 'POST'])
def assign_project(project_id):
    if 'user_id' not in session or not session['is_admin']:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    project = Project.query.get_or_404(project_id)
    
    if request.method == 'POST':
        user_id = request.form['user_id']
        role = request.form['role']
        
        # Check if the user is already assigned to the project
        existing_assignment = Assignment.query.filter_by(user_id=user_id, project_id=project_id).first()
        if existing_assignment:
            flash('User is already assigned to this project', 'warning')
            return redirect(url_for('assign_project', project_id=project_id))
        
        # Create new assignment
        new_assignment = Assignment(
            user_id=user_id,
            project_id=project_id,
            role=role,
            assigned_date=datetime.utcnow()
        )
        
        db.session.add(new_assignment)
        db.session.commit()
        
        # Notify the assigned user
        user = User.query.get(user_id)
        notification = Notification(
            user_id=user_id,
            message=f"You have been assigned to project '{project.name}' as {role}",
            notification_type="project"
        )
        db.session.add(notification)
        db.session.commit()
        
        flash('User assigned to project successfully', 'success')
        return redirect(url_for('admin_projects'))
    
    users = User.query.all()
    return render_template('admin/assign_project.html', project=project, users=users)

@app.route('/admin/categories', methods=['GET', 'POST'])
def admin_categories():
    if 'user_id' not in session or not session['is_admin']:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        
        # Check if category name already exists
        if TaskCategory.query.filter_by(name=name).first():
            flash('Category name already exists', 'danger')
            return redirect(url_for('admin_categories'))
        
        # Create new category
        new_category = TaskCategory(name=name, description=description)
        db.session.add(new_category)
        db.session.commit()
        
        flash('Category added successfully', 'success')
        return redirect(url_for('categories'))
    
    categories = TaskCategory.query.all()
    return render_template('admin/categories.html', categories=categories)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)