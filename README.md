# Cloud Sprint 🏃‍♂️☁️  

A collaborative **Project & Team Management Web Application** built with **Flask** and **SQLAlchemy**, designed to streamline task assignments, progress tracking, client management, team communication, and resource planning — all in one platform.  

---

## 🚀 Features  

### 🔑 User Authentication & Roles  
- Secure login & registration with password hashing  
- Role-based access (Admins & Team Members)  

### 👥 Team & Project Management  
- Create, edit, assign, and delete projects  
- Manage teams and assign users to specific projects  
- Track project status, milestones, and risks  

### ✅ Task Management  
- Create and categorize tasks  
- Assign tasks to team members  
- Track progress, update status, and add comments  

### ⏱️ Time Tracking & Reporting  
- Log time spent on tasks  
- View personal and team timesheets  
- Submit and view project progress reports  

### 📂 File Management  
- Upload project-related files  
- Secure file sharing with selected team members  
- Download with access control  

### 🧑‍💼 Client & Budget Management  
- Maintain client profiles  
- Track project budgets, used amounts, and remaining funds  

### 💬 Team Collaboration  
- In-app chat for team communication  
- Notifications for tasks, meetings, updates  

### 📅 Meetings & Scheduling  
- Schedule project meetings  
- Notify participants automatically  

---

## 🛠️ Tech Stack  
- **Backend:** Python, Flask, SQLAlchemy  
- **Database:** SQLite (can be upgraded to PostgreSQL/MySQL)  
- **Frontend:** HTML, CSS, Jinja2 Templates  
- **Authentication:** Werkzeug Security  
- **File Handling:** Secure Uploads & Downloads  

---

## 📂 Project Structure  
CloudSprint/
│
├── app.py # Main Flask application
├── static/ # CSS, JS, and uploaded files
├── templates/ # Jinja2 HTML templates
├── cloudsprint.db # SQLite database (created at runtime)
└── README.md # Project documentation

yaml
Copy code

---

## ⚡ Installation & Setup  

### 1️⃣ Clone the Repository  
```bash
git clone https://github.com/your-username/cloud-sprint.git
cd cloud-sprint
2️⃣ Create a Virtual Environment & Install Dependencies
bash
Copy code
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install flask flask_sqlalchemy werkzeug
3️⃣ Initialize the Database
bash
Copy code
python app.py
This will automatically create cloudsprint.db.

4️⃣ Run the App
bash
Copy code
python app.py
Then visit http://127.0.0.1:5000 in your browser.

👥 Usage
Register as a new user — the first registered user becomes Admin

Create teams, add users, and assign projects

Manage tasks, milestones, budgets, risks, and files

Communicate through the built-in chat and receive notifications for updates

