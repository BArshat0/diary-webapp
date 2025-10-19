# Digital Diary Web Application

A secure, modern web-based diary application built with Flask that provides users with a private digital space for personal journaling. This project showcases the power of AI-assisted development through extensive prompt engineering with ChatGPT and DeepSeek.

## 🚀 AI-Powered Development

**This project was extensively developed using AI prompt engineering** with ChatGPT and DeepSeek. The entire development process—from initial concept to deployment—was guided and accelerated through strategic prompting, demonstrating the capabilities of modern AI coding assistants.

## ✨ Features

### 🔐 Security & Authentication
- Secure user registration and login system
- Password hashing with Werkzeug
- CSRF protection for all forms
- Session management with secure cookies
- Input validation and sanitization

### 📝 Diary Management
- Create multiple personal diaries
- Rich text editing interface
- Real-time search functionality
- Download diaries for local backup
- Edit and update existing entries

### 🎨 User Experience
- Responsive Bootstrap design
- Dark/Light theme toggle
- Smooth page transitions and animations
- Mobile-friendly interface
- Toast notifications for user feedback

### 🔧 Technical Features
- SQLite database with user management
- File-based diary storage
- Logging system with rotation
- Gunicorn production server ready

## 🛠️ Tech Stack

- **Backend**: Python, Flask, SQLite
- **Frontend**: HTML5, CSS3, JavaScript, Bootstrap 5
- **Security**: Werkzeug, CSRF protection, input validation
- **Development**: AI Prompt Engineering (ChatGPT, DeepSeek)

## 📋 Prerequisites

- Python 3.8+
- pip package manager

## 🚀 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/BArshat0/diary-webapp.git
   cd diary-webapp
2. Install Dependencies
    pip install -r requirements.txt
3. Set up Enviornment
    export SECRET_KEY="your-secret-key-here"
4. Run the application
  # Development
python diary_webapp.py

  # Production
gunicorn wsgi:app (or you can use waitress)

## 📁 Project Structure
diary-webapp/

  ├── diary_webapp.py        # Main application
  
  ├── config.py              # Configuration settings
  
  ├── wsgi.py               # Production WSGI entry point
  
  ├── requirements.txt       # Python dependencies
  
  ├── Diary.py              # Additional modules
  
  └── README.md             # Project documentation

## 🔒 Security Features
-Password hashing with salt

-CSRF token validation

-SQL injection prevention

-XSS protection through input sanitization

-Secure session management

-File path traversal protection

## 🧑‍💻 Author

# Barshat Panday
💬 Passionate about Cybersecurity and AI-Prompt Enginnering.
📍 Built entirely with ChatGPT & DeepSeek assistance.

5. Set up environment
    
