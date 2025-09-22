# Catatan Harian - Personal Note-Taking Application

## Overview

Catatan Harian is a Flask-based personal note-taking application designed for Indonesian users. The application allows users to create, store, and manage their personal notes with privacy features including app lock functionality and individual note locking. The system emphasizes simplicity and security, providing a clean interface for personal journaling and note management.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Template Engine**: Jinja2 templates with Bootstrap 5.1.3 for responsive UI
- **Styling Framework**: Bootstrap with custom CSS for enhanced visual appeal
- **JavaScript**: Vanilla JavaScript for form interactions, password toggles, and UI enhancements
- **Internationalization**: Indonesian language interface with localized text and date formatting

### Backend Architecture
- **Framework**: Flask web framework with session-based authentication
- **Authentication**: Werkzeug password hashing with session management
- **Security Features**: 
  - App-level PIN protection for additional security layer
  - Individual note privacy locks with confirmation prompts
  - Session-based user authentication
- **Routing**: RESTful route structure for user management and note operations

### Data Storage Solution
- **Database Type**: JSON file-based storage system
- **Files**:
  - `data/users.json`: User account information and credentials
  - `data/notes.json`: Note content, metadata, and privacy settings
- **Data Models**:
  - Users: ID, name, email, hashed password, creation timestamp, app lock PIN
  - Notes: ID, title, content, creation timestamp, privacy lock status, user association

### Authentication and Authorization
- **User Authentication**: Email/password login with secure password hashing
- **Session Management**: Flask sessions for maintaining user login state
- **Multi-layer Security**: 
  - Primary login authentication
  - Optional app-level PIN lock
  - Individual note privacy protection
- **Access Control**: User-scoped note access with privacy confirmation workflows

### Application Features
- **Note Management**: Create, view, and organize personal notes
- **Privacy Controls**: Lock sensitive notes requiring explicit confirmation to view
- **User Profiles**: Basic user information and account management
- **Security Dashboard**: App lock configuration and security settings
- **Responsive Design**: Mobile-friendly interface with Bootstrap components

## External Dependencies

### Frontend Libraries
- **Bootstrap 5.1.3**: CSS framework for responsive design and UI components
- **Font Awesome 6.0.0**: Icon library for enhanced visual interface
- **CDN Delivery**: External CDN hosting for Bootstrap and Font Awesome assets

### Backend Dependencies
- **Flask**: Core web framework for Python
- **Werkzeug**: Password hashing and security utilities
- **Gunicorn**: Production WSGI server for deployment
- **Python Standard Library**: JSON handling, datetime operations, file I/O, and session management

### Development Environment
- **Session Management**: Environment variable configuration for session secrets (SESSION_SECRET)
- **File System**: Local file storage for JSON databases and static assets
- **Static Assets**: CSS and JavaScript files served through Flask's static file handling
- **Replit Configuration**: ProxyFix middleware configured for proper HTTPS URL generation in Replit environment

## Recent Changes (September 21, 2025)

### Project Import and Setup
- Successfully imported GitHub repository to Replit environment
- Installed required Python dependencies: flask, werkzeug, gunicorn
- Configured Flask app with ProxyFix middleware for Replit proxy compatibility
- Set up workflow to serve on port 5000 with webview output
- Configured deployment settings for autoscale deployment target
- Verified application functionality with existing user data and notes