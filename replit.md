# PranavCrypt - Multi-Algorithm Cryptographic Application

## Overview
PranavCrypt is a comprehensive Python Flask web application demonstrating four modern cryptographic algorithms: RSA, AES, ChaCha20, and Blowfish. It provides an interactive web interface for file and text encryption/decryption with a sleek Matrix-themed design.

## Project Setup

### Technology Stack
- **Backend**: Flask 2.3.3 (Python web framework)
- **Cryptography**: Python cryptography library 41.0.7
- **Frontend**: Bootstrap 5.1.3, Font Awesome 6.0.0
- **Server**: Gunicorn 21.2.0 (production)
- **Python Version**: 3.11

### Project Structure
```
├── pranav_crypt.py          # Main Flask application with crypto logic
├── app.py                   # Simple app launcher
├── requirements.txt         # Python dependencies
├── templates/               # HTML templates
│   ├── base.html           # Base template with navigation and styling
│   ├── home.html           # Home page with algorithm showcase
│   ├── encrypt_decrypt.html # Main encryption/decryption interface
│   ├── about.html          # About page with algorithm details
│   └── index.html          # Index page
├── temp_uploads/           # Temporary file storage (auto-created)
└── Secret.key              # Secret key file
```

### Supported Algorithms
1. **RSA**: Asymmetric encryption with 2048-bit keys and hybrid encryption
2. **AES**: Symmetric encryption using AES-256-CBC with random IV generation
3. **ChaCha20**: High-performance stream cipher with 256-bit keys
4. **Blowfish**: Fast block cipher with 448-bit keys and CBC mode

## Replit Configuration

### Workflow
- **Name**: flask-app
- **Command**: `python pranav_crypt.py`
- **Port**: 5000 (webview)
- **Status**: Running

### Deployment
- **Type**: Autoscale (stateless web application)
- **Command**: `gunicorn --bind=0.0.0.0:5000 --reuse-port pranav_crypt:app`
- **Port**: 5000

### Environment Variables
- `PORT`: 5000 (default, can be overridden)
- `FLASK_ENV`: Set to 'production' for deployment
- `SECRET_KEY`: Auto-generated for session management

## Features

### Security Features
- No persistent storage of keys or messages
- Cryptographically secure random number generation
- Input validation and sanitization
- Secure session management
- All operations performed in memory

### User Interface
- Clean, responsive Bootstrap 5 design
- Matrix-themed with neon green/blue color scheme
- Animated background with Matrix rain effect
- Algorithm selection with detailed descriptions
- Key generation for asymmetric algorithms
- Real-time encryption and decryption
- Base64 encoded output for easy sharing

## Development Notes

### Important Implementation Details
1. **Host Configuration**: Flask app is configured to run on `0.0.0.0:5000` which works with Replit's proxy system
2. **File Upload**: Max file size is 50MB (configurable via `MAX_CONTENT_LENGTH`)
3. **Temporary Storage**: Files are stored in `temp_uploads/` directory which is gitignored
4. **Hybrid Encryption**: RSA uses hybrid encryption (AES + RSA) for large messages
5. **Session Security**: Uses secure session management with auto-generated secret keys

### Running Locally
```bash
python pranav_crypt.py
```
Access at: `http://localhost:5000`

### Production Deployment
The app is configured for Replit's autoscale deployment using Gunicorn as the WSGI server.

## Recent Changes
- **2025-11-03**: Initial Replit setup
  - Installed Python 3.11 and dependencies
  - Configured workflow for port 5000
  - Set up deployment configuration for autoscale
  - Verified frontend and backend functionality

## User Preferences
(To be updated as preferences are expressed)
