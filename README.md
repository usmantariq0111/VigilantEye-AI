# VigilantEye-AI

A Flask-based web application for detecting malicious GIF files using AI/ML models.

## Features

- GIF file scanning and malware detection
- User authentication (login/signup)
- Scan history tracking
- CSV report export
- Modern web interface

## Installation

1. Clone the repository:
```bash
git clone https://github.com/usmantariq0111/VigilantEye-AI.git
cd VigilantEye-AI
```

2. Create a virtual environment:
```bash
python -m venv venv
```

3. Activate the virtual environment:
- Windows PowerShell: `.\venv\Scripts\Activate.ps1`
- Windows CMD: `venv\Scripts\activate.bat`
- Linux/Mac: `source venv/bin/activate`

4. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the Flask application:
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## Project Structure

- `app.py` - Main Flask application
- `test_model.py` - ML model for GIF prediction
- `templates/` - HTML templates
- `static/` - Static files (CSS, JS, uploads)

## License

MIT License

