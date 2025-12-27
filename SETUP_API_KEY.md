# API Key Setup Guide

## Option 1: Using .env File (Recommended)

1. Create a file named `.env` in the project root directory (same folder as `app.py`)

2. Add your API key to the `.env` file:
   ```
   GEMINI_API_KEY=your-actual-api-key-here
   ```

3. The `.env` file is already in `.gitignore`, so it won't be committed to git.

## Option 2: Using System Environment Variable (Windows)

### PowerShell (Temporary - Current Session Only)
```powershell
$env:GEMINI_API_KEY="your-actual-api-key-here"
python app.py
```

### PowerShell (Permanent - User Level)
```powershell
[System.Environment]::SetEnvironmentVariable('GEMINI_API_KEY', 'your-actual-api-key-here', 'User')
```
Then restart your terminal/PowerShell.

### Command Prompt (CMD)
```cmd
setx GEMINI_API_KEY "your-actual-api-key-here"
```
Then restart your terminal/CMD.

### Windows GUI Method
1. Press `Win + R`, type `sysdm.cpl`, press Enter
2. Go to "Advanced" tab → Click "Environment Variables"
3. Under "User variables", click "New"
4. Variable name: `GEMINI_API_KEY`
5. Variable value: `your-actual-api-key-here`
6. Click OK and restart your terminal/IDE

## Option 3: Using System Environment Variable (Linux/Mac)

### Terminal (Temporary - Current Session Only)
```bash
export GEMINI_API_KEY="your-actual-api-key-here"
python app.py
```

### Terminal (Permanent)
Add to `~/.bashrc` or `~/.zshrc`:
```bash
export GEMINI_API_KEY="your-actual-api-key-here"
```
Then run: `source ~/.bashrc` (or `source ~/.zshrc`)

## Verify Setup

After setting up, run your application:
```bash
python app.py
```

The application will automatically load the API key from the environment variable when using the "Intelligence Analyst" model.

