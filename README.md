
# CyberSentinel

*Made by Team CyferTrace*

CyberSentinel is a FastAPI-based web application for automated cyber threat analysis. It parses and analyzes Indicators of Compromise (IOCs) such as hashes, IPs, domains, URLs, and emails, providing risk scoring, threat intelligence, geo-location, and actionable recommendations. The app supports exporting results in CSV and STIX formats.

## Features
- IOC extraction and analysis (hashes, IPs, domains, URLs, emails)
- Threat intelligence lookups
- Risk scoring and action recommendations
- Geo-location enrichment
- YARA and Sigma rule scanning
- MITRE ATT&CK mapping
- Export results as CSV or STIX
- Web interface with summary tables

## Project Structure
```
backend/
  main.py            # FastAPI app entry point
  config/
    api_keys.json    # API keys for external services
agents/              # Analysis and enrichment modules
static/              # Static files (CSS)
templates/           # Jinja2 HTML templates
utils/               # Helper utilities
requirements.txt     # Python dependencies
```

## Getting Started

### Prerequisites
- Python 3.12 or later (recommended)
- Git (for cloning the repository)
- Internet connection (for installing dependencies and threat lookups)


### 1. Clone the repository
```
git clone <repo-url>
cd CyberSentinel
```

### 2. Create and activate a virtual environment (Windows)
```
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install dependencies
```
pip install -r requirements.txt
```

If you encounter permission errors on Windows, use:
```
pip install --no-cache-dir -r requirements.txt
```

### 4. Configure environment variables
- Create a `.env` file in the root if needed (for API keys, etc.)
- Edit `backend/config/api_keys.json` with your API keys if required

### 5. Run the application
```
cd backend
uvicorn main:app --reload
```

### 6. Access the web interface
Open your browser and go to:
```
http://127.0.0.1:8000/
```

## Troubleshooting
- If you see errors about missing packages (e.g., `ModuleNotFoundError`), install them with `pip install <package-name>`.
- For permission errors during installation, run your terminal as Administrator or use the `--no-cache-dir` flag.
- If you see `ModuleNotFoundError: No module named 'sigma.collection'`, uninstall the `sigma` package and install `sigma-cli` instead:
  ```
  pip uninstall -y sigma
  pip install sigma-cli
  ```
- For form upload errors, install `python-multipart`:
  ```
  pip install python-multipart
  ```

## Usage
- Paste raw log data or IOCs into the input form
- Select options for geo enrichment or export
- View results and download reports as needed

## Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss what you would like to change.


## License
MIT License
