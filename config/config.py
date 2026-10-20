import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, 'sample_data')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports_output')
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')
RULES_OVERRIDE_FILE = os.path.join(BASE_DIR, 'config', 'detection_rules.json')

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Risk score -> severity thresholds (score < RISK_LOW => LOW, ...)
RISK_LOW = 30
RISK_MEDIUM = 60
RISK_HIGH = 80

# Upload / parsing limits
MAX_UPLOAD_ROWS = 500_000
