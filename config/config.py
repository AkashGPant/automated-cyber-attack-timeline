import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, 'sample_data')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports_output')

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

RISK_LOW = 30
RISK_MEDIUM = 60
RISK_HIGH = 80
