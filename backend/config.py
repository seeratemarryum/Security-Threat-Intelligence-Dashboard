import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
    UPLOAD_FOLDER = 'static/uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    
    PHISHTANK_URL = 'http://data.phishtank.com/data/online-valid.json'