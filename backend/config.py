import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', 'your_shodan_api_key_here')
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', 'your_abuseipdb_api_key_here')
    UPLOAD_FOLDER = 'static/uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024