import os
import sys
import logging
# DON'T CHANGE THIS !!!
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from flask import Flask, send_from_directory
from flask_cors import CORS
from src.models import db
from src.routes.user import user_bp
from src.routes.security import security_bp
from src.config import get_config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

app = Flask(__name__, static_folder=os.path.join(os.path.dirname(__file__), 'static'))

# Load configuration
config = get_config()
app.config.from_object(config)

# Enable CORS for all routes
CORS(app)

# Register blueprints
app.register_blueprint(user_bp, url_prefix='/api')
app.register_blueprint(security_bp, url_prefix='/api/security')

# Import and register analytics blueprint
from src.routes.analytics import analytics_bp
app.register_blueprint(analytics_bp, url_prefix='/api/analytics')

# Initialize database
db.init_app(app)

with app.app_context():
    db.create_all()

@app.route('/', defaults={'path': ''}) 
@app.route('/<path:path>')
def serve(path):
    static_folder_path = app.static_folder
    if static_folder_path is None:
            return "Static folder not configured", 404

    if path != "" and os.path.exists(os.path.join(static_folder_path, path)):
        return send_from_directory(static_folder_path, path)
    else:
        # Check for dashboard.html first, then index.html
        dashboard_path = os.path.join(static_folder_path, 'dashboard.html')
        index_path = os.path.join(static_folder_path, 'index.html')
        
        if os.path.exists(dashboard_path):
            return send_from_directory(static_folder_path, 'dashboard.html')
        elif os.path.exists(index_path):
            return send_from_directory(static_folder_path, 'index.html')
        else:
            return "Dashboard not found", 404

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return {'status': 'healthy', 'service': 'cloud-security-automation'}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)


