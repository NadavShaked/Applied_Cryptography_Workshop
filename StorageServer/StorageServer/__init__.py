# __init__.py

from flask import Flask
from .api import api_bp


def create_app():
    app = Flask(__name__)

    # Register the API Blueprint for the StorageServer app
    app.register_blueprint(api_bp)

    return app
