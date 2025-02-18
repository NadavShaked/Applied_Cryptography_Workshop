# config.py

import os

# Directory to save uploaded files
UPLOAD_FOLDER = 'StorageDirectory'

# Ensure the directory exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
