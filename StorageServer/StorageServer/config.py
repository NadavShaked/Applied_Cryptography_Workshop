# config.py

import os
import shutil

# Directory to save uploaded files
UPLOAD_FOLDER = 'StorageDirectory'

if os.path.exists(UPLOAD_FOLDER):
    shutil.rmtree(UPLOAD_FOLDER)
else:
    # Ensure the directory exists
    os.makedirs(UPLOAD_FOLDER)
