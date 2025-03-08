# Standard library imports
import os


files_details_dict = {}


# Function to save uploaded files to the specified directory
def save_file(file, upload_folder):
    # Ensure the directory exists
    if not os.path.exists(upload_folder):
        os.makedirs(upload_folder)

    file_path = os.path.join(upload_folder, file.filename)

    # Check if the file already exists
    if os.path.exists(file_path):
        print("FileExistsError")
        raise FileExistsError(f"File '{file.filename}' already exists in the directory.")

    try:
        file.save(file_path)
    except Exception as e:
        raise Exception(f"Failed to save file: {str(e)}")

    return file_path


# Function to remove a file from the specified directory
def remove_file(file_name, upload_folder):
    file_path = os.path.join(upload_folder, file_name)

    # Check if the file exists
    if not os.path.exists(file_path):
        print("FileNotFoundError")
        raise FileNotFoundError(f"File '{file_name}' does not exist in the directory.")

    try:
        os.remove(file_path)
        print(f"File '{file_name}' has been removed successfully.")
    except Exception as e:
        raise Exception(f"Failed to remove file: {str(e)}")
