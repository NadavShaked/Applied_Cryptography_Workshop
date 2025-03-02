import requests
import os


def upload_file(file_path, escrow_pubkey):
    """Uploads a file to the Flask server with additional parameters."""
    url = "http://localhost:8000/api/upload"

    # Open the file in binary mode
    with open(file_path, "rb") as file:
        files = {"file": file}  # The key "file" must match Flask's expected key
        data = {
            "escrow_public_key": escrow_pubkey
        }

        # Send the request with both files and JSON data
        response = requests.post(url, files=files, data=data)

    # Print the response from the server
    print("Upload response:", response.json())

    # Return the uploaded filename to use in the next API call
    return response.json().get("filename")


def corrupt_file(file_name):
    """Requests file corruption for the given file."""
    url = f"http://localhost:8000/api/corrupt?filename={file_name}"

    # Send a GET request to the corruption API
    response = requests.get(url)

    # Print the response from the server
    print("Corrupt response:", response.json())


def calculate_file_data(file_name):
    """Requests the calculation for the given file."""
    url = f"http://localhost:8000/api/calculate_and_prove?filename={file_name}"

    # Send a GET request to the calculation API
    response = requests.get(url)

    # Print the response from the server
    print("Calculation response:", response.json())


def download_file(file_name, save_path):
    """Downloads a file from the Flask server."""
    url = f"http://localhost:8000/api/download?filename={file_name}"

    # Send a GET request to download the file
    response = requests.get(url)

    download_file_path = os.path.join(save_path, file_name)

    if response.status_code == 200:
        with open(download_file_path, "wb") as file:
            file.write(response.content)
        print(f"File '{file_name}' downloaded successfully to '{save_path}'.")
    else:
        print(f"Failed to download file: {response.json()}")


if __name__ == "__main__":
    # Change this to the actual file path you want to upload
    file_path = "/Users/nadavshaked/Code Projects/Pycharm Projects/Applied_Cryptography_Workshop/Files/PoR.pdf"

    # Step 1: Upload the file
    uploaded_filename = upload_file(file_path, "7pbM6QCdgRU1LxVmyKpuSvYTR4VSXYbBkPYM25zDwASk")

    # Step 2: Corrupt the file
    # corrupt_file("PoR.pdf.encoded")

    # Step 3: Request calculations for the uploaded file
    # calculate_file_data("PoR.pdf.encoded")

    # Step 4: Download the file
    # download_file("PoR.pdf.encoded", "/Users/nadavshaked/Downloads/aaaaa")
