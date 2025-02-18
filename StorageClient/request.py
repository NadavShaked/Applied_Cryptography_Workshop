import requests


def upload_file(file_path):
    """Uploads a file to the Flask server."""
    url = "http://localhost:8000/api/upload"

    # Open the file in binary mode
    with open(file_path, "rb") as file:
        files = {"file": file}  # The key "file" must match Flask's expected key
        response = requests.post(url, files=files)

    # Print the response from the server
    print("Upload response:", response.json())

    # Return the uploaded filename to use in the next API call
    return response.json().get("filename")


def calculate_file_data(filename):
    """Requests the calculation for the given file."""
    url = f"http://localhost:8000/api/calculate?filename={filename}"

    # Send a GET request to the calculation API
    response = requests.get(url)

    # Print the response from the server
    print("Calculation response:", response.json())


if __name__ == "__main__":
    # Change this to the actual file path you want to upload
    file_path = "/Users/nadavshaked/Code Projects/Pycharm Projects/Applied_Cryptography_Workshop/PublicKeyVersionScheme/EncodedFiles/PoR.pdf.encoded.txt"

    # Step 1: Upload the file
    uploaded_filename = upload_file(file_path)

    # Step 2: Request calculations for the uploaded file
    calculate_file_data("PoR.pdf.encoded.txt")
