import requests


def upload_file(file_path, query_size, number_of_blocks, u, g, v, validate_every, buyer_private_key, seller_pubkey):
    """Uploads a file to the Flask server with additional parameters."""
    url = "http://localhost:8000/api/upload"

    # Open the file in binary mode
    with open(file_path, "rb") as file:
        files = {"file": file}  # The key "file" must match Flask's expected key
        data = {
            "query_size": query_size,
            "number_of_blocks": number_of_blocks,
            "u": u,
            "g": g,
            "v": v,
            "validate_every": validate_every,
            "buyer_private_key": buyer_private_key,
            "escrow_public_key": seller_pubkey
        }

        # Send the request with both files and JSON data
        response = requests.post(url, files=files, data=data)

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
    file_path = "/Users/nadavshaked/Code Projects/Pycharm Projects/Applied_Cryptography_Workshop/PublicKeyVersionScheme/EncodedFiles/PoR.pdf.encoded"

    # Step 1: Upload the file
    uploaded_filename = upload_file(file_path,              #file_path
                                    4,                      #query_size
                                    7,                     #number_of_blocks
                                    "8b9c0c74e3ca7830f7daf44f3d81c2ca046ff2a8ec1d4c06e724edc0891836e792e0893925779d601aa4bdc6d8966e3a",                    #u
                                    "a801eb01d33a752d4e5bb26c873d1773a4fc7289b3edfbaa444a368f15b8f9ef139c385323939cb85be3b3dd526aa44a13c50c21c1cbb9b358bf1fc3ff65cc6acfc895d430964efbb9eebfbc5eeb56b908d9baf78a5a6b5921afbb9a943d401e",                    #g
                                    "887cf0251525479fe1f7b3fdd1b089c08f12aea37ae622386cdd89fbb0f542c83067c20f51710bead72434c269b0e57e15e6b8c8224c23946b346edc2962b55a26247d1dff3afe1001a184a9965da744faa2351e5d8829e0d6eedee32c7f1759",                    #v
                                    10,                     #validate_every
                                    "5HhvksCUDH5TS4dy9iPLS4kjSQaJSNCQiRseQVCY2ESrBpebB9FjjxhPLTsfbyVJc2yaBwnKuyVVgpHvN6PCRkB3",    #buyer_private_key
                                    "8KjBMY5TYJnDJaYhxequB3uYDmD6K1apxRUvhtUZjDyH")        #escrow_pubkey

    # Step 2: Request calculations for the uploaded file
    calculate_file_data("PoR.pdf.encoded")
