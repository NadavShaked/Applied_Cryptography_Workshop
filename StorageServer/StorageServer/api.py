from flask import Blueprint, request, jsonify
from Common.Providers.solanaApiGatewayProvider import SolanaGatewayClientProvider
from . import calculate_sigma_mu_and_prove
from .storage import save_file
from .config import UPLOAD_FOLDER
from datetime import datetime
from .storage import files_details_dict
from Common.ReedSolomon.reedSolomon import corrupt_file
from flask import send_file
import os


# Create a Blueprint for the API in the StorageServer app
api_bp = Blueprint('api', __name__)


@api_bp.route('/api/download', methods=['GET'])
def download_endpoint():
    """
    Handles file download requests.

    This function:
    - Accepts a filename parameter from the request.
    - Validates if the filename is provided.
    - Checks if the file exists in the storage directory.
    - If the file exists, it sends the file as an attachment for download.
    - If the file does not exist, it returns a 404 error with a message.

    Args:
        None

    Returns:
        send_file (file): The file requested for download, sent as an attachment.
        jsonify (dict): A JSON response with error messages (in case of failure).
    """
    filename = request.args.get("filename")
    print(f"Received download request for file: {filename}")

    if not filename:
        print("Error: Filename not provided")
        return jsonify({"error": "Filename not provided"}), 400

    file_path = os.path.abspath(os.path.join(UPLOAD_FOLDER, filename))
    print(f"Constructed file path: {file_path}")

    if not os.path.exists(file_path):
        print(f"Error: File {filename} not found at {file_path}")
        return jsonify({"error": "File not found"}), 404

    print(f"File {filename} found, sending for download...")
    return send_file(file_path, as_attachment=True)


@api_bp.route("/api/upload", methods=["POST"])
def upload_endpoint():
    """
    Handles file uploads and processes associated metadata for an escrow account.

    This function:
    - Accepts a file upload via a POST request.
    - Retrieves the `escrow_public_key` from the request.
    - Fetches escrow data from the Solana Gateway Client.
    - Validates the data and saves the file to the specified directory.
    - Updates the metadata for the uploaded file in the `files_details_dict`.

    Args:
        None

    Returns:
        jsonify (dict): A response object containing success or error message.
    """
    print("Received file upload request")

    # Check if a file is included in the request
    if "file" not in request.files:
        print("Error: No file provided in the request")
        return jsonify({"error": "No file provided"}), 400

    uploaded_file = request.files["file"]

    # Check if the uploaded file has a name
    if uploaded_file.filename == "":
        print("Error: Empty file name")
        return jsonify({"error": "Empty file name"}), 400

    if request.content_type == "application/json":
        params = request.json
        print("Received parameters as JSON")
    else:
        params = request.form
        print("Received parameters as form-data")

    escrow_pubkey = params.get("escrow_public_key", type=str)
    print(f"Escrow public key: {escrow_pubkey}")

    try:
        # Initialize Solana client and get escrow data
        client = SolanaGatewayClientProvider()
        print("Fetching escrow data using the Solana client")
        get_escrow_data_response = client.get_escrow_data(escrow_pubkey)

        # Check if the response from the Solana client is successful
        if 200 <= get_escrow_data_response.status_code < 300:
            print("Successfully retrieved escrow data")
            get_escrow_data_response_json = get_escrow_data_response.json()

            # Extract the 'validate_every' parameter from the response
            validate_every = get_escrow_data_response_json.get("validate_every")
            print(f"Validate every: {validate_every}")
        else:
            print(f"Error: Failed to retrieve escrow data, status code: {get_escrow_data_response.status_code}")
            return jsonify({"error": f"Failed to retrieve escrow data"}), 500

    except Exception as e:
        print(f"Exception while fetching escrow data: {str(e)}")
        return jsonify({"error": f"Failed to fetch escrow data: {str(e)}"}), 500

    # Save the uploaded file
    try:
        print(f"Saving file: {uploaded_file.filename}")
        file_path = save_file(uploaded_file, UPLOAD_FOLDER)
        print(f"File saved at {file_path}")
    except FileExistsError as e:
        print(f"Error: File '{e.args[0]}' already exists in the directory")
        return jsonify({"error": f"File '{e.args[0]}' already exists in the directory."}), 409
    except Exception as e:
        print(f"Exception while saving file: {str(e)}")
        return jsonify({"error": f"Failed to save file: {str(e)}"}), 500

    # Update the details of the uploaded file in the storage dictionary
    files_details_dict[uploaded_file.filename] = {
        "escrow_public_key": escrow_pubkey,
        "validate_every": validate_every,
        "last_verify": datetime.now()
    }
    print(f"Updated file details for {uploaded_file.filename}")

    # Return a success message
    return jsonify({"message": "File received and saved", "filename": uploaded_file.filename})


@api_bp.route("/api/calculate_and_prove", methods=["GET"])
def calculate_and_prove_endpoint():
    """
    Calculates the values of σ (sigma) and μ (mu) for a given file based on its metadata and
    validates the proof of the calculation.

    This function:
    - Retrieves the filename from the request parameters.
    - Looks up the file details in `files_details_dict`.
    - Validates the existence of the file in the specified folder.
    - Calculates the values of σ and μ using the `calculate_sigma_mu_and_prove` function.
    - Returns whether the calculation was successfully proved.

    Args:
        None

    Returns:
        jsonify (dict): A response object containing the result of the calculation and whether it was proved.
        - If successful, returns a JSON object with a "proved" field indicating the validity of the calculation.
        - If an error occurs, returns an error message and a corresponding HTTP status code.
    """
    try:
        # Retrieve filename from request parameters
        filename = request.args.get("filename")
        file_details = files_details_dict[filename]

        # Check if the filename is provided
        if not filename:
            return jsonify({"error": "Filename not provided"}), 400

        # Construct the full file path
        file_path = os.path.join(UPLOAD_FOLDER, filename)

        # Check if the file exists
        if not os.path.exists(file_path):
            return jsonify({"error": "File not found"}), 404

        # Calculate the values of σ and μ and check if the proof is valid
        is_proved: bool = calculate_sigma_mu_and_prove(filename, file_details["escrow_public_key"])

        # Return the calculated values and the proof result
        return jsonify({
            "proved": is_proved,
        })

    except Exception as e:
        return jsonify({"error": f"An error occurred during calculation: {str(e)}"}), 500


@api_bp.route("/api/corrupt", methods=["GET"])
def corrupt_file_endpoint():
    """
    Handles file corruption requests.

    This function:
    - Accepts a filename as a request parameter.
    - Checks if the filename is provided and if the file exists.
    - If the file exists, it corrupts the file using the `corrupt_file_with_rs` function.
    - If any errors occur during the process, it returns a 500 error with the exception message.

    Args:
        None

    Returns:
        jsonify (dict): A response object containing success or error message.
    """
    try:
        # Retrieve file_name from request parameters
        file_name = request.args.get("filename")

        # Check if the file_name is provided
        if not file_name:
            return jsonify({"error": "Filename not provided"}), 400

        file_path = os.path.join(UPLOAD_FOLDER, file_name)

        if not os.path.exists(file_path):
            return jsonify({"error": "File not found"}), 404

        # corrupt the file by changing bytes
        corrupt_file(file_path, file_path)

        # Return the calculated values and the proof result
        return jsonify({
            "message": f'The file "{file_name}" corrupted.',
        })

    except Exception as e:
        return jsonify({"error": f"An error occurred during calculation: {str(e)}"}), 500
