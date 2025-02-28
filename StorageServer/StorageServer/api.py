
from flask import Blueprint, request, jsonify

from Common.Providers.solanaApiGatewayProvider import SolanaGatewayClientProvider
from PublicKeyVersionScheme.helpers import p, MAC_SIZE, BLOCK_SIZE, compress_g1_to_hex, MAC_SIZE_3D
from .storage import save_file
from .config import UPLOAD_FOLDER
import py_ecc.optimized_bls12_381 as bls_opt
from datetime import datetime
from .storage import files_details_dict

import os

SELLER_PRIVATE_KEY = "4RkKhxhNf28menedSJ3sAprUaYiT1SAcBwpHX48mmHKPrQcJNtqPHMZSYY24W8Fsrp73qGRKhgBi7EjaDGN2dsUL"

# Create a Blueprint for the API in the StorageServer app
api_bp = Blueprint('api', __name__)


@api_bp.route("/api/upload", methods=["POST"])
def upload_file():
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

    # Get parameters from request based on content type (either JSON or form-data)
    if request.content_type == "application/json":
        params = request.json  # If sent as JSON
        print("Received parameters as JSON")
    else:
        params = request.form  # If sent as form-data
        print("Received parameters as form-data")

    # Extract the escrow public key from the request parameters
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


@api_bp.route("/api/calculate", methods=["GET"])
def calculate_values():
    """
    Calculates the values of σ (sigma) and μ (mu) for a given file based on its metadata.

    This function:
    - Retrieves the filename from the request parameters.
    - Looks up the file details in `files_details_dict`.
    - Validates that the file exists in the specified folder.
    - Calculates the values of σ and μ using the `calculate_sigma_mu_and_prove` function.
    - Returns whether the calculation was successfully proved or not.

    Args:
        None

    Returns:
        jsonify (dict): A response object containing the result of the calculation and whether it was proved.
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
            "proved": is_proved,  # Indicates whether the proof was valid
        })

    except Exception as e:
        # Handle any errors that occur during the process
        return jsonify({"error": f"An error occurred during calculation: {str(e)}"}), 500


def calculate_sigma_mu_and_prove(filename: str, escrow_public_key: str) -> bool:
    """
    Calculates the values of σ (sigma) and μ (mu) based on the provided file and escrow public key,
    and sends a proof request to the Solana gateway client.

    This function:
    - Retrieves queries from the Solana gateway for a specific escrow account.
    - Processes the file by reading its blocks, extracting the relevant information, and calculating
      the values of σ and μ using cryptographic operations.
    - Sends the proof to the Solana gateway to verify the results.

    Args:
        filename (str): The name of the file containing the data to be processed.
        escrow_public_key (str): The public key associated with the escrow account.

    Returns:
        bool: Returns True if the proof was successfully generated and verified, otherwise False.
    """
    file_path = os.path.join(UPLOAD_FOLDER, filename)

    # Create client instance to interact with the Solana gateway
    client = SolanaGatewayClientProvider()

    # Fetch queries associated with the given escrow public key
    generate_queries_response = client.generate_queries(SELLER_PRIVATE_KEY, escrow_public_key)

    if 200 <= generate_queries_response.status_code < 300:
        # Assuming generate_queries_response is the response from the GET query
        generate_queries_response_json = generate_queries_response.json()

        # Fetch the 'message' key's value (for logging or debugging purposes)
        message = generate_queries_response_json.get("message")
        print(message)
    else:
        return False

    # Fetch existing queries associated with the escrow public key
    get_queries_by_escrow_pubkey_response = client.get_queries_by_escrow(escrow_public_key)

    if 200 <= get_queries_by_escrow_pubkey_response.status_code < 300:
        # Assuming get_queries_response is the response from the GET query
        get_queries_by_escrow_pubkey_response_json = get_queries_by_escrow_pubkey_response.json()

        # Fetch the 'queries' key's value (list of queries)
        queries = get_queries_by_escrow_pubkey_response_json.get("queries")
    else:
        return False

    # Separate the indices and coefficients from the queries
    indices = [query[0] for query in queries]
    coefficients = [int(query[1], 16) for query in queries]

    # Initialize the variables for σ and μ
    σ = None
    μ: int = 0

    # Process the file to calculate σ and μ
    with open(file_path, "rb") as f:
        block_index: int = 0

        while True:
            # Read the next block (data + authenticator)
            full_block: bytes = f.read(BLOCK_SIZE + MAC_SIZE_3D)  # up-to 1024-byte data, 4-byte * 3 for 3d point authenticator tag
            if not full_block:
                break  # End of file

            # Extract m_i from the block data
            m_i: int = int.from_bytes(full_block[:-MAC_SIZE_3D], byteorder='big') % p

            # Extract 3D MAC (x, y, z coordinates)
            _3d_mac: bytes = full_block[-MAC_SIZE_3D:]
            mac_x_coordinate: bytes = _3d_mac[0:MAC_SIZE]  # Bytes 0 - (MAC_SIZE - 1)
            mac_y_coordinate: bytes = _3d_mac[MAC_SIZE:2 * MAC_SIZE]  # Bytes (MAC_SIZE) - (2 * MAC_SIZE - 1)
            mac_z_coordinate: bytes = _3d_mac[2 * MAC_SIZE:3 * MAC_SIZE]  # Bytes (2 * MAC_SIZE) - (3 * MAC_SIZE - 1)

            # Convert MAC coordinates to integers
            mac_x_coordinate_as_int = int.from_bytes(mac_x_coordinate, byteorder='big')
            mac_y_coordinate_as_int = int.from_bytes(mac_y_coordinate, byteorder='big')
            mac_z_coordinate_as_int = int.from_bytes(mac_z_coordinate, byteorder='big')

            # Create the σ_i tuple for the current block
            σ_i = (bls_opt.FQ(mac_x_coordinate_as_int), bls_opt.FQ(mac_y_coordinate_as_int),
                   bls_opt.FQ(mac_z_coordinate_as_int))

            # If this block's index is part of the queries, calculate the corresponding values
            if block_index in indices:
                v_i: int = coefficients[indices.index(block_index)]
                σ_i_power_v_i = bls_opt.multiply(σ_i, v_i)  # (σ_i)^(v_i)

                # Aggregate the σ_i values
                if σ is None:
                    σ = σ_i_power_v_i
                else:
                    σ = bls_opt.add(σ, σ_i_power_v_i)

                # Update μ with the corresponding value
                v_i_multiply_m_i = (v_i * m_i) % p
                μ = (μ + v_i_multiply_m_i) % p

            block_index += 1

    # Send the proof request to the Solana gateway
    prove_response = client.prove(SELLER_PRIVATE_KEY, escrow_public_key, compress_g1_to_hex(σ), μ.to_bytes(32, 'big').hex())

    if 200 <= prove_response.status_code < 300:
        # Assuming prove_response is the response from the prove request
        prove_response_json = prove_response.json()

        # Fetch the 'queries' key's value (for logging or debugging purposes)
        queries = prove_response_json.get("queries")
        return True  # Return True to indicate the proof was successfully generated and verified
    else:
        return False  # Return False if the proof request failed
