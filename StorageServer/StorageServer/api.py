# api.py
import secrets

from flask import Blueprint, request, jsonify

from Common.Providers.SolanaApiGatewayProvider import SolanaGatewayClientProvider
from Common.helpers import write_file_by_blocks_with_authenticators, secure_random_sample
from PublicKeyVersionScheme.helpers import HASH_INDEX_BYTES, DST, p, generate_g, generate_x, generate_v, generate_u, \
    MAC_SIZE, BLOCK_SIZE, compress_g1_to_hex
from .storage import save_file
from .config import UPLOAD_FOLDER
import py_ecc.bls.hash_to_curve as bls_hash
import py_ecc.optimized_bls12_381 as bls_opt
import requests
from datetime import datetime
from .storage import files_details_dict

import os
from hashlib import sha256

SELLER_PRIVATE_KEY = "4RkKhxhNf28menedSJ3sAprUaYiT1SAcBwpHX48mmHKPrQcJNtqPHMZSYY24W8Fsrp73qGRKhgBi7EjaDGN2dsUL"

# Create a Blueprint for the API in the StorageServer app
api_bp = Blueprint('api', __name__)


# File upload API
@api_bp.route("/api/upload", methods=["POST"])
def upload_file():
    print("yay3")

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    uploaded_file = request.files["file"]

    if uploaded_file.filename == "":
        return jsonify({"error": "Empty file name"}), 400

    # Get parameters from request
    if request.content_type == "application/json":
        params = request.json  # If sent as JSON
    else:
        params = request.form  # If sent as form-data

    # Extract parameters as before
    query_size = params.get("query_size", type=int)
    number_of_blocks = params.get("number_of_blocks", type=int)
    u = params.get("u", type=str)
    g = params.get("g", type=str)
    v = params.get("v", type=str)
    validate_every = params.get("validate_every", type=int)
    buyer_private_key = params.get("buyer_private_key", type=str)
    escrow_pubkey = params.get("escrow_public_key", type=str)

    # Save the uploaded file as before
    try:
        file_path = save_file(uploaded_file, UPLOAD_FOLDER)
    except FileExistsError as e:
        return jsonify({"error": f"File '{e.args[0]}' already exists in the directory."}), 409
    except Exception as e:
        return jsonify({"error": f"Failed to save file: {str(e)}"}), 500

    # Update files_details_dict in storage.py
    files_details_dict[uploaded_file.filename] = {
        "u": u,
        "g": g,
        "v": v,
        "query_size": query_size,
        "number_of_blocks": number_of_blocks,
        "buyer_private_key": buyer_private_key,
        "escrow_public_key": escrow_pubkey,
        "validate_every": validate_every,
        "last_verify": datetime.now()
    }

    return jsonify({"message": "File received and saved", "filename": uploaded_file.filename})


# New API to calculate σ and μ
@api_bp.route("/api/calculate", methods=["GET"])
def calculate_values():
    try:
        filename = request.args.get("filename")
        file_details = files_details_dict[filename]

        if not filename:
            return jsonify({"error": "Filename not provided"}), 400

        file_path = os.path.join(UPLOAD_FOLDER, filename)

        if not os.path.exists(file_path):
            return jsonify({"error": "File not found"}), 404

        is_proved: bool = calculate_sigma_mu_and_prove(filename, file_details["escrow_public_key"])

        # Return the calculated values for σ and μ to the client
        return jsonify({
            "proved": is_proved,  # Convert σ and μ to string if needed for JSON serialization
        })

    except Exception as e:
        return jsonify({"error": f"An error occurred during calculation: {str(e)}"}), 500


@api_bp.route("/api/corrupt", methods=["GET"])
def calculate_values():
    try:
        filename = request.args.get("filename")
        file_details = files_details_dict[filename]

        if not filename:
            return jsonify({"error": "Filename not provided"}), 400

        file_path = os.path.join(UPLOAD_FOLDER, filename)

        if not os.path.exists(file_path):
            return jsonify({"error": "File not found"}), 404

        is_proved: bool = calculate_sigma_mu_and_prove(filename, file_details["escrow_public_key"])

    except Exception as e:
        return jsonify({"error": f"An error occurred during calculation: {str(e)}"}), 500


def calculate_sigma_mu_and_prove(filename: str, escrow_public_key: str) -> bool:
    file_path = os.path.join(UPLOAD_FOLDER, filename)

    client = SolanaGatewayClientProvider()

    generate_queries_response = client.generate_queries(SELLER_PRIVATE_KEY, escrow_public_key)

    if 200 <= generate_queries_response.status_code < 300:
        # Assuming get_queries_response is the response from the GET query
        generate_queries_response_json = generate_queries_response.json()

        # Fetch the 'message' key's value
        message = generate_queries_response_json.get("message")
        print(message)
    else:
        return False

    get_queries_by_escrow_pubkey_response = client.get_queries_by_escrow_pubkey(escrow_public_key)

    if 200 <= get_queries_by_escrow_pubkey_response.status_code < 300:
        # Assuming get_queries_response is the response from the GET query
        get_queries_by_escrow_pubkey_response_json = get_queries_by_escrow_pubkey_response.json()

        # Fetch the 'queries' key's value
        queries = get_queries_by_escrow_pubkey_response_json.get("queries")
    else:
        return False

    # Separate into two lists
    indices = [query[0] for query in queries]
    coefficients = [int(query[1], 16) for query in queries]

    σ = None
    μ: int = 0

    # Calculate the σ and μ
    with open(file_path, "rb") as f:
        block_index: int = 0
        _3d_mac_size = MAC_SIZE * 3

        while True:
            # Read the next block (data + authenticator)
            full_block: bytes = f.read(
                BLOCK_SIZE + _3d_mac_size)  # up-to 1024-byte data, 4-byte * 3 for 3d point authenticator tag
            if not full_block:
                break  # End of file

            m_i: int = int.from_bytes(full_block[:-_3d_mac_size], byteorder='big') % p

            _3d_mac: bytes = full_block[-_3d_mac_size:]
            mac_x_coordinate: bytes = _3d_mac[0:MAC_SIZE]  # Bytes 0 - (MAC_SIZE - 1)
            mac_y_coordinate: bytes = _3d_mac[MAC_SIZE:2 * MAC_SIZE]  # Bytes (MAC_SIZE) - (2 * MAC_SIZE - 1)
            mac_z_coordinate: bytes = _3d_mac[2 * MAC_SIZE:3 * MAC_SIZE]  # Bytes (2 * MAC_SIZE) - (3 * MAC_SIZE - 1)

            mac_x_coordinate_as_int = int.from_bytes(mac_x_coordinate, byteorder='big')
            mac_y_coordinate_as_int = int.from_bytes(mac_y_coordinate, byteorder='big')
            mac_z_coordinate_as_int = int.from_bytes(mac_z_coordinate, byteorder='big')

            σ_i = (bls_opt.FQ(mac_x_coordinate_as_int), bls_opt.FQ(mac_y_coordinate_as_int),
                   bls_opt.FQ(mac_z_coordinate_as_int))

            if block_index in indices:
                v_i: int = coefficients[indices.index(block_index)]
                σ_i_power_v_i = bls_opt.multiply(σ_i, v_i)  # (σ_i)^(v_i)

                if σ is None:
                    σ = σ_i_power_v_i
                else:
                    σ = bls_opt.add(σ, σ_i_power_v_i)

                v_i_multiply_m_i = (v_i * m_i) % p
                μ = (μ + v_i_multiply_m_i) % p

            block_index += 1

    # Send the prove request
    prove_response = client.prove(SELLER_PRIVATE_KEY, escrow_public_key, compress_g1_to_hex(σ), μ.to_bytes(32, 'little').hex())

    if 200 <= prove_response.status_code < 300:
        # Assuming get_queries_response is the response from the GET query
        prove_response_json = prove_response.json()

        # Fetch the 'queries' key's value
        queries = prove_response_json.get("queries")
        return True # TODO: Get from the rust server if it succeeded or failed
    else:
        return False
