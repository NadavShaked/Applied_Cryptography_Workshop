# api.py
import secrets

from flask import Blueprint, request, jsonify

from Common.helpers import write_file_by_blocks_with_authenticators, secure_random_sample
from PublicKeyVersionScheme.helpers import HASH_INDEX_BYTES, DST, p, generate_g, generate_x, generate_v, generate_u, \
    MAC_SIZE, BLOCK_SIZE
from .storage import save_file
from .config import UPLOAD_FOLDER
import py_ecc.bls.hash_to_curve as bls_hash
import py_ecc.optimized_bls12_381 as bls_opt


import os
from hashlib import sha256

# Create a Blueprint for the API in the StorageServer app
api_bp = Blueprint('api', __name__)


# File upload API
@api_bp.route("/api/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    uploaded_file = request.files["file"]

    if uploaded_file.filename == "":
        return jsonify({"error": "Empty file name"}), 400

    try:

        # Save the uploaded file using the save_file function
        file_path = save_file(uploaded_file, UPLOAD_FOLDER)
    except FileExistsError as e:
        # Return 409 if the file already exists
        return jsonify({"error": f"File '{e.args[0]}' already exists in the directory."}), 409
    except Exception as e:
        # Handle other exceptions, like failed save
        return jsonify({"error": f"Failed to save file: {str(e)}"}), 500

    return jsonify({"message": "File received and saved", "filename": uploaded_file.filename})


# New API to calculate σ and μ
@api_bp.route("/api/calculate", methods=["GET"])
def calculate_values():
    try:
        filename = request.args.get("filename")
        if not filename:
            return jsonify({"error": "Filename not provided"}), 400

        file_path = os.path.join(UPLOAD_FOLDER, filename)

        if not os.path.exists(file_path):
            return jsonify({"error": "File not found"}), 404

        x: int = generate_x()  # private key

        g = generate_g()
        v = generate_v(g, x)  # v = g^x in G2

        u = generate_u()  # u in G1

        n: int = 1
        l: int = 1  # TODO: decide what is l - how many challenges the client sends

        # Select random indices
        indices: list[int] = secure_random_sample(n, l)
        coefficients: list[int] = [secrets.randbelow(p) for _ in range(l)]

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

        # Verify pairing
        left_pairing = bls_opt.pairing(g, σ)  # e(σ, g)

        Π_H_i_multiply_v_i = None
        for i, coefficient in zip(indices, coefficients):
            v_i: int = coefficient

            H_i = bls_hash.hash_to_G1(i.to_bytes(HASH_INDEX_BYTES, byteorder='big'), DST, sha256)  # H(i)

            H_i_multiply_v_i = bls_opt.multiply(H_i, v_i)  # H(i)^(v_i)

            if Π_H_i_multiply_v_i is None:
                Π_H_i_multiply_v_i = H_i_multiply_v_i
            else:
                Π_H_i_multiply_v_i = bls_opt.add(Π_H_i_multiply_v_i, H_i_multiply_v_i)

        u_μ = bls_opt.multiply(u, μ)  # u^μ

        multiplication_sum = bls_opt.add(Π_H_i_multiply_v_i, u_μ)

        right_pairing = bls_opt.pairing(v, multiplication_sum)  # e(Π(H(i)^(v_i)) * u^μ, v)

        print(left_pairing.coeffs[0] == right_pairing.coeffs[0] and left_pairing.coeffs[1] == right_pairing.coeffs[1] and
              left_pairing.coeffs[2] == right_pairing.coeffs[2])

        # Return the calculated values for σ and μ to the client
        return jsonify({
            "σ": str(σ),  # Convert σ and μ to string if needed for JSON serialization
            "μ": μ,
            "pairing_check": True
        })

    except Exception as e:
        return jsonify({"error": f"An error occurred during calculation: {str(e)}"}), 500
