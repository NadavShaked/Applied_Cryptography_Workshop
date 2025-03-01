from Common.Providers.solanaApiGatewayProvider import SolanaGatewayClientProvider
from PublicKeyVersionScheme.helpers import p, MAC_SIZE, BLOCK_SIZE, compress_g1_to_hex, MAC_SIZE_3D
from .config import UPLOAD_FOLDER
import py_ecc.optimized_bls12_381 as bls_opt
import os
from .constants import SELLER_PRIVATE_KEY


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


def get_escrow_data(escrow_public_key: str):
    """
    Fetches escrow data for the provided public key from the Solana gateway client.

    This function:
    - Initializes the Solana client.
    - Sends a request to get escrow data associated with the provided public key.
    - Returns the JSON response from the Solana gateway if the request is successful.

    Args:
        escrow_public_key (str): The public key of the escrow account.

    Returns:
        dict: The JSON response from the Solana gateway containing the escrow data.
    """
    try:
        # Initialize Solana client and get escrow data
        client = SolanaGatewayClientProvider()
        print(f"Fetching escrow data for escrow public key: {escrow_public_key} using the Solana client")

        # Send the request to fetch escrow data
        get_escrow_data_response = client.get_escrow_data(escrow_public_key)

        # Check if the response from the Solana client is successful
        if 200 <= get_escrow_data_response.status_code < 300:
            print("Successfully fetched escrow data.")
            return get_escrow_data_response.json()
        else:
            print(f"Failed to fetch escrow data, status code: {get_escrow_data_response.status_code}")
            return None

    except Exception as e:
        print(f"Exception occurred while fetching escrow data: {str(e)}")
        return None


def request_funds(escrow_public_key: str) -> bool:
    """
    Requests funds from the Solana gateway for a specified escrow public key.

    This function:
    - Sends a request to the Solana gateway to request funds from the escrow account.
    - Logs the response message for debugging purposes.
    - Returns True if the request is successful, or False if it fails.

    Args:
        escrow_public_key (str): The public key of the escrow account to request funds from.

    Returns:
        bool: True if the fund request was successful, False otherwise.
    """
    try:
        # Initialize Solana client and send request for funds
        client = SolanaGatewayClientProvider()
        print(f"Requesting funds from escrow public key: {escrow_public_key} using the Solana client")

        # Send the request to the Solana client for funds
        request_funds_response = client.request_funds(SELLER_PRIVATE_KEY, escrow_public_key)

        # Check if the response from the Solana client is successful (status code 2xx)
        if 200 <= request_funds_response.status_code < 300:
            request_funds_response_json = request_funds_response.json()
            message = request_funds_response_json.get("message")
            print(f"Fund request successful. Message: {message}")
            return True
        else:
            print(f"Request Fund Failed. Status Code: {request_funds_response.status_code}")
            return False

    except Exception as e:
        print(f"Exception occurred while requesting funds: {str(e)}")
        return False


def end_subscription_by_seller(escrow_public_key: str) -> bool:
    """
    Ends a subscription by the seller for the specified escrow public key.

    This function:
    - Sends a request to the Solana gateway to end the subscription for the escrow account.
    - Logs the response message for debugging purposes.
    - Returns True if the request is successful, or False if it fails.

    Args:
        escrow_public_key (str): The public key of the escrow account for which to end the subscription.

    Returns:
        bool: True if the subscription was successfully ended, False otherwise.
    """
    try:
        # Initialize Solana client and send request to end subscription
        client = SolanaGatewayClientProvider()
        print(f"Ending subscription for escrow public key: {escrow_public_key} using the Solana client")

        # Send the request to the Solana client to end the subscription
        request_funds_response = client.end_subscription_by_seller(SELLER_PRIVATE_KEY, escrow_public_key)

        # Check if the response from the Solana client is successful (status code 2xx)
        if 200 <= request_funds_response.status_code < 300:
            request_funds_response_json = request_funds_response.json()
            message = request_funds_response_json.get("message")
            print(f"Subscription ended successfully. Message: {message}")
            return True
        else:
            print(f"End Subscription Failed. Status Code: {request_funds_response.status_code}")
            return False

    except Exception as e:
        print(f"Exception occurred while ending subscription: {str(e)}")
        return False


def delete_file_from_storage_server(file_name: str):
    """
    Deletes a file from the storage server.

    This function:
    - Constructs the full file path based on the provided filename.
    - Checks if the file exists in the storage directory.
    - Deletes the file if it exists and logs the success message.
    - Logs an error message if the file does not exist.

    Args:
        file_name (str): The name of the file to be deleted.

    Returns:
        None
    """
    file_path = os.path.join(UPLOAD_FOLDER, file_name)
    print(f"Attempting to delete file: {file_path}")

    # Check if the file exists at the specified path
    if os.path.exists(file_path):
        try:
            # Remove the file
            os.remove(file_path)
            print(f"File {file_path} deleted successfully.")
        except Exception as e:
            print(f"Error deleting file {file_path}: {str(e)}")
    else:
        print(f"The file {file_path} does not exist.")
