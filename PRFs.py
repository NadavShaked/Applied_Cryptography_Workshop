import hmac
import hashlib


def hmac_prf(k, index):
    """
    Pseudo-Random Function using HMAC.
    :param k: Random key (bytes)
    :param index: Input value (integer)
    :return: Pseudo-random output (hexadecimal)
    """
    # Convert k to bytes (e.g., 4-byte big-endian format)
    k_in_bytes = k.to_bytes(4, byteorder='big')
    # Convert index to bytes (e.g., 4-byte big-endian format)
    index_in_bytes = index.to_bytes(4, byteorder='big')

    # Compute HMAC-based PRF
    hex_output = hmac.new(k_in_bytes, index_in_bytes, hashlib.sha256).hexdigest()

    # Convert the hex string to an integer
    return int(hex_output, 16)  # Convert from hexadecimal to integer