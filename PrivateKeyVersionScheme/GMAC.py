# Standard library imports
import os

# Third-party library imports
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


NONCE_SIZE = 12
GMAC_SIZE = 16


def convert_index_to_bytes(index: int, max_bytes_size: int = 16):
    """
    Converts a index into bytes with a specified maximum byte size.

    Args:
    - index (int): The index to convert.
    - max_bytes_size (int, optional): The maximum byte size for the index. Default is 16 bytes.

    Returns:
    - bytes: The index as bytes, fitting within the specified byte size.
    """
    index_in_bytes = index.to_bytes(max_bytes_size, byteorder='big') # TODO: Check what is the maximum blocks, to set the maximum bytes size, 16

    return index_in_bytes


def process_file_with_gmac(file_path, block_size=1024):
    # Generate a random 256-bit (32-byte) AES key
    key = os.urandom(32)

    # Open the file for reading
    with open(file_path, "rb") as f:
        blocks_with_mac = []  # To store blocks with appended GMAC
        block_number = 0

        while True:
            # Read the next block
            block = f.read(block_size)
            if not block:  # End of file
                break

            # Generate a random nonce (12 bytes recommended for AES-GCM)
            nonce = os.urandom(NONCE_SIZE)

            # Initialize AES-GCM
            aesgcm = AESGCM(key)

            block_number_bytes = convert_index_to_bytes(block_number)
            block_with_number = block + block_number_bytes

            # Generate GMAC (encrypt empty plaintext with block as AAD)
            gmac_tag = aesgcm.encrypt(nonce, b"", block_with_number) #TODO: validate that the append index is correct here

            # Append GMAC to the block
            block_with_mac = block + gmac_tag
            blocks_with_mac.append((block_number, nonce, block_with_mac))

            # Increment block number
            block_number += 1

    return blocks_with_mac, key  # Return processed blocks and the key for verification


def write_blocks_to_file(blocks_with_mac, output_file):
    # Write processed blocks with GMAC to a new file
    with open(output_file, "wb") as out_f:
        for _, nonce, block_with_mac in blocks_with_mac:
            # Write nonce (12 bytes), block, and its GMAC
            out_f.write(nonce + block_with_mac) #TODO: What does it mean that we append the nonce at the beginning of the block


def validate_block_with_gmac(block: bytes, block_index: int, key):
    # block (nonce + data + GMAC)
    # Extract the nonce (first 12 bytes)
    nonce = block[:12]

    # Extract the data (everything in between)
    data = block[12:-16]

    # Extract the GMAC (last 16 bytes)
    gmac_tag = block[-16:]

    index_in_bytes = convert_index_to_bytes(block_index)
    data_with_index = data + index_in_bytes

    # Recompute GMAC for the block
    aesgcm = AESGCM(key)
    try:
        # Try to verify the GMAC by decrypting (recompute GMAC)
        aesgcm.decrypt(nonce, gmac_tag, data_with_index)
        return True
    except Exception as e:
        return False


def validate_file_with_gmac(file_path, key, block_size=1024):
    with open(file_path, "rb") as f:
        block_index = 0
        while True:
            # Read the next block (nonce + data + GMAC)
            full_block = f.read(NONCE_SIZE + block_size + GMAC_SIZE)  # 12-byte nonce (IV), up-to 1024-byte data, 16-byte GMAC tag
            if not full_block:
                break  # End of file
            isValid = validate_block_with_gmac(full_block, block_index, key)

            if isValid:
                print(f"Block {block_index} is authenticated.")
            else:
                print(f"Block {block_index} authentication failed")
                break

            block_index += 1


# Example usage
file_path = "../PoR.pdf"  # Replace with your file path
output_file = "../processed_with_gmac.txt"
block_size = 1024

blocks_with_mac, key = process_file_with_gmac(file_path, block_size)
write_blocks_to_file(blocks_with_mac, output_file)

print(f"Processed file saved to {output_file}")
print(f"AES Key (hex): {key.hex()}")

# Example usage
validate_file_with_gmac(output_file, key)

print("yay")
