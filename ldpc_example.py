import numpy as np
import os


# Generate a random sparse parity-check matrix H
def generate_parity_check_matrix(n, k, density=0.1):
    m = n - k  # Number of parity bits
    H = np.random.choice([0, 1], size=(m, n), p=[1 - density, density])
    return H


# Generate a generator matrix G from H
def generate_generator_matrix(H, n, k):
    # Append identity matrix to H to create G
    m = H.shape[0]
    G = np.concatenate((np.eye(k, dtype=int), H.T[:k]), axis=1)
    return G


# Encode a block of data
def ldpc_encode(data_block, G):
    # Ensure the data block length matches G's rows
    if len(data_block) != G.shape[0]:
        raise ValueError(f"Data block length {len(data_block)} does not match generator matrix input size {G.shape[0]}.")
    codeword = np.dot(data_block, G) % 2
    return codeword


# Decode a received block using belief propagation
def ldpc_decode(received_block, H, max_iterations=50):
    n = H.shape[1]  # Codeword length
    m = H.shape[0]  # Number of parity-check equations

    if len(received_block) != n:
        raise ValueError(f"Received block length {len(received_block)} does not match codeword length {n}.")

    syndromes = np.dot(H, received_block.T) % 2

    if np.all(syndromes == 0):
        return received_block[:n-m]  # Return the data part (first k bits)

    # Initialize belief propagation
    for _ in range(max_iterations):
        for i in range(m):
            parity_sum = np.dot(H[i], received_block) % 2
            if parity_sum != 0:
                for j in range(n):
                    if H[i, j] == 1:
                        received_block[j] = (received_block[j] + parity_sum) % 2

        syndromes = np.dot(H, received_block.T) % 2
        if np.all(syndromes == 0):
            return received_block[:n-m]

    raise ValueError("Decoding failed after max iterations")


# Process a single block of data
def process_block(block, H, G, operation="encode", noise_level=0.1):
    k = G.shape[0]  # Data length
    n = G.shape[1]  # Codeword length

    # Ensure block size matches k
    if len(block) > k:
        block = block[:k]  # Truncate
    elif len(block) < k:
        block = np.pad(block, (0, k - len(block)), 'constant')  # Pad

    if operation == "encode":
        return ldpc_encode(block, G)
    elif operation == "decode":
        # Add noise to simulate channel errors
        noisy_block = (block + np.random.choice([0, 1], size=len(block), p=[1-noise_level, noise_level])) % 2
        return ldpc_decode(noisy_block, H)
    else:
        raise ValueError("Invalid operation: choose 'encode' or 'decode'")


# Process a file block-by-block
def process_file(file_path, block_size, H, G, operation="encode", output_path=None):
    k = G.shape[0]  # Data length
    n = G.shape[1]  # Codeword length

    if output_path is None:
        output_path = file_path + (".encoded" if operation == "encode" else ".decoded")

    with open(file_path, "rb") as f_in, open(output_path, "wb") as f_out:
        while chunk := f_in.read(block_size // 8):
            # Convert to binary
            block = np.unpackbits(np.frombuffer(chunk, dtype=np.uint8))
            if operation == "encode":
                if len(block) < k:
                    block = np.pad(block, (0, k - len(block)), 'constant')  # Pad block
                encoded_block = process_block(block, H, G, operation="encode")
                f_out.write(np.packbits(encoded_block))
            elif operation == "decode":
                if len(block) < n:
                    block = np.pad(block, (0, n - len(block)), 'constant')  # Pad block
                decoded_block = process_block(block, H, G, operation="decode")
                decoded_chunk = np.packbits(decoded_block[:block_size // 8])
                f_out.write(decoded_chunk)

    return output_path


# Example Usage
if __name__ == "__main__":
    n = 32  # Codeword length
    k = 16  # Data length
    block_size = k  # Block size in bits

    # Generate matrices
    H = generate_parity_check_matrix(n, k)
    G = generate_generator_matrix(H, n, k)

    # File paths
    input_file = "example.txt"  # Replace with your file
    encoded_file = process_file(input_file, block_size, H, G, operation="encode")
    decoded_file = process_file(encoded_file, block_size, H, G, operation="decode")

    print(f"File encoded to: {encoded_file}")
    print(f"File decoded to: {decoded_file}")
