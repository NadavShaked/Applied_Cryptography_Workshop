import reedsolo


def encode_file_with_rs(filepath: str, output_filepath: str, chunk_size: int = 245) -> str:
    """
    Reads a file, applies Reed-Solomon encoding in chunks, and saves the encoded file.

    :param filepath: The path to the file to encode.
    :param output_filepath: The path where the encoded file will be saved.
    :param chunk_size: The size of each chunk to read from the file (default is 245).
    :return: The path to the encoded file.
    """
    # Initialize the Reed-Solomon codec with 10 error correction symbols and block size 255
    rs = reedsolo.RSCodec(10, nsize=255)

    with open(filepath, "rb") as file, open(output_filepath, "wb") as encoded_file:
        while chunk := file.read(chunk_size):
            encoded_chunk = rs.encode(chunk)
            encoded_file.write(encoded_chunk)  # Write encoded chunk

    return output_filepath


def decode_file_with_rs(encoded_filepath: str, output_filepath: str, chunk_size: int =255) -> str:
    """
    Reads a Reed-Solomon encoded file, decodes it in chunks, and saves the original file.

    :param encoded_filepath: The path to the encoded file to decode.
    :param output_filepath: The path where the decoded file will be saved.
    :param chunk_size: The size of each chunk to read from the encoded file (default is 255).
    :return: The path to the decoded file.
    """
    # Initialize the Reed-Solomon codec with 10 error correction symbols and block size 255
    rs = reedsolo.RSCodec(10, nsize=255)

    with open(encoded_filepath, "rb") as encoded_file, open(output_filepath, "wb") as decoded_file:
        while chunk := encoded_file.read(chunk_size):
            decoded_chunk = rs.decode(chunk)
            decoded_file.write(decoded_chunk[0])  # Write decoded chunk

    return output_filepath


def corrupt_file(input_filepath: str, output_filepath: str, block_size: int = 1024) -> str:
    """
    Corrupts the file by flipping the first byte of every block of a specified size.

    :param input_filepath: The path to the file to corrupt.
    :param output_filepath: The path where the corrupted file will be saved.
    :param block_size: The size of the blocks in which corruption occurs (default is 1024 bytes).
    :return: The path to the corrupted file.
    """
    with open(input_filepath, "rb") as file:
        data: bytearray = bytearray(file.read())

    # Iterate through the file in blocks of the specified size
    for i in range(0, len(data), block_size):
        # Flip the first byte of each block (XOR with 0xFF)
        data[i] ^= 0xFF

    with open(output_filepath, "wb") as corrupted_file:
        corrupted_file.write(data)

    return output_filepath
