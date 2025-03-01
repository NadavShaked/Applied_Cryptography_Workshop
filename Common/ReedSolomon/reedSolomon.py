import reedsolo


def encode_file_with_rs(filepath, output_filepath, chunk_size=245):
    """Reads a file, applies Reed-Solomon encoding in chunks, and saves the encoded file."""
    rs = reedsolo.RSCodec(10, nsize=255)  # Full mode

    with open(filepath, "rb") as file, open(output_filepath, "wb") as encoded_file:
        while chunk := file.read(chunk_size):
            encoded_chunk = rs.encode(chunk)
            encoded_file.write(encoded_chunk)

    return output_filepath


def corrupt_file(input_filepath, output_filepath, block_size=1024):
    """Corrupts the file by flipping the first byte of every 1024-byte block."""
    with open(input_filepath, "rb") as file:
        data = bytearray(file.read())

    for i in range(0, len(data), block_size):
        data[i] ^= 0x80  # Flip the first byte

    with open(output_filepath, "wb") as corrupted_file:
        corrupted_file.write(data)

    return output_filepath


def decode_file_with_rs(encoded_filepath, output_filepath, chunk_size=255):
    """Reads a Reed-Solomon encoded file, decodes it in chunks, and saves the original file."""
    rs = reedsolo.RSCodec(10, nsize=255)  # Full mode

    with open(encoded_filepath, "rb") as encoded_file, open(output_filepath, "wb") as decoded_file:
        while chunk := encoded_file.read(chunk_size):
            decoded_chunk = rs.decode(chunk)
            decoded_file.write(decoded_chunk[0])  # Write decoded chunk

    return output_filepath
