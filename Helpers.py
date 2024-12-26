from PRFs import hmac_prf
import galois
import struct


def gf_to_bytes_struct(gf_element):
    """
    Convert a Galois Field element to bytes using struct.
    :param gf_element: Element from GF(p)
    :return: Byte representation of the element
    """
    # Convert GF element to integer
    gf_int = int(gf_element)

    # Use struct to convert integer to bytes
    # 'I' format: unsigned int (4 bytes)
    return struct.pack('>I', gf_int)


def get_blocks_authenticators_by_file_path(
        file_path: str,
        alpha,
        block_size: int = 1024,
        k: int = 0,
        p: int = 4294967311
) -> list[tuple[bytes, bytes]]:
    blocks_with_authenticators = []

    # Open the file for reading
    with open(file_path, "rb") as f:
        GF = galois.GF(p)
        block_index = 0

        while True:
            # Read the next block
            block = f.read(block_size)
            if not block:  # End of file
                break

            f_k_i = GF(hmac_prf(k, block_index) % p)
            block_as_int = GF(int.from_bytes(block, byteorder='big') % p)
            sigma_i = f_k_i + alpha * block_as_int  # the authenticator for block i

            sigma_i_in_bytes = gf_to_bytes_struct(sigma_i)

            blocks_with_authenticators.append((block, sigma_i_in_bytes))

            block_index += 1

    return blocks_with_authenticators


def write_file_by_blocks_with_authenticators(output_file: str, blocks_with_authenticators: list[tuple[bytes, bytes]]):
    # Write processed blocks with authenticator to a new file
    with open(output_file, "wb") as out_f:
        for block_with_authenticator in blocks_with_authenticators:
            # Write data
            out_f.write(block_with_authenticator[0])
            # Write authenticator
            out_f.write(block_with_authenticator[1])
