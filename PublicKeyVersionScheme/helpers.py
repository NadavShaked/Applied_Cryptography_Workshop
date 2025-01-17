# Standard library imports
from hashlib import sha256

# Third-party library imports
import py_ecc.bls.hash_to_curve as bls_hash
import py_ecc.optimized_bls12_381 as bls_opt

HASH_INDEX_BYTES = 32
DST = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_"


def curve_field_element_to_bytes(point: tuple,
                                 num_bytes: int) -> bytes:  # todo: type for tuple + rename the func and comments
    """
    The curve satisfy the equation y^2 = x^3 + b
    Convert a Galois Field (GF) element to its byte representation.

    :param point: The Optimized bn128 FQ.
    :param num_bytes: The desired length of the byte representation.
    :return: A byte representation of the element in big-endian order.
    """
    x_as_int: int = int(point[0])
    y_as_int: int = int(point[1])
    b_as_int: int = int(point[2])

    # Convert the integer to a byte array
    return x_as_int.to_bytes(num_bytes, byteorder='big') + y_as_int.to_bytes(num_bytes,
                                                                             byteorder='big') + b_as_int.to_bytes(
        num_bytes, byteorder='big')


def get_blocks_authenticators_by_file_path(
        file_path: str,
        block_size: int,
        p,
        x,
        u,
        mac_size: int
) -> list[tuple[bytes, bytes]]:
    blocks_with_authenticators: list[tuple[bytes, bytes]] = []

    # Open the file for reading
    with open(file_path, "rb") as f:
        block_index: int = 0

        while True:
            # Read the next block
            block: bytes = f.read(block_size)
            if not block:  # End of file
                break

            block_in_z_p: int = int.from_bytes(block, byteorder='big') % p

            u_m_i = bls_opt.multiply(u, block_in_z_p)

            H_i = bls_hash.hash_to_G1(block_index.to_bytes(HASH_INDEX_BYTES, byteorder='big'), DST, sha256)  # H(i)

            H_i_add_u_m_i = bls_opt.add(H_i, u_m_i)  # H(i) * u^(m_i)

            sigma_i = bls_opt.multiply(H_i_add_u_m_i, x)  # [H(i) * u^(m_i)]^x

            sigma_i_in_bytes: bytes = curve_field_element_to_bytes(sigma_i, mac_size)

            blocks_with_authenticators.append((block, sigma_i_in_bytes))

            block_index += 1

    return blocks_with_authenticators
