# Standard library imports
from hashlib import sha256

# Third-party library imports
import py_ecc.bls.hash_to_curve as bls_hash
from py_ecc.fields import optimized_bls12_381_FQ
import py_ecc.optimized_bls12_381 as bls_opt

HASH_INDEX_BYTES = 32
DST = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_"


def curve_field_element_to_bytes(
    point: tuple[optimized_bls12_381_FQ, optimized_bls12_381_FQ, optimized_bls12_381_FQ],
    num_bytes: int
) -> bytes:
    """
    Convert a tuple representing a BLS 12_381 Curve point element on an elliptic curve to its byte representation.

    The curve satisfies the equation: y^2 = x^3 + 4.

    :param point: A tuple containing three elements (x, y, z) representing a point on the elliptic curve.
    :param num_bytes: The desired length of the byte representation for each coordinate.
    :return: A concatenated byte representation of (x, y, z) in big-endian order.
    """
    x_as_int: int = int(point[0])
    y_as_int: int = int(point[1])
    z_as_int: int = int(point[2])

    # Convert each integer to a byte array
    return (
        x_as_int.to_bytes(num_bytes, byteorder='big') +
        y_as_int.to_bytes(num_bytes, byteorder='big') +
        z_as_int.to_bytes(num_bytes, byteorder='big')
    )


def get_blocks_authenticators_by_file_path(
        file_path: str,
        block_size: int,
        p: int,
        x: int,
        u: tuple[optimized_bls12_381_FQ, optimized_bls12_381_FQ, optimized_bls12_381_FQ],
        mac_size: int
) -> list[tuple[bytes, bytes]]:
    """
    Process a file into blocks with their corresponding cryptographic authenticators.

    :param file_path: Path to the input file.
    :param block_size: Size of each block in bytes.
    :param p: A prime modulus used in some field arithmetic operations.
    :param x: A scalar value used in multiplication operations.
    :param u: A tuple representing an elliptic curve point (u) used in cryptographic computations.
    :param mac_size: Size of the message authentication code (MAC) in bytes.
    :return: A list of tuples, where each tuple contains a block of bytes and its corresponding authenticator.
    """
    blocks_with_authenticators: list[tuple[bytes, bytes]] = []

    # Open the file for reading
    with open(file_path, "rb") as f:
        block_index: int = 0

        while True:
            # Read the next block
            block: bytes = f.read(block_size)
            if not block:  # End of file
                break

            block_in_z_p: int = int.from_bytes(block, byteorder='big') % p  # m_i

            # Compute u^(m_i)
            u_m_i = bls_opt.multiply(u, block_in_z_p)

            # Compute H(i) where i is the block index
            H_i = bls_hash.hash_to_G1(block_index.to_bytes(HASH_INDEX_BYTES, byteorder='big'), DST, sha256)

            # Compute H(i) * u^(m_i)
            H_i_add_u_m_i = bls_opt.add(H_i, u_m_i)

            # Compute σ_i = [H(i) * u^(m_i)]^x
            σ_i = bls_opt.multiply(H_i_add_u_m_i, x)

            # Convert σ_i to bytes
            σ_i_in_bytes: bytes = curve_field_element_to_bytes(σ_i, mac_size)

            # Append the block and its corresponding authenticator
            blocks_with_authenticators.append((block, σ_i_in_bytes))

            block_index += 1

    return blocks_with_authenticators
