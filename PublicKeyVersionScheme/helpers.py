# from typing import Type
# import secrets
from typing import Type

import galois
from galois import FieldArray
# from py_ecc.bls import G2ProofOfPossession as bls_pop
# import py_ecc.bn128 as bls_opr
import py_ecc.bls.hash_to_curve as bls_hash
import py_ecc.optimized_bls12_381 as bls_opt
from hashlib import sha256
# from py_ecc.fields import FQ
from py_ecc.bls.hash_to_curve import hash_to_G1


def curve_field_element_to_bytes(point: tuple, num_bytes: int) -> bytes:    #todo: type for tuple + rename the func and comments
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
    return x_as_int.to_bytes(num_bytes, byteorder='big') + y_as_int.to_bytes(num_bytes, byteorder='big') + b_as_int.to_bytes(num_bytes, byteorder='big')


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

            DST = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_"

            H_i = hash_to_G1(block_index.to_bytes(byteorder='big'), DST, sha256) # H(i)  #todo: maybe not convert to string

            H_i_add_u_m_i = bls_opt.add(H_i, u_m_i) # H(i) * u^(m_i)

            sigma_i = bls_opt.multiply(H_i_add_u_m_i, x)  # [H(i) * u^(m_i)]^x

            sigma_i_in_bytes: bytes = curve_field_element_to_bytes(sigma_i, mac_size)

            blocks_with_authenticators.append((block, sigma_i_in_bytes))

            block_index += 1

    return blocks_with_authenticators


def write_file_by_blocks_with_authenticators(output_file: str, blocks_with_authenticators: list[tuple[bytes, bytes]]) -> None:
    # Write processed blocks with authenticator to a new file
    with open(output_file, "wb") as out_f:
        for block_with_authenticator in blocks_with_authenticators:
            # Write data
            out_f.write(block_with_authenticator[0])
            # Write authenticator
            out_f.write(block_with_authenticator[1])
