# Standard library imports
from typing import Type

# Third-party library imports
import galois
from galois import FieldArray

# Local imports
from PRFs import hmac_prf


def galois_field_element_to_bytes(element: FieldArray, num_bytes: int) -> bytes:
    """
    Convert a Galois Field (GF) element to its byte representation.

    :param element: The Galois Field element to convert.
    :param num_bytes: The desired length of the byte representation.
    :return: A byte representation of the element in big-endian order.
    """
    # Ensure the element is an integer
    element_as_int: int = int(element)

    # Convert the integer to a byte array
    return element_as_int.to_bytes(num_bytes, byteorder='big')


def get_blocks_authenticators_by_file_path(
        file_path: str,
        α: FieldArray,
        block_size: int,
        k: int,
        p: int,
        mac_size: int
) -> list[tuple[bytes, bytes]]:
    blocks_with_authenticators: list[tuple[bytes, bytes]] = []

    # Open the file for reading
    with open(file_path, "rb") as f:
        GF: Type[FieldArray] = galois.GF(p)
        block_index: int = 0

        while True:
            # Read the next block
            block: bytes = f.read(block_size)
            if not block:  # End of file
                break

            f_k_i: FieldArray = GF(hmac_prf(k, block_index) % p)
            block_in_z_p: FieldArray = GF(int.from_bytes(block, byteorder='big') % p)
            σ_i: FieldArray = f_k_i + α * block_in_z_p  # the authenticator for block i

            σ_i_in_bytes: bytes = galois_field_element_to_bytes(σ_i, mac_size)

            blocks_with_authenticators.append((block, σ_i_in_bytes))

            block_index += 1

    return blocks_with_authenticators


def is_prime(n: int) -> bool:
    """Check if a number is prime."""
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True
