from PRFs import hmac_prf
import galois
from galois import FieldArray
import secrets
import math
from typing import Type


def bytes_needed(number: int) -> int:
    """
    Calculate the smallest number of bytes needed to represent the integer
    where the byte size is a power of two.

    :param number: The integer to analyze.
    :return: The smallest number of bytes (power of 2) needed.
    """
    if number < 0:
        raise ValueError("Number must be non-negative.")
    if number == 0:
        return 1  # Special case: 0 fits in 1 byte

    # Determine the bit length of the number
    bit_length: int = number.bit_length()

    # Find the smallest power of 2 greater than or equal to the bit length
    # Divide by 8 to get bytes, then round up to the next power of 2
    byte_count: int = math.ceil(bit_length / 8)
    power_of_two_bytes: int = 2**math.ceil(math.log2(byte_count))

    return power_of_two_bytes


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
        alpha: FieldArray,
        block_size: int,
        k: int,
        p: int,
        mac_size: int
) -> list[tuple[bytes, bytes]]:
    blocks_with_authenticators: list[tuple[bytes, bytes]] = []

    # Open the file for reading
    with open(file_path, "rb") as f:
        GF: 'Type[FieldArray]' = galois.GF(p)
        block_index: int = 0

        while True:
            # Read the next block
            block: bytes = f.read(block_size)
            if not block:  # End of file
                break

            f_k_i: FieldArray = GF(hmac_prf(k, block_index) % p)
            block_in_z_p: FieldArray = GF(int.from_bytes(block, byteorder='big') % p)
            sigma_i: FieldArray = f_k_i + alpha * block_in_z_p  # the authenticator for block i

            sigma_i_in_bytes: bytes = galois_field_element_to_bytes(sigma_i, mac_size)

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


def secure_random_sample(maxIndex: int, number_of_indices: int) -> list[int]:
    if number_of_indices > maxIndex:
        raise ValueError("Sample size l cannot be larger than the range n.")

    # Create a list of indices
    indices: list[int] = list(range(maxIndex))

    # Shuffle the list using cryptographic randomness
    for i in range(len(indices) - 1, 0, -1):
        j: int = secrets.randbelow(i + 1)  # Get a secure random index
        indices[i], indices[j] = indices[j], indices[i]

    # Return the first `l` items
    return indices[:number_of_indices]


def is_prime(n: int) -> bool:
    """Check if a number is prime."""
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True
