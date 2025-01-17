# Standard library imports
import math
import secrets


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


def secure_random_sample(maxIndex: int, number_of_indices: int) -> list[int]:   # todo: validate that the same index doesnt return twice
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


def write_file_by_blocks_with_authenticators(output_file: str, blocks_with_authenticators: list[tuple[bytes, bytes]]) -> None:
    # Write processed blocks with authenticator to a new file
    with open(output_file, "wb") as out_f:
        for block_with_authenticator in blocks_with_authenticators:
            # Write data
            out_f.write(block_with_authenticator[0])
            # Write authenticator
            out_f.write(block_with_authenticator[1])