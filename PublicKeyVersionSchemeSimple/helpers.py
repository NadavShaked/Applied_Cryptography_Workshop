# Local imports
from PrivateKeyVersionScheme.PRFs import hmac_prf

p = 101


def add(a, b):
    """Perform addition in Z_p."""
    return (a + b) % p


def multiply(a, n):
    """Perform scalar multiplication in Z_p."""
    return (a * n) % p


def pairing(a, b):
    """Perform pairing operation in Z_p."""
    return (a * b) % p


def hash(index):
    return hmac_prf(3, index) % p


def curve_field_element_to_bytes(point: int, num_bytes: int) -> bytes:
    x_as_int: int = int(point)
    y_as_int: int = int(point)
    b_as_int: int = int(point)

    # Convert the integer to a byte array
    return x_as_int.to_bytes(num_bytes, byteorder='big') + y_as_int.to_bytes(num_bytes, byteorder='big') + b_as_int.to_bytes(num_bytes, byteorder='big')


def get_blocks_authenticators_by_file_path(
        file_path: str,
        block_size: int,
        p: int,
        x: int,
        u: int,
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

            u_m_i = multiply(u, block_in_z_p)

            H_i = hash(block_index)  # H(i)

            H_i_add_u_m_i = add(H_i, u_m_i)  # H(i) * u^(m_i)

            σ_i = multiply(H_i_add_u_m_i, x)  # [H(i) * u^(m_i)]^x

            σ_i_in_bytes: bytes = curve_field_element_to_bytes(σ_i, mac_size)

            blocks_with_authenticators.append((block, σ_i_in_bytes))

            block_index += 1

    return blocks_with_authenticators
