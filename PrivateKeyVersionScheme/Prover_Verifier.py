import galois
from galois import FieldArray
import secrets
from Common.helpers import bytes_needed, secure_random_sample
from PRFs import hmac_prf
from helpers import get_blocks_authenticators_by_file_path, write_file_by_blocks_with_authenticators
from Common.primes import PRIME_NUMBER_16_BYTES

p: int = PRIME_NUMBER_16_BYTES
MAC_SIZE: int = bytes_needed(p)

# Create a finite field GF(p)
GF = galois.GF(p)

file_name: str = "PoR.pdf"
file_path: str = "../Files/" + file_name  # Replace with your file path
BLOCK_SIZE: int = 1024

k: int = secrets.randbelow(100)  # TODO: Check what is the interval of values
alpha: FieldArray = GF(secrets.randbelow(p))

# To store blocks with appended authenticator
blocks_with_authenticators: list[tuple[bytes, bytes]] = get_blocks_authenticators_by_file_path(file_path, alpha, BLOCK_SIZE, k, p, MAC_SIZE)

output_file: str = "./EncodedFiles/" + file_name + ".encoded.txt"

write_file_by_blocks_with_authenticators(output_file, blocks_with_authenticators)

n: int = len(blocks_with_authenticators)
l: int = secrets.randbelow(n)   # todo: decide what is l - how many challenges the client sends

# Select random indices
indices: list[int] = secure_random_sample(n, l) # TODO: validate that random as requested
coefficients: list[int] = [secrets.randbelow(p) for _ in range(l)]

sigma: FieldArray = GF(0)
mu: FieldArray = GF(0)

# Calculate the Sigma and mu
with open(output_file, "rb") as f:
    block_index: int = 0
    while True:
        # Read the next block (data + authenticator)
        full_block: bytes = f.read(BLOCK_SIZE + MAC_SIZE)  # up-to 1024-byte data, 4-byte authenticator tag
        if not full_block:
            break  # End of file

        m_i: FieldArray = GF(int.from_bytes(full_block[:-MAC_SIZE], byteorder='big') % p)
        sigma_i: FieldArray = GF(int.from_bytes(full_block[-MAC_SIZE:], byteorder='big') % p)

        if block_index in indices:
            v_i: FieldArray = GF(coefficients[indices.index(block_index)] % p)
            sigma += v_i * sigma_i
            mu += v_i * m_i

        block_index += 1

# Verify Sigma
sum: FieldArray = GF(0)
for i, coefficient in zip(indices, coefficients):
    v_i: FieldArray = GF(coefficient % p)
    f_k_i: FieldArray = GF(hmac_prf(k, i) % p)
    sum += v_i * f_k_i

maybe_sigma: FieldArray = alpha * mu + sum

print(sigma == maybe_sigma)
