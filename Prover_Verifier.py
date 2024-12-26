import galois
import random
from PRFs import hmac_prf
from Helpers import get_blocks_authenticators_by_file_path, write_file_by_blocks_with_authenticators

MAC_SIZE = 4

p = 4294967311

# Create a finite field GF(p)
GF = galois.GF(p)

file_path = "PoR.pdf"  # Replace with your file path
block_size = 1024

k = random.randint(1, 100)  # TODO: Check what is the interval of values
alpha = GF.Random()

# To store blocks with appended authenticator
blocks_with_authenticators = get_blocks_authenticators_by_file_path(file_path, alpha, block_size, k, p)

output_file = "processed_with_gmac.txt"

write_file_by_blocks_with_authenticators(output_file, blocks_with_authenticators)

n = len(blocks_with_authenticators)
l = random.randint(0, n - 1)

# Select random indices
indices = random.sample(range(n), l)
coefficients = [random.randint(1, p) for _ in range(l)]

sigma = GF(0)
mu = GF(0)

# Calculate the Sigma and mu
with open(output_file, "rb") as f:
    block_index = 0
    while True:
        # Read the next block (data + authenticator)
        full_block = f.read(block_size + MAC_SIZE)  # up-to 1024-byte data, 4-byte authenticator tag
        if not full_block:
            break  # End of file

        m_i = GF(int.from_bytes(full_block[:-MAC_SIZE], byteorder='big') % p)
        sigma_i = GF(int.from_bytes(full_block[-MAC_SIZE:], byteorder='big') % p)

        if block_index in indices:
            v_i = GF(coefficients[indices.index(block_index)] % p)
            sigma += v_i * sigma_i
            mu += v_i * m_i

        block_index += 1

# Verify Sigma
sum = GF(0)
for i, coefficient in zip(indices, coefficients):
    v_i = GF(coefficient % p)
    f_k_i = GF(hmac_prf(k, i) % p)
    sum += v_i * f_k_i

maybe_sigma = alpha * mu + sum

print(sigma == maybe_sigma)
