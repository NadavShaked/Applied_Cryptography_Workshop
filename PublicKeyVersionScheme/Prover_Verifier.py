import galois
from galois import FieldArray
import secrets

from Common.helpers import secure_random_sample, bytes_needed
from helpers import get_blocks_authenticators_by_file_path, write_file_by_blocks_with_authenticators
from Common.primes import PRIME_NUMBER_16_BYTES
from py_ecc.bls import G2ProofOfPossession as bls_pop
import py_ecc.optimized_bls12_381 as bls_opt
from hashlib import sha256
import py_ecc.bls.hash_to_curve as bls_hash
from py_ecc.bls12_381.bls12_381_curve import curve_order
from typing import Type


p: int = 2**255 - 19    # Todo: verify that the prime is correct
MAC_SIZE: int = 128 # TODO: verify max int in G group

file_name: str = "specific_8_byte_file.txt" # "PoR.pdf"
file_path: str = "../Files/" + file_name  # Replace with your file path
BLOCK_SIZE: int = 1024

x: int = secrets.randbelow(p)    # private key

rand_value_1 = secrets.randbelow(p)
g = bls_opt.multiply(bls_opt.G2, rand_value_1)
v = bls_opt.multiply(g, x)  # v = g^x in G

rand_value_2 = secrets.randbelow(p)
u = bls_opt.multiply(bls_opt.G1, rand_value_2)  # u in G

# To store blocks with appended authenticator
blocks_with_authenticators: list[tuple[bytes, bytes]] = get_blocks_authenticators_by_file_path(file_path, BLOCK_SIZE, p, x, u, MAC_SIZE)

output_file: str = "./EncodedFiles/" + file_name + ".encoded.txt"

write_file_by_blocks_with_authenticators(output_file, blocks_with_authenticators)

n: int = len(blocks_with_authenticators)
l: int = 1  #secrets.randbelow(n)   # todo: decide what is l - how many challenges the client sends

# Select random indices
indices: list[int] = secure_random_sample(n, l) # TODO: validate that random as requested
coefficients: list[int] = [secrets.randbelow(p) for _ in range(l)]

sigma = None
mu: int = 0

# Calculate the Sigma and mu
with open(output_file, "rb") as f:
    block_index: int = 0
    _3d_mac_size = MAC_SIZE * 3

    while True:
        # Read the next block (data + authenticator)
        full_block: bytes = f.read(BLOCK_SIZE + _3d_mac_size)  # up-to 1024-byte data, 4-byte * 3 for 3d point authenticator tag
        if not full_block:
            break  # End of file

        m_i: int = int.from_bytes(full_block[:-_3d_mac_size], byteorder='big') % p

        _3d_mac: bytes = full_block[-_3d_mac_size:]
        mac_x_coordinate: bytes = _3d_mac[0:MAC_SIZE]  # Bytes 0 - (MAC_SIZE - 1)
        mac_y_coordinate: bytes = _3d_mac[MAC_SIZE:2*MAC_SIZE]  # Bytes (MAC_SIZE) - (2 * MAC_SIZE - 1)
        mac_b_coordinate: bytes = _3d_mac[2*MAC_SIZE:3*MAC_SIZE]  # Bytes (2 * MAC_SIZE) - (3 * MAC_SIZE - 1)

        mac_x_coordinate_as_int = int.from_bytes(mac_x_coordinate, byteorder='big')
        mac_y_coordinate_as_int = int.from_bytes(mac_y_coordinate, byteorder='big')
        mac_b_coordinate_as_int = int.from_bytes(mac_b_coordinate, byteorder='big')

        sigma_i = (bls_opt.FQ(mac_x_coordinate_as_int), bls_opt.FQ(mac_y_coordinate_as_int), bls_opt.FQ(mac_b_coordinate_as_int))

        if block_index in indices:
            v_i: int = coefficients[indices.index(block_index)]
            sigma_i_power_v_i = bls_opt.multiply(sigma_i, v_i)   # (sigma_i)^(v_i)

            if sigma is None:
                sigma = sigma_i_power_v_i
            else:
                sigma = bls_opt.add(sigma, sigma_i_power_v_i)

            v_i_multiply_m_i = (v_i * m_i) % p
            mu = (mu + v_i_multiply_m_i) % p

        block_index += 1


# Verify Sigma
pair1 = bls_opt.pairing(g, sigma)   # e(sigma, g)

py_H_i_multiply_v_i = None
for i, coefficient in zip(indices, coefficients):
    v_i: int = coefficient

    DST = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_"

    H_i = bls_hash.hash_to_G1(i.to_bytes(byteorder='big'), DST, sha256)  # H(i)  #todo: maybe not convert to string

    H_i_multiply_v_i = bls_opt.multiply(H_i, v_i)  # H(i)^(v_i)

    if py_H_i_multiply_v_i is None:
        py_H_i_multiply_v_i = H_i_multiply_v_i
    else:
        py_H_i_multiply_v_i = bls_opt.add(py_H_i_multiply_v_i, H_i_multiply_v_i)

u_mu = bls_opt.multiply(u, mu)  # u^mu

all = bls_opt.add(py_H_i_multiply_v_i, u_mu)

pair2 = bls_opt.pairing(v, all)   # e(PY(H(i)^(v_i)) * u^mu, v)

trtrtr = 3