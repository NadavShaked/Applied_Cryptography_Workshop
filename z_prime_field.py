from typing import Union
from PrivateKeyVersionScheme.helpers import is_prime
import secrets


class ZPrimeField:
    def __init__(self, prime: int = None, value: int = 0):
        if prime is None:
            raise ValueError("Prime cannot be None")
        if not isinstance(prime, int) or prime <= 1:
            raise ValueError(f"{prime} is not a valid prime number. It must be a positive integer greater than 1.")
        if not is_prime(prime):
            raise ValueError(f"{prime} is not a prime number.")

        self.value = value % prime
        self.prime = prime

    # Addition (+) operator
    def __add__(self, other: Union['ZPrimeField', int]) -> 'ZPrimeField':
        if isinstance(other, ZPrimeField):
            return ZPrimeField((self.value + other.value) % self.prime, self.prime)
        elif isinstance(other, int):
            return ZPrimeField((self.value + other) % self.prime, self.prime)
        return NotImplemented

    # Subtraction (-) operator
    def __sub__(self, other: Union['ZPrimeField', int]) -> 'ZPrimeField':
        if isinstance(other, ZPrimeField):
            return ZPrimeField((self.value - other.value) % self.prime, self.prime)
        elif isinstance(other, int):
            return ZPrimeField((self.value - other) % self.prime, self.prime)
        return NotImplemented

    # Multiplication (*) operator
    def __mul__(self, other: Union['ZPrimeField', int]) -> 'ZPrimeField':
        if isinstance(other, ZPrimeField):
            return ZPrimeField((self.value * other.value) % self.prime, self.prime)
        elif isinstance(other, int):
            return ZPrimeField((self.value * other) % self.prime, self.prime)
        return NotImplemented

    # Exponentiation (**) operator
    def __pow__(self, other: Union['ZPrimeField', int]) -> 'ZPrimeField':
        if isinstance(other, ZPrimeField):
            return ZPrimeField(pow(self.value, other.value, self.prime), self.prime)
        elif isinstance(other, int):
            return ZPrimeField(pow(self.value, other, self.prime), self.prime)
        return NotImplemented

    # Representation method to display the object
    def __repr__(self):
        return f"ZPrime({self.value}, {self.prime})"

    def generate_random(self) -> 'ZPrimeField':
        """Generate a random number in the prime field."""
        # Generate a random integer in the range [0, prime-1]
        random_value = secrets.randbelow(self.prime)
        return ZPrimeField(prime=self.prime, value=random_value)

    @staticmethod
    def generate_random_number_in_prime_field(prime: int) -> 'ZPrimeField':
        """Generate a random number in the prime field."""
        if not is_prime(prime):
            raise ValueError(f"{prime} is not a prime number.")
        # Generate a random integer in the range [0, prime-1]
        random_value = secrets.randbelow(prime)
        return ZPrimeField(prime=prime, value=random_value)