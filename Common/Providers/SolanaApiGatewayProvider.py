import json

import requests


SOLANA_GATEWAY_BASE_URL = "http://127.0.0.1:3030"


class SolanaGatewayClientProvider:
    def __init__(self):
        """
        Initialize the ClientProvider with the base URL.
        """
        self.headers = {"Content-Type": "application/json"}

    def _send_request(self, endpoint, method="POST", payload=None):
        """
        Helper method to send HTTP requests.

        Args:
            endpoint (str): The API endpoint to hit (relative to base_url).
            method (str): The HTTP method to use (GET, POST, etc.).
            payload (dict): The data to send with the request (for POST/PUT requests).

        Returns:
            response (requests.Response): The response object from the server.
        """
        url = f"{SOLANA_GATEWAY_BASE_URL}/{endpoint}"

        # Send the request
        if method.upper() == "POST":
            response = requests.post(url, headers=self.headers, json=payload)
        # elif method.upper() == "GET":
        #     response = requests.get(url, headers=self.headers, params=payload)
        else:
            raise ValueError("Unsupported HTTP method")

        return response

    # TODO: update the comment
    def start_subscription(self, buyer_private_key, seller_pubkey, u, g, v, query_size, number_of_blocks, validate_every):
        """
        Generates queries for a given escrow account.

        Args:
            escrow_pubkey (str): The escrow public key.
            user_private_key (str): The user private key.

        Returns:
            response (requests.Response): The response object from the server.
        """
        payload = {
            "buyer_private_key": buyer_private_key,
            "seller_pubkey": seller_pubkey,
            "u": u,
            "g": g,
            "v": v,
            "query_size": int(query_size),
            "number_of_blocks": int(number_of_blocks),
            "validate_every": int(validate_every)
        }

        return self._send_request("start_subscription", method="POST", payload=payload)

    # TODO: update the comment
    def add_funds_to_subscription(self, buyer_private_key, escrow_pubkey, lamports_amount):
        """
        Generates queries for a given escrow account.

        Args:
            escrow_pubkey (str): The escrow public key.
            user_private_key (str): The user private key.

        Returns:
            response (requests.Response): The response object from the server.
        """
        payload = {
            "buyer_private_key": buyer_private_key,
            "escrow_pubkey": escrow_pubkey,
            "amount": int(lamports_amount),
        }

        return self._send_request("add_funds_to_subscription", method="POST", payload=payload)

    # TODO: update the comment
    def end_subscription_by_buyer(self, buyer_private_key, escrow_pubkey):
        """
        Generates queries for a given escrow account.

        Args:
            escrow_pubkey (str): The escrow public key.
            user_private_key (str): The user private key.

        Returns:
            response (requests.Response): The response object from the server.
        """
        payload = {
            "buyer_private_key": buyer_private_key,
            "escrow_pubkey": escrow_pubkey,
        }

        return self._send_request("end_subscription_by_buyer", method="POST", payload=payload)

    def generate_queries(self, escrow_pubkey, user_private_key):
        """
        Generates queries for a given escrow account.

        Args:
            escrow_pubkey (str): The escrow public key.
            user_private_key (str): The user private key.

        Returns:
            response (requests.Response): The response object from the server.
        """
        payload = {
            "escrow_pubkey": escrow_pubkey,
            "user_private_key": user_private_key
        }
        return self._send_request("generate_queries", method="POST", payload=payload)

    def get_queries_by_escrow_pubkey(self, escrow_pubkey):
        """
        Retrieves queries based on the escrow public key.

        Args:
            escrow_pubkey (str): The escrow public key.

        Returns:
            response (requests.Response): The response object from the server.
        """
        payload = {"escrow_pubkey": escrow_pubkey}
        return self._send_request("get_queries_by_escrow_pubkey", method="POST", payload=payload)

    def prove(self, seller_private_key, escrow_pubkey, sigma, mu):
        """
        Sends a prove request.

        Args:
            seller_private_key (str): The seller's private key.
            escrow_pubkey (str): The escrow account public key.
            sigma (str): The base64 encoded 48-byte value.
            mu (str): The mu value as a string.

        Returns:
            response (requests.Response): The response object from the server.
        """
        payload = {
            "seller_private_key": seller_private_key,
            "escrow_pubkey": escrow_pubkey,
            "sigma": sigma,
            "mu": mu
        }
        return self._send_request("prove", method="POST", payload=payload)
