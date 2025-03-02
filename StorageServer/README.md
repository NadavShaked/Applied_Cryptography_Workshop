# Storage Server

## Overview

The **Storage Server** is a Flask-based application that provides secure file storage, retrieval, validation, and corruption testing functionalities. It integrates with a **Solana API Gateway** to manage escrow-based storage subscriptions and ensures data integrity through **Proof of Retrievability (PoR)**.

## Features

### API

- **File Upload & Storage:** Securely upload and store files with metadata linked to escrow accounts.
- **File Download:** Retrieve stored files via API requests.
- **Proof of Retrievability (PoR) Calculation:** Compute and verify PoR values (`sigma` and `mu`) for data integrity validation.
- **File Corruption:** Simulate data corruption using Reed-Solomon encoding for error detection. This gave you the capability to test that the storage server cheat and don't store the buyer file as the subscription agreement.

### Job

- **Automated File Validation:** Periodic validation of stored files based on their escrow contract conditions.
- **Subscription & Fund Management:** Interacts with Solana's escrow accounts to validate and handle storage payments.

## Prerequisites

Before running the Storage Server, ensure you have the following installed:

- [Python 3.11](https://www.python.org/downloads/)
- Required dependencies from [`requirements.txt`](requirements.txt), install with:

```sh
pip install -r requirements.txt
```

## Curl Templates and Examples

Example `curl` requests for all endpoints are available in the [`./curls`](Curls) directory. You can use them to quickly test the API.

## API Endpoints

### 1. **File Upload**
- **Endpoint:** `/api/upload`
- **Method:** `POST`
- **Description:** Uploads a file and associates it with an escrow account.
- **Parameters:**
  - `file`: The file to upload.
  - `escrow_public_key`: The escrow account associated with the file.
- **Response:**
  ```json
  { "message": "File received and saved", "filename": "example.txt" }
  ```

### 2. **File Download**
- **Endpoint:** `/api/download`
- **Method:** `GET`
- **Description:** Downloads a stored file.
- **Parameters:**
  - `filename`: The name of the file to download.
- **Response:** The requested file as an attachment.

### 3. **Calculate and Prove (PoR Validation)**
- **Endpoint:** `/api/calculate_and_prove`
- **Method:** `GET`
- **Description:** Computes and validates the PoR values (`sigma` and `mu`) for the given file.
- **Parameters:**
  - `filename`: The file to validate.
- **Response:**
  ```json
  { "proved": true }
  ```

### 4. **File Corruption Simulation**
- **Endpoint:** `/api/corrupt`
- **Method:** `GET`
- **Description:** Corrupts a stored file to test error detection and recovery mechanisms.
- **Parameters:**
  - `filename`: The file to corrupt.
- **Response:**
  ```json
  { "message": "The file 'example.txt' corrupted." }
  ```

## Automated Validation System

The Storage Server periodically validates stored files based on escrow contract conditions. The process follows these steps:

1. Check if the file needs validation based on `validate_every` interval.
2. Retrieve the escrow details and check the storage subscription status.
3. If the storage subscription has ended, attempt to withdraw funds and delete the file.
4. If the storage subscription is active, ensure there are sufficient funds for validation.
5. Perform PoR validation (calculate `sigma` and `mu`) and update the last verification timestamp.

## Running the Server

1. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```
2. Run the server:
   ```sh
   python -m flask run
   ```
3. The server will start at `http://127.0.0.1:5000/`

## Scheduled Job & Cleanup

The server includes a background job that periodically validates files. On shutdown, it performs cleanup tasks:

- Ends subscriptions for stored files.
- Shuts down the job gracefully.
