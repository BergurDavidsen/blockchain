# Simple Blockchain in Golang

This is a simple blockchain implementation written in Go. It allows adding blocks containing BPM (Beats Per Minute) values to a blockchain and provides a basic HTTP API to interact with it.

## Features

- Implements a simple blockchain structure
- Hashing using SHA-256
- Validation of blocks
- REST API to interact with the blockchain
- Uses Gorilla Mux for routing

## Prerequisites

- Go (latest version recommended)
- [Gorilla Mux](https://github.com/gorilla/mux)
- [Godotenv](https://github.com/joho/godotenv)
- [Go-spew](https://github.com/davecgh/go-spew)

## Installation

1. Clone the repository:

   ```sh
   git clone https://github.com/BergurDavidsen/blockchain.git
   ```

2. Navigate to the project directory:

   ```sh
   cd blockchain
   ```

3. Install dependencies:

   ```sh
   go mod tidy
   ```

4. Create a `.env` file and specify the port:

   ```sh
   echo "ADDR=8080" > .env
   ```

## Usage

1. Run the blockchain server:

   ```sh
   go run main.go
   ```

2. The server will start on `http://localhost:8080` (or the port specified in `.env`)

## API Endpoints

### Get Blockchain

- **Endpoint:** `GET /`
- **Description:** Retrieves the current blockchain
- **Example Request:**

  ```sh
  curl -X GET http://localhost:8080/
  ```

### Add a Block

- **Endpoint:** `POST /`
- **Description:** Adds a new block to the blockchain
- **Example Request:**

  ```sh
  curl -X POST -H "Content-Type: application/json" -d '{"BPM":72}' http://localhost:8080/
  ```

## Future Enhancements

- Implement Proof of Work (PoW)
- Add peer-to-peer networking
- Improve data persistence

## License

This project is licensed under the MIT License.
