package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Block structure should match the blockchain node's structure
type Block struct {
	Index      int
	Timestamp  string
	BPM        int
	Hash       string
	PrevHash   string
	Nonce      int
	Difficulty int
	Signature  struct {
		R *big.Int
		S *big.Int
	}
	PubKeyX *big.Int `json:"PubKeyX"`
	PubKeyY *big.Int `json:"PubKeyY"`
}

// Response structure from the blockchain node
type BlockchainResponse []Block

var mu = sync.Mutex{}

// Function to calculate a block's hash
func calculateHash(block Block) string {
	record := fmt.Sprint(block.Index) + block.Timestamp + fmt.Sprint(block.BPM) + block.PrevHash + fmt.Sprint(block.Nonce)

	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)

	return hex.EncodeToString(hashed)
}

func signBlockHash(privKey *ecdsa.PrivateKey, block Block) (r, s *big.Int, err error) {
	blockHash := calculateHash(block)

	hash := sha256.New()
	hash.Write([]byte(blockHash))
	blockHashBytes := hash.Sum(nil)

	r, s, err = ecdsa.Sign(rand.Reader, privKey, blockHashBytes)
	if err != nil {
		return nil, nil, err
	}

	return r, s, nil

}

// Function to validate proof-of-work

func isValidProof(hash string, difficulty int) bool {
	prefix := strings.Repeat("0", difficulty)
	return strings.HasPrefix(hash, prefix)
}

func generateKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		return nil, nil, err
	}

	return privKey, &privKey.PublicKey, nil
}

var privKey *ecdsa.PrivateKey
var pubKey *ecdsa.PublicKey

// Miner function to mine and submit blocks
func miner(minerID int, url string) {

	privKey, pubKey, _ = generateKeyPair()

	for {
		// Get the latest block from the blockchain
		resp, err := http.Get(url)
		if err != nil {
			log.Printf("Miner %d: Error fetching blockchain: %v\n", minerID, err)
			time.Sleep(5 * time.Second)
			continue
		}

		defer resp.Body.Close()

		var blockchain BlockchainResponse
		if err := json.NewDecoder(resp.Body).Decode(&blockchain); err != nil {
			log.Printf("Miner %d: Error decoding blockchain response: %v\n", minerID, err)
			time.Sleep(5 * time.Second)
			continue
		}

		if len(blockchain) == 0 {
			log.Printf("Miner %d: Blockchain is empty, skipping mining...\n", minerID)
			time.Sleep(5 * time.Second)
			continue
		}

		lastBlock := blockchain[len(blockchain)-1]
		newBlock := Block{
			Index:      lastBlock.Index + 1,
			Timestamp:  time.Now().String(),
			BPM:        50, // Random BPM between 50 and 150
			PrevHash:   lastBlock.Hash,
			Difficulty: lastBlock.Difficulty, // Keep the same difficulty
			Nonce:      0,
		}

		// Mine the new block by finding a valid Nonce
		for {
			newBlock.Nonce++
			newBlock.Hash = calculateHash(newBlock)

			if isValidProof(newBlock.Hash, newBlock.Difficulty) {
				break
			}
		}

		mu.Lock()
		r, s, err := signBlockHash(privKey, newBlock)
		if err != nil {
			log.Printf("Miner %d: Error signing block: %v\n", minerID, err)
			continue
		}

		newBlock.Signature.R = r
		newBlock.Signature.S = s

		newBlock.PubKeyX = pubKey.X
		newBlock.PubKeyY = pubKey.Y

		// Send the mined block to the blockchain
		payload, err := json.Marshal(newBlock)
		if err != nil {
			log.Printf("Miner %d: Error encoding JSON: %v\n", minerID, err)
			continue
		}

		resp, err = http.Post(url, "application/json", bytes.NewBuffer(payload))
		if err != nil {
			log.Printf("Miner %d: Error sending block: %v\n", minerID, err)
			continue
		}
		mu.Unlock()

		log.Println("response: ", resp)

		log.Printf("Miner %d: ✅ Mined new block #%d with Nonce %d\n", minerID, newBlock.Index, newBlock.Nonce)

		// Wait before mining the next block
		time.Sleep(time.Duration(2) * time.Second)
	}
}

func main() {
	url := "http://localhost:8080/" // Blockchain node URL

	// Start multiple miners as goroutines
	numMiners := 1
	for i := 1; i <= numMiners; i++ {
		go miner(i, url)
	}

	// Keep main thread alive
	select {}
}
