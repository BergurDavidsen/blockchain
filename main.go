package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

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
	PubKeyX *big.Int
	PubKeyY *big.Int
}

var Blockchain []Block

// generate a private and public key pair
func generateKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		return nil, nil, err
	}

	return privKey, &privKey.PublicKey, nil
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

func calculateHash(block Block) string {
	record := fmt.Sprint(block.Index) + block.Timestamp + fmt.Sprint(block.BPM) + block.PrevHash + fmt.Sprint(block.Nonce)

	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)

	return hex.EncodeToString(hashed)
}
func isValidProof(hash string, difficulty int) bool {
	prefix := strings.Repeat("0", difficulty)
	return strings.HasPrefix(hash, prefix)
}
func mineBlock(oldBlock Block, BPM int, privKey *ecdsa.PrivateKey, difficulty int) (Block, error) {
	var newBlock Block

	t := time.Now()

	newBlock.Index = oldBlock.Index + 1
	newBlock.BPM = BPM
	newBlock.Timestamp = t.String()
	newBlock.PrevHash = oldBlock.Hash
	newBlock.Difficulty = difficulty

	for {
		newBlock.Nonce++
		newBlock.Hash = calculateHash(newBlock)

		if isValidProof(newBlock.Hash, difficulty) {
			break
		}

	}
	r, s, err := signBlockHash(privKey, newBlock)
	if err != nil {
		return newBlock, err
	}

	newBlock.Signature.R = r
	newBlock.Signature.S = s

	return newBlock, nil

}

func generateBlock(oldBlock Block, BPM int, privKey *ecdsa.PrivateKey) (Block, error) {

	var newBlock Block

	t := time.Now()

	newBlock.Index = oldBlock.Index + 1
	newBlock.Timestamp = t.String()
	newBlock.BPM = BPM
	newBlock.PrevHash = oldBlock.Hash
	newBlock.Hash = calculateHash(newBlock)

	r, s, err := signBlockHash(privKey, newBlock)

	if err != nil {
		return newBlock, err
	}

	newBlock.Signature.R = r
	newBlock.Signature.S = s

	return newBlock, nil
}

func verifyBlockSignature(block Block) bool {

	minerPubKey := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     block.PubKeyX,
		Y:     block.PubKeyY,
	}

	blockHash := calculateHash(block)

	hash := sha256.New()
	hash.Write([]byte(blockHash))
	blockHashBytes := hash.Sum(nil)

	valid := ecdsa.Verify(&minerPubKey, blockHashBytes, block.Signature.R, block.Signature.S)

	return valid
}

func isBlockValid(newBlock, oldBlock Block) bool {
	if oldBlock.Index+1 != newBlock.Index {
		log.Println("index not valid")
		return false
	}

	if oldBlock.Hash != newBlock.PrevHash {
		log.Println("prev hash not valid")
		return false
	}

	if calculateHash(newBlock) != newBlock.Hash {
		log.Println("hash Not valid")
		return false
	}

	if !verifyBlockSignature(newBlock) {
		log.Println("signature not valid")
		return false
	}

	return true
}

func replaceChain(newBlocks []Block) {
	if len(newBlocks) > len(Blockchain) {
		Blockchain = newBlocks
	}
}

func run() error {
	mux := makeMuxRouter()
	httpAddr := os.Getenv("ADDR")
	log.Println("Listening on ", os.Getenv("ADDR"))

	s := &http.Server{
		Addr:           ":" + httpAddr,
		Handler:        mux,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	if err := s.ListenAndServe(); err != nil {
		return err
	}

	return nil
}

func makeMuxRouter() http.Handler {
	muxRouter := mux.NewRouter()
	muxRouter.HandleFunc("/", handleGetBlockchain).Methods("GET")
	muxRouter.HandleFunc("/", handleWriteBlock).Methods("POST")
	return muxRouter
}

func handleGetBlockchain(w http.ResponseWriter, r *http.Request) {
	bytes, err := json.MarshalIndent(Blockchain, "", " ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	io.Writer.Write(w, bytes)
}

type Message struct {
	BPM int
}

func handleWriteBlock(w http.ResponseWriter, r *http.Request) {
	var newBlock Block

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&newBlock); err != nil {
		respondWithJSON(w, r, http.StatusBadRequest, "Invalid block format")
		return
	}
	defer r.Body.Close()
	spew.Dump(newBlock)

	lastBlock := Blockchain[len(Blockchain)-1]

	// Validate proof-of-work
	if !isValidProof(newBlock.Hash, newBlock.Difficulty) {
		respondWithJSON(w, r, http.StatusForbidden, "Block does not meet proof-of-work requirements")
		return
	}

	// Validate if the new block is legitimate
	if isBlockValid(newBlock, lastBlock) {
		Blockchain = append(Blockchain, newBlock)
		spew.Dump(Blockchain)
		respondWithJSON(w, r, http.StatusCreated, newBlock)
	} else {
		log.Println("Invalid block")
		respondWithJSON(w, r, http.StatusBadRequest, "Invalid block")
	}
}

func respondWithJSON(w http.ResponseWriter, r *http.Request, code int, payload interface{}) {

	response, err := json.MarshalIndent(payload, "", " ")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("HTTP 500: Internal Server Error"))
		return
	}

	w.WriteHeader(code)
	w.Write(response)
}

var privKey *ecdsa.PrivateKey
var pubKey *ecdsa.PublicKey

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal(err)
	}

	privKey, pubKey, err = generateKeyPair()

	if err != nil {
		log.Fatal("error generating key pair: ", err)
	}

	go func() {
		t := time.Now()
		genesisBlock := Block{
			Index:      0,
			Timestamp:  t.String(),
			BPM:        0,
			PrevHash:   "",
			Difficulty: 6,
		}

		genesisBlock.Hash = calculateHash(genesisBlock)

		r, s, err := signBlockHash(privKey, genesisBlock)
		if err != nil {
			log.Fatal("Error signing genesis block: ", err)
		}

		genesisBlock.Signature.R = r
		genesisBlock.Signature.S = s

		Blockchain = append(Blockchain, genesisBlock)
		spew.Dump(genesisBlock)

	}()
	log.Fatal(run())
}
