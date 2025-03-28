package main

import (
	"bytes"
	"encoding/json"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"
)

// Message struct matches the expected request body
type Message struct {
	BPM int `json:"BPM"`
}

var mu = sync.Mutex{}

// Miner function that continuously mines and sends new blocks
func miner(minerID int, url string) {
	for {
		// Generate a random BPM value
		bpm := rand.Intn(100) + 50 // Random BPM between 50 and 150

		// Create JSON payload
		message := Message{BPM: bpm}
		payload, err := json.Marshal(message)
		if err != nil {
			log.Printf("Miner %d: Error encoding JSON: %v\n", minerID, err)
			continue
		}

		// Send POST request
		mu.Lock()
		resp, err := http.Post(url, "application/json", bytes.NewBuffer(payload))
		if err != nil {
			log.Printf("Miner %d: Error sending request: %v\n", minerID, err)
			continue
		}
		mu.Unlock()

		// Read response
		log.Printf("Miner %d: Mined new block with BPM %d, Response Status: %s\n", minerID, bpm, resp.Status)

		// Wait before mining the next block
		time.Sleep(time.Duration(rand.Intn(5)+3) * time.Second) // Wait 3-7 seconds
	}
}

func main() {
	url := "http://localhost:8080/" // Change this if your blockchain node is running on a different port

	// Start multiple miners as goroutines
	numMiners := 3
	for i := 1; i <= numMiners; i++ {
		go miner(i, url)
	}

	// Keep main thread alive
	select {}
}
