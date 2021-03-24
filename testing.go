package main

import (
	"compress/gzip"
	"encoding/json"
	"os"

	"github.com/CyberSecurityN00b/star/pkg/star"
)

type A struct {
	ID star.NodeID `json:"id"`
	B  B           `json:"b"`
}

type B struct {
	ID star.MessageID `json:"id`
}

func main() {
	var id1 star.NodeID
	var id2 star.MessageID

	star.NewUID(id1[:])
	star.NewUID(id2[:])

	t := new(A)
	t.ID = id1
	t.B.ID = id2

	x := json.NewEncoder(os.Stdout)
	x.Encode(t)

	z := gzip.NewWriter(os.Stdout)
	z.
	y := json.NewEncoder(z)
	y.Encode(t)
	z.Close()
}
