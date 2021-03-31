package main

import (
	"embed"
	"fmt"

	"github.com/CyberSecurityN00b/star/pkg/star"
)

//go:embed connection.crt
var fs embed.FS

type A struct {
	ID star.NodeID `json:"id"`
	B  B           `json:"b"`
}

type B struct {
	ID star.MessageID `json:"id`
}

func main() {
	var test []byte
	fmt.Println(len(test))
}
