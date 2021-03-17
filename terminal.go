package main

import (
	"fmt"

	"github.com/CyberSecurityN00b/star/pkg/star"
)

func main() {
	fmt.Println("NodeID:", star.NewNode(star.NodeTypeTerminal).ID)
}
