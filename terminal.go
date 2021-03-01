package main

import (
	"fmt"

	"github.com/CyberSecurityN00b/star/pkg/star"
)

func main() {
	fmt.Println(star.NodeTypeTerminal)
	fmt.Println("NodeID:", star.NewNodeID())
}
