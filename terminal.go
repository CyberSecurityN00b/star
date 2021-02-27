package main

import (
	"fmt"

	"github.com/CyberSecurityN00b/star/pkg/star"
)

func main() {
	fmt.Println(star.NodeType_Terminal)
	fmt.Println("NodeID:", star.NewNodeID())
}
