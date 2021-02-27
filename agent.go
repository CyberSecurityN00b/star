package main

import (
	"fmt"

	"github.com/CyberSecurityN00b/star/pkg/star"
)

func main() {
	fmt.Println(star.NodeType_Agent001)
	fmt.Println("NodeID:", star.NewNodeID())
	fmt.Println("MessageID:", star.NewMessageID())
}
