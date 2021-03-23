package main

import (
	"fmt"

	"github.com/CyberSecurityN00b/star/pkg/star"
)

func main() {
	msg := star.NewMessage()
	node := star.NewNode(star.NodeTypeAgent)

	msg.Destination = node.ID

	fmt.Println("NodeID:", node.ID)
	fmt.Println("MessageID:", msg.ID)

	fmt.Println(msg)
}
