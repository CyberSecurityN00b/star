package main

import (
	"fmt"
	"unsafe"

	"github.com/CyberSecurityN00b/star/pkg/star"
)

func main() {
	msg := star.NewMessage()
	node := star.NewNode(star.NodeTypeAgent)

	msg.Destination = node.ID

	fmt.Println("NodeID:", node.ID)
	fmt.Println("MessageID:", msg.ID)

	fmt.Println(msg)
	//fmt.Println(msg.Meta.RequestSent)

	fmt.Println(unsafe.Sizeof(msg))
}
