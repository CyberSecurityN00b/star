package main

import (
	"fmt"
	"time"
	"unsafe"

	"github.com/CyberSecurityN00b/star/pkg/star"
)

func main() {
	fmt.Println(star.NodeTypeAgent001)
	fmt.Println("NodeID:", star.NewNodeID())
	fmt.Println("MessageID:", star.NewMessageID())

	var msg star.Message
	msg.Meta.RequestSent = time.Now()
	fmt.Println(msg)
	fmt.Println(msg.Meta.RequestSent)

	fmt.Println(unsafe.Sizeof(msg))
}
