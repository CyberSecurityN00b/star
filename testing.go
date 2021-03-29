package main

import (
	"bufio"
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
	var id1 star.NodeID
	var id2 star.MessageID

	star.NewUID(id1[:])
	star.NewUID(id2[:])

	t := new(A)
	t.ID = id1
	t.B.ID = id2
	/*
		l, _ := net.Listen("tcp", ":12345")
		c, _ := l.Accept()

		z := gzip.NewWriter(c)
		//j := json.NewEncoder(z)
		g := gob.NewEncoder(z)
		g.Encode(t)
		z.Close()
	*/

	data, _ := fs.ReadFile("message.cert")
	fmt.Println(string(data))
	/*
		data, _ = fs.ReadFile("embed/terminal.key")
		fmt.Println(string(data))*/
	in := bufio.NewReadWriter()
	fmt.Println("Waiting for input:")

	input, _ := in.ReadString('\n')
	fmt.Println(input)
}
