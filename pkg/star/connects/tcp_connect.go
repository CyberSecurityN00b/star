package star

import (
	"encoding/json"
	"io"
	"net"
	"time"

	"github.com/CyberSecurityN00b/star/pkg/star"
)

type TCP_Connector struct {
	Address string
}

type TCP_Connection struct {
	Conn        net.Conn
	ID          star.ConnectID
	JsonEncoder json.Encoder
	JsonDecoder json.Decoder
}

///////////////////////////////////////////////////////////////////////////////
/******************************* TCP Connector *******************************/
///////////////////////////////////////////////////////////////////////////////

func (connector TCP_Connector) Connect() (err error) {
	var conn *TCP_Connection

	c, err := net.Dial("tcp", connector.Address)
	if err != nil {
		return
	}

	conn.Conn = c
	go conn.Handle()
	return
}

func (connector TCP_Connector) Listen() error {
	l, err := net.Listen("tcp", connector.Address)
	if err != nil {
		return err
	}

	var conn *TCP_Connection
	for {
		conn = new(TCP_Connection)
		c, err := l.Accept()
		if err != nil {
			return err
		}

		conn.Conn = c
		go conn.Handle()
	}
}

///////////////////////////////////////////////////////////////////////////////
/******************************* TCP Connection ******************************/
///////////////////////////////////////////////////////////////////////////////

func (c TCP_Connection) Handle() {
	// If not a proper message, check if it is an HTTP request
	// If an HTTP request, offload that to the STAR agent download feature
	// If not an HTTP request, treat like a shell connecting
	var msg *star.Message
	for {
		msg = new(star.Message)
		err := c.JsonDecoder.Decode(&msg)
		if err == io.EOF {
			go msg.Handle(c.ID)
		}
	}
}

func (c TCP_Connection) MessageDuration() (d time.Duration) {
	return 1 * time.Minute
}

func (c TCP_Connection) Send(msg star.Message) (err error) {
	c.JsonEncoder.Encode(msg)
	return
}

func (c TCP_Connection) StreamChunkSize() uint {
	return 30000
}
