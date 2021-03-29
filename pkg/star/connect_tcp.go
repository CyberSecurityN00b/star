package star

import (
	"crypto/tls"
	"encoding/gob"
	"fmt"
	"io"
	"net"
	"time"
)

type TCP_Connector struct {
	Address string
}

type TCP_Connection struct {
	TLSConn *tls.Conn
	NetConn net.Conn
	ID      ConnectID
	Encoder *gob.Encoder
	Decoder *gob.Decoder
}

func NewTCPConnection(address string) {
	go TCP_Connector{Address: address}.Connect()
}

func NewTCPListener(address string) {
	go TCP_Connector{Address: address}.Listen()
}

///////////////////////////////////////////////////////////////////////////////
/******************************* TCP Connector *******************************/
///////////////////////////////////////////////////////////////////////////////

func (connector TCP_Connector) Connect() (err error) {
	var conn TCP_Connection

	c, err := tls.Dial("tcp", connector.Address, ConnectionConfig)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	conn.TLSConn = c
	conn.Encoder = gob.NewEncoder(c)
	conn.Decoder = gob.NewDecoder(c)
	conn.ID = RegisterConnection(conn)
	go conn.Handle()
	return
}

func (connector TCP_Connector) Listen() error {
	l, err := tls.Listen("tcp", connector.Address, ConnectionConfig)
	if err != nil {
		fmt.Println(err.Error())
		return err
	}

	id := RegisterListener(connector)

	// Defer cleanup for when listener ends
	defer func() {
		recover()
		msg := NewMessageError(MessageErrorResponseTypeBindDropped, connector.Address)
		msg.Send(ConnectID{})
		UnregisterListener(id)
	}()

	// Notify of new listener
	msg := NewMessageNewBind(connector.Address)
	msg.Send(ConnectID{})

	var conn *TCP_Connection
	for {
		conn = new(TCP_Connection)
		c, err := l.Accept()
		if err != nil {
			fmt.Println(err.Error())
			return err
		}

		conn.NetConn = c
		conn.Encoder = gob.NewEncoder(c)
		conn.Decoder = gob.NewDecoder(c)
		conn.ID = RegisterConnection(conn)
		go conn.Handle()
	}
}

///////////////////////////////////////////////////////////////////////////////
/******************************* TCP Connection ******************************/
///////////////////////////////////////////////////////////////////////////////

func (c TCP_Connection) Handle() {
	// Defer cleanup for when connection drops.
	var addr string
	if c.NetConn != nil {
		addr = c.NetConn.RemoteAddr().String()
	} else {
		addr = c.TLSConn.RemoteAddr().String()
	}
	defer func() {
		recover()
		msg := NewMessageError(MessageErrorResponseTypeConnectionLost, addr)
		msg.Send(ConnectID{})
		UnregisterConnection(c.ID)
	}()

	// Notify of new connection
	msg := NewMessageNewConnection(addr)
	msg.Send(ConnectID{})

	// If not a proper message, check if it is an HTTP request
	// If an HTTP request, offload that to the STAR agent download feature
	// If not an HTTP request, treat like a shell connecting
	for {
		msg := &Message{}
		err := c.Decoder.Decode(&msg)
		if err == nil {
			go msg.Handle(c.ID)
		} else if err == io.EOF {
			c.NetConn.Close()
			return
		}
	}
}

func (c TCP_Connection) MessageDuration() (d time.Duration) {
	return 1 * time.Minute
}

func (c TCP_Connection) Send(msg Message) (err error) {
	c.Encoder.Encode(msg)
	return
}

func (c TCP_Connection) StreamChunkSize() uint {
	return 30000
}
