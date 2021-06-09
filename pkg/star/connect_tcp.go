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
	Address  string
	Listener *net.Listener
}

type TCP_Connection struct {
	TLSConn *tls.Conn
	NetConn net.Conn
	ID      ConnectID
	Encoder *gob.Encoder
	Decoder *gob.Decoder
}

func NewTCPConnection(address string) {
	go (&TCP_Connector{Address: address}).Connect()
}

func NewTCPListener(address string) {
	go (&TCP_Connector{Address: address}).Listen()
}

///////////////////////////////////////////////////////////////////////////////
/******************************* TCP Connector *******************************/
///////////////////////////////////////////////////////////////////////////////

func (connector *TCP_Connector) Connect() (err error) {
	conn := &TCP_Connection{}

	c, err := tls.Dial("tcp", connector.Address, ConnectionConfig)
	if err != nil {
		fmt.Println(err.Error())
		NewMessageError(0, err.Error()).Send(ConnectID{})
		return
	}

	conn.TLSConn = c
	conn.Encoder = gob.NewEncoder(c)
	conn.Decoder = gob.NewDecoder(c)
	conn.ID = RegisterConnection(conn)
	go conn.Handle()
	return
}

func (connector *TCP_Connector) Listen() error {
	l, err := tls.Listen("tcp", connector.Address, ConnectionConfig)
	if err != nil {
		NewMessageError(0, err.Error()).Send(ConnectID{})
		return err
	}

	connector.Listener = &l
	id := RegisterListener(connector)
	ThisNodeInfo.AddListener(id, ConnectorType_TCPTLS, connector.Address)

	// Defer cleanup for when listener ends
	defer func() {
		recover()
		NewMessageError(MessageErrorResponseTypeBindDropped, connector.Address).Send(ConnectID{})
		UnregisterListener(id)
		ThisNodeInfo.RemoveListener(id)
	}()

	// Notify of new listener
	NewMessageNewBind(connector.Address).Send(ConnectID{})

	var conn *TCP_Connection
	for {
		conn = new(TCP_Connection)
		c, err := l.Accept()
		if err != nil {
			fmt.Println(err.Error())
			NewMessageError(0, err.Error()).Send(ConnectID{})
			return err
		}

		conn.NetConn = c
		conn.Encoder = gob.NewEncoder(c)
		conn.Decoder = gob.NewDecoder(c)
		conn.ID = RegisterConnection(conn)
		go conn.Handle()
	}
}

func (connector *TCP_Connector) Close() {
	(*connector.Listener).Close()
}

///////////////////////////////////////////////////////////////////////////////
/******************************* TCP Connection ******************************/
///////////////////////////////////////////////////////////////////////////////

func (c TCP_Connection) Handle() {
	// Defer cleanup for when connection drops.
	var addr string
	if c.TLSConn != nil {
		addr = c.TLSConn.RemoteAddr().String()
	} else {
		addr = c.NetConn.RemoteAddr().String()
	}
	defer func() {
		recover()
		NewMessageError(MessageErrorResponseTypeConnectionLost, addr).Send(ConnectID{})
		UnregisterConnection(c.ID)
		ThisNodeInfo.RemoveConnector(c.ID)
	}()

	// Notify of new connection
	NewConnection(addr).Send(ConnectID{})
	ThisNodeInfo.AddConnector(c.ID, ConnectorType_TCPTLS, addr)

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

func (c TCP_Connection) Close() {
	if c.NetConn != nil {
		c.NetConn.Close()
	}
	if c.TLSConn != nil {
		c.TLSConn.Close()
	}
}
