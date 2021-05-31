package star

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"
)

type Shell_Connector struct {
	Type      ShellType
	Address   string
	Listener  *net.Listener
	Requester NodeID
}

type Shell_Connection struct {
	Type        ShellType
	NetConn     net.Conn
	TLSConn     *tls.Conn
	ConnectID   ConnectID
	StreamID    StreamID
	Destination NodeID
}

type ShellType byte

const (
	ShellTypeTCP ShellType = iota + 1
	ShellTypeTCPTLS
	ShellTypeUDP
	ShellTypeUDPTLS
)

func NewShellConnection(address string, t ShellType, requester NodeID) {
	go (&Shell_Connector{Address: address, Type: t, Requester: requester}).Connect()
}

func NewShellListener(address string, t ShellType, requester NodeID) {
	go (&Shell_Connector{Address: address, Type: t, Requester: requester}).Listen()
}

///////////////////////////////////////////////////////////////////////////////
/****************************** Shell Connector ******************************/
///////////////////////////////////////////////////////////////////////////////

func (connector *Shell_Connector) Connect() (err error) {
	// Connect to a bind generic shell (i.e., netcat shell)
	conn := &Shell_Connection{}

	var n net.Conn
	var t *tls.Conn
	switch connector.Type {
	case ShellTypeTCP:
		n, err = net.Dial("tcp", connector.Address)
	case ShellTypeTCPTLS:
		t, err = tls.Dial("tcp", connector.Address, &tls.Config{InsecureSkipVerify: true})
	case ShellTypeUDP:
		n, err = net.Dial("udp", connector.Address)
	case ShellTypeUDPTLS:
		t, err = tls.Dial("udp", connector.Address, &tls.Config{InsecureSkipVerify: true})
	default:
		//TODO: Error message here
		return io.ErrClosedPipe
	}

	if err != nil {
		fmt.Println(err.Error())
		NewMessageError(0, err.Error()).Send(ConnectID{})
	}

	conn.NetConn = n
	conn.TLSConn = t
	conn.Type = connector.Type
	conn.ConnectID = RegisterConnection(conn)
	go conn.Handle()
	return
}

func (connector *Shell_Connector) Listen() (err error) {
	var l net.Listener
	var info string
	switch connector.Type {
	case ShellTypeTCP:
		l, err = net.Listen("tcp", connector.Address)
		info = fmt.Sprintf("[shell][tcp]%s", connector.Address)
	case ShellTypeTCPTLS:
		l, err = tls.Listen("tcp", connector.Address, &tls.Config{InsecureSkipVerify: true})
		info = fmt.Sprintf("[shell][tcp/tls]%s", connector.Address)
	case ShellTypeUDP:
		l, err = net.Listen("udp", connector.Address)
		info = fmt.Sprintf("[shell][udp]%s", connector.Address)
	case ShellTypeUDPTLS:
		l, err = tls.Listen("udp", connector.Address, &tls.Config{InsecureSkipVerify: true})
		info = fmt.Sprintf("[shell][udp/tls]%s", connector.Address)
	default:
		//TODO: Error message here
		return io.ErrClosedPipe
	}

	if err != nil {
		fmt.Println(err.Error())
		NewMessageError(0, err.Error()).Send(ConnectID{})
		return err
	}

	connector.Listener = &l
	id := RegisterListener(connector)
	ThisNodeInfo.AddListener(id, info)

	// Defer cleanup for when listener ends
	defer func() {
		recover()
		NewMessageError(MessageErrorResponseTypeBindDropped, connector.Address).Send(ConnectID{})
		UnregisterListener(id)
		ThisNodeInfo.RemoveListener(id)
	}()

	// Notify of new listener
	NewMessageNewBind(connector.Address).Send(ConnectID{})

	var conn *Shell_Connection
	for {
		conn = new(Shell_Connection)
		c, err := l.Accept()
		if err != nil {
			fmt.Println(err.Error())
			NewMessageError(0, err.Error()).Send(ConnectID{})
			return err
		}

		conn.NetConn = c
		conn.Type = connector.Type
		conn.Destination = connector.Requester
		conn.ConnectID = RegisterConnection(conn)
		go conn.Handle()
	}
}

func (connector *Shell_Connector) Close() {
	(*connector.Listener).Close()
}

///////////////////////////////////////////////////////////////////////////////
/****************************** Shell Connector ******************************/
///////////////////////////////////////////////////////////////////////////////

func (c Shell_Connection) Handle() {
	// Defer cleanup for when connection drops.
	var addr string
	if c.TLSConn != nil {
		addr = c.TLSConn.RemoteAddr().String()
	} else if c.NetConn != nil {
		addr = c.NetConn.RemoteAddr().String()
	} else {
		// What are we even doing here???
		return
	}
	defer func() {
		recover()
		NewMessageError(MessageErrorResponseTypeShellConnectionLost, addr).Send(ConnectID{})
		UnregisterConnection(c.ConnectID)
		ActiveStreams[c.StreamID].Close()
		ThisNodeInfo.RemoveConnector(c.ConnectID)
	}()

	// Notify of new connection
	NewConnection(addr).Send(ConnectID{})
	ThisNodeInfo.AddConnector(c.ConnectID, addr)

	// Setup new stream
	var context string
	switch c.Type {
	case ShellTypeTCP:
		context = fmt.Sprintf("shell[tcp][%s]", addr)
	case ShellTypeTCPTLS:
		context = fmt.Sprintf("shell[tcp/tls][%s]", addr)
	case ShellTypeUDP:
		context = fmt.Sprintf("shell[udp][%s]", addr)
	case ShellTypeUDPTLS:
		context = fmt.Sprintf("shell[udp/tls][%s]", addr)
	default:
		//TODO: Error message here
		return
	}
	meta := NewStreamMetaShell(c.Destination, context, func(data []byte) {
		c.NetConn.Write(data)
	}, func(s StreamID) {
		c.Close()
	})
	c.StreamID = meta.ID

	for {
		buff := make([]byte, RandDataSize())
		n, err := c.NetConn.Read(buff)
		if err == nil && n > 0 {
			meta.Write(buff[:n])
		} else {
			c.NetConn.Close()
			return
		}
	}
}

func (c Shell_Connection) MessageDuration() (d time.Duration) {
	return 1 * time.Minute
}

func (c Shell_Connection) Send(msg Message) (err error) {
	return
}

func (c Shell_Connection) Close() {
	if c.NetConn != nil {
		c.NetConn.Close()
	}
	if c.TLSConn != nil {
		c.TLSConn.Close()
	}
}
