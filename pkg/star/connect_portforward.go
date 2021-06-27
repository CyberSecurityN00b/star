package star

import (
	"io"
	"net"
	"time"
)

type PortForward_Connector struct {
	Type       ConnectorType
	Address    string
	DstNode    NodeID
	DstAddress string
	DstType    ConnectorType
	Listener   *net.Listener
}

type PortForward_Connection struct {
	Type       ConnectorType
	NetConn    net.Conn
	DstNode    NodeID
	DstAddress string
	DstType    ConnectorType
	ID         ConnectID
	StreamID   StreamID
}

func NewPortForwardConnection(address string, t ConnectorType, dstNode NodeID, dstAddress string, dstType ConnectorType) {
	go (&PortForward_Connector{Address: address, Type: t, DstNode: dstNode, DstAddress: dstAddress, DstType: dstType}).Connect()
}

func NewPortForwardListener(address string, t ConnectorType, dstNode NodeID, dstAddress string, dstType ConnectorType) {
	go (&PortForward_Connector{Address: address, Type: t, DstNode: dstNode, DstAddress: dstAddress, DstType: dstType}).Listen()
}

///////////////////////////////////////////////////////////////////////////////
/*************************** PortForward Connector ***************************/
///////////////////////////////////////////////////////////////////////////////

func (connector *PortForward_Connector) Connect() (err error) {
	conn := &PortForward_Connection{}

	var n net.Conn
	switch connector.Type {
	case ConnectorType_PortForwardTCP:
		n, err = net.Dial("tcp", connector.Address)
	case ConnectorType_PortForwardUDP:
		n, err = net.Dial("udp", connector.Address)
	default:
		return io.ErrClosedPipe
	}

	if err != nil {
		NewMessageError(0, err.Error()).Send(ConnectID{})
		return
	}

	conn.NetConn = n
	conn.Type = connector.Type
	conn.DstAddress = connector.DstAddress
	conn.DstNode = connector.DstNode
	conn.DstType = connector.DstType
	conn.ID = RegisterConnection(conn)
	go conn.Handle()

	return
}

func (connector *PortForward_Connector) Listen() (err error) {
	var l net.Listener
	switch connector.Type {
	case ConnectorType_PortForwardTCP:
		l, err = net.Listen("tcp", connector.Address)
	case ConnectorType_PortForwardUDP:
		l, err = net.Listen("udp", connector.Address)
	default:
		return io.ErrClosedPipe
	}

	if err != nil {
		NewMessageError(0, err.Error()).Send(ConnectID{})
		return err
	}

	connector.Listener = &l
	id := RegisterListener(connector)
	ThisNodeInfo.AddListener(id, connector.Type, connector.Address)

	// Defer cleanup for when listener ends
	defer func() {
		recover()
		NewMessageError(MessageErrorResponseTypeBindDropped, connector.Address).Send(ConnectID{})
		UnregisterListener(id)
		ThisNodeInfo.RemoveListener(id)
	}()

	// Notify of new listener
	NewMessageNewBind(connector.Address).Send(ConnectID{})

	var conn *PortForward_Connection
	for {
		conn = new(PortForward_Connection)
		c, err := l.Accept()
		if err != nil {
			NewMessageError(0, err.Error()).Send(ConnectID{})
			return err
		}

		conn.NetConn = c
		conn.Type = connector.Type
		conn.DstAddress = connector.DstAddress
		conn.DstNode = connector.DstNode
		conn.DstType = connector.DstType
		conn.ID = RegisterConnection(conn)
		go conn.Handle()
	}
}

func (connector *PortForward_Connector) Close() {
	if (*connector.Listener) != nil {
		(*connector.Listener).Close()
	}
}

///////////////////////////////////////////////////////////////////////////////
/*************************** PortForward Connection **************************/
///////////////////////////////////////////////////////////////////////////////

func (c PortForward_Connection) Handle() {
	// Defer cleanup for when connection drops
	var addr string
	if c.NetConn != nil {
		addr = c.NetConn.RemoteAddr().Network()
	} else {
		// What are we even going here???
		return
	}
	defer func() {
		recover()
		NewMessageError(MessageErrorResponseTypePortForwardingConnectionLost, addr).Send(ConnectID{})
		s, ok := GetActiveStream(c.StreamID)
		if ok {
			s.Close()
		}
		UnregisterConnection(c.ID)
		ThisNodeInfo.RemoveConnector(c.ID)
	}()

	// Notify of new connection
	NewConnection(addr).Send(ConnectID{})
	ThisNodeInfo.AddConnector(c.ID, c.Type, addr)

	// Setup new stream
	var meta *StreamMeta
	if c.DstType == ConnectorType_PortForwardUDP {
		meta = NewStreamMetaPortForwardingUDP(c.DstNode, c.DstAddress, func(data []byte) {
			c.NetConn.Write(data)
		}, func(s StreamID) {
			c.Close()
		})
	} else {
		meta = NewStreamMetaPortForwardingTCP(c.DstNode, c.DstAddress, func(data []byte) {
			c.NetConn.Write(data)
		}, func(s StreamID) {
			c.Close()
		})
	}
	c.StreamID = meta.ID

	buff := make([]byte, c.DataSize())
	for {
		n, err := c.Read(buff)
		if err == nil && n > 0 {
			meta.Write(buff[:n])
		} else {
			c.Close()
		}
	}
}

func (c PortForward_Connection) MessageDuration() (d time.Duration) {
	return 1 * time.Minute
}

func (c PortForward_Connection) Send(msg Message) (err error) {
	return
}

func (c PortForward_Connection) Read(data []byte) (n int, err error) {
	if c.NetConn != nil {
		n, err = c.NetConn.Read(data)
	}
	return
}

func (c PortForward_Connection) Write(data []byte) (n int, err error) {
	if c.NetConn != nil {
		n, err = c.NetConn.Write(data)
	}
	return
}

func (c PortForward_Connection) Close() {
	if c.NetConn != nil {
		c.NetConn.Close()
	}
	UnregisterConnection(c.ID)
	ThisNodeInfo.RemoveConnector(c.ID)
}

func (c PortForward_Connection) DataSize() (s int) {
	return 65535
}

///////////////////////////////////////////////////////////////////////////////
// Share this one between both agent and terminal node types
///////////////////////////////////////////////////////////////////////////////

func ProcessMessagePortForward(msg *Message) {
	var reqMsg MessagePortForwardRequest

	err := msg.GobDecodeMessage(&reqMsg)
	if err != nil {
		return
	}

	go NewPortForwardListener(reqMsg.SrcAddress, ConnectorType_PortForwardTCP, reqMsg.DstNode, reqMsg.DstAddress, reqMsg.DstType)
}
