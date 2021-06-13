package star

import (
	"crypto/tls"
	"io"
	"net"
	"time"
)

type FileServer_Connector struct {
	Type       ConnectorType
	Address    string
	Listener   *net.Listener
	Requester  NodeID
	FileConnID ConnectID
}

type FileServer_Connection struct {
	Type        ConnectorType
	NetConn     net.Conn
	TLSConn     *tls.Conn
	ID          ConnectID
	FileConnID  ConnectID
	StreamID    StreamID
	Destination NodeID
}

func NewFileServerConnection(address string, t ConnectorType, requester NodeID, FileConnID ConnectID) {
	go (&FileServer_Connector{Address: address, Type: t, Requester: requester, FileConnID: FileConnID}).Connect()
}

func NewFileServerListener(address string, t ConnectorType, requester NodeID, FileConnID ConnectID) {
	go (&FileServer_Connector{Address: address, Type: t, Requester: requester, FileConnID: FileConnID}).Listen()
}

///////////////////////////////////////////////////////////////////////////////
/**************************** FileServer Connector ***************************/
///////////////////////////////////////////////////////////////////////////////

func (connector *FileServer_Connector) Connect() (err error) {
	// Connect to a listener and serve the file
	conn := &FileServer_Connection{}

	var n net.Conn
	var t *tls.Conn
	switch connector.Type {
	case ConnectorType_FileServerTCP:
		n, err = net.Dial("tcp", connector.Address)
	case ConnectorType_FileServerTCPTLS:
		t, err = tls.Dial("tcp", connector.Address, &tls.Config{InsecureSkipVerify: true})
	case ConnectorType_FileServerUDP:
		n, err = net.Dial("udp", connector.Address)
	case ConnectorType_FileServerUDPTLS:
		t, err = tls.Dial("udp", connector.Address, &tls.Config{InsecureSkipVerify: true})
	default:
		return io.ErrClosedPipe
	}

	if err != nil {
		print(err.Error())
		NewMessageError(0, err.Error()).Send(ConnectID{})
		return
	}

	conn.NetConn = n
	conn.TLSConn = t
	conn.Type = connector.Type
	conn.FileConnID = connector.FileConnID
	conn.ID = RegisterConnection(conn)
	go conn.Handle()
	return
}

func (connector *FileServer_Connector) Listen() (err error) {
	var l net.Listener
	switch connector.Type {
	case ConnectorType_FileServerTCP:
		l, err = net.Listen("tcp", connector.Address)
	case ConnectorType_FileServerTCPTLS:
		l, err = tls.Listen("tcp", connector.Address, &tls.Config{InsecureSkipVerify: true})
	case ConnectorType_FileServerUDP:
		l, err = net.Listen("udp", connector.Address)
	case ConnectorType_ShellUDPTLS:
		l, err = tls.Listen("udp", connector.Address, &tls.Config{InsecureSkipVerify: true})
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

	var conn *FileServer_Connection
	for {
		conn = new(FileServer_Connection)
		c, err := l.Accept()
		if err != nil {
			NewMessageError(0, err.Error()).Send(ConnectID{})
			return err
		}

		conn.NetConn = c
		conn.Type = connector.Type
		conn.Destination = connector.Requester
		conn.FileConnID = connector.FileConnID
		conn.ID = RegisterConnection(conn)
		go conn.Handle()
	}
}

func (connector *FileServer_Connector) Close() {
	(*connector.Listener).Close()
}

///////////////////////////////////////////////////////////////////////////////
/*************************** FileServer Connection ***************************/
///////////////////////////////////////////////////////////////////////////////

func (c FileServer_Connection) Handle() {
	// Defer cleanup for when connection drops
	var addr string
	if c.TLSConn != nil {
		addr = c.TLSConn.RemoteAddr().String()
	} else if c.NetConn != nil {
		addr = c.NetConn.RemoteAddr().String()
	} else {
		// What are we even doing here???
		return
	}

	// Notify of new connection
	NewConnection(addr).Send(ConnectID{})
	ThisNodeInfo.AddConnector(c.ID, c.Type, addr)

	// Request transfer initiation
	NewMessageFileServerInitiateTransferRequest(c.FileConnID, c.ID).Send(ConnectID{})
}

func (c FileServer_Connection) MessageDuration() (d time.Duration) {
	return 1 * time.Minute
}

func (c FileServer_Connection) Send(msg Message) (err error) {
	return
}

func (c FileServer_Connection) Read(data []byte) (n int, err error) {
	if c.TLSConn != nil {
		n, err = c.TLSConn.Read(data)
	} else if c.NetConn != nil {
		n, err = c.NetConn.Read(data)
	}
	return
}

func (c FileServer_Connection) Write(data []byte) (n int, err error) {
	if c.TLSConn != nil {
		n, err = c.TLSConn.Write(data)
	} else if c.NetConn != nil {
		n, err = c.NetConn.Write(data)
	}
	return
}

func (c FileServer_Connection) Close() {
	if c.NetConn != nil {
		c.NetConn.Close()
	}
	if c.TLSConn != nil {
		c.TLSConn.Close()
	}
	UnregisterConnection(c.ID)
	ThisNodeInfo.RemoveConnector(c.ID)
}
