package star

import (
	"crypto/tls"
	"net"
)

type FileServer_Connector struct {
	Type      ConnectorType
	Address   string
	Listener  *net.Listener
	Requester NodeID
}

type FileServer_Connection struct {
	Type        ConnectorType
	NetConn     net.Conn
	TLSConn     *tls.Conn
	ConnectID   ConnectID
	StreamID    StreamID
	Destination NodeID
}

func NewFileServerConnection(address string, t ConnectorType, requester NodeID) {
	//go (&FileServer_Connector{Address: address, Type: t, Requester: requester}).Connect()
}

func NewFileServerListener(address string, t ConnectorType, requester NodeID) {
	//go (&FileServer_Connector{Address: address, Type: t, Requester: requester}).Listen()
}

///////////////////////////////////////////////////////////////////////////////
/**************************** FileServer Connector ***************************/
///////////////////////////////////////////////////////////////////////////////
/*
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
		//TODO: Error message here
		return io.ErrClosedPipe
	}

	if err != nil {
		fmt.Println(err.Error())
		NewMessageError(0, err.Error()).Send(ConnectID{})
		return
	}

	conn.NetConn = n
	conn.TLSConn = t
	conn.Type = connector.Type
	conn.ConnectID = RegisterConnection(conn)
	go conn.Handle()
	return
}

func (connector *FileServer_Connector) Listen() (err error) {
	var l net.Listener
	var info string
	switch connector.Type {
	case ConnectorType_FileServerTCP:
		l, err = net.Listen("tcp", connector.Address)
		info = fmt.Sprintf("[")
	}
}
*/
