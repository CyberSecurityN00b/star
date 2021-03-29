package star

import (
	"crypto/tls"
	"time"
)

// The Connection interface provides the standard functions for using STAR node communications.
type Connection interface {
	Handle()
	MessageDuration() time.Duration
	Send(msg Message) (err error)
	StreamChunkSize() uint
}

// The Connector interface provides the standard functions for creating STAR node connections.
type Connector interface {
	Connect() (err error)
	Listen() (err error)
}

var connectionTracker map[ConnectID]Connection
var listenerTracker map[ConnectID]Connector
var destinationTracker map[NodeID]ConnectID
var ConnectionCert tls.Certificate
var ConnectionConfig *tls.Config

///////////////////////////////////////////////////////////////////////////////
/******************************* Connection ID *******************************/
///////////////////////////////////////////////////////////////////////////////

// The ConnectID type is a fixed-length byte array which should serve as a
// UUID for each Connection
type ConnectID [9]byte

func NewConnectID() (id ConnectID) {
	NewUID([]byte(id[:]))
	return
}

// Formats a ConnectID into a print-friendly string
func (id ConnectID) String() string {
	return SqrtedString(id[:], "-")
}

///////////////////////////////////////////////////////////////////////////////
/******************************* ConnectorType *******************************/
///////////////////////////////////////////////////////////////////////////////

type ConnectorType byte

const (
	// ConnectorTypeTCP is used by the terminal to tell an agent that a TCP
	// connector should be used when requesting a bind or a connect.
	// The implementation for a TCP connector is in connects/tcp_connect.go
	ConnectorTypeTCP ConnectorType = iota + 1
)

///////////////////////////////////////////////////////////////////////////////
/***************************** ConnectionTracker *****************************/
///////////////////////////////////////////////////////////////////////////////

// RegisterConnection adds a Connection to the tracker
func RegisterConnection(conn Connection) ConnectID {
	id := NewConnectID()
	connectionTracker[id] = conn
	return id
}

// UnregisterConnection removes a Connectrion from the tracker
func UnregisterConnection(connID ConnectID) {
	delete(connectionTracker, connID)
}

///////////////////////////////////////////////////////////////////////////////
/****************************** ListenerTracker ******************************/
///////////////////////////////////////////////////////////////////////////////

// RegisterListener adds a Listener to the tracker
func RegisterListener(conn Connector) ConnectID {
	id := NewConnectID()
	listenerTracker[id] = conn
	return id
}

func UnregisterListener(connID ConnectID) {
	delete(listenerTracker, connID)
}

///////////////////////////////////////////////////////////////////////////////

func SetupConnectionCertificate(certPEMBlock []byte, keyPEMBlock []byte) (err error) {
	ConnectionCert, err = tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	ConnectionConfig = &tls.Config{Certificates: []tls.Certificate{ConnectionCert}, InsecureSkipVerify: true}
	return
}

///////////////////////////////////////////////////////////////////////////////
