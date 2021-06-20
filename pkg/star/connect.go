package star

import (
	"crypto/tls"
	"crypto/x509"
	"sync"
	"time"
)

// The Connection interface provides the standard functions for using STAR node communications.
type Connection interface {
	Handle()
	MessageDuration() time.Duration
	Send(msg Message) (err error)
	Read(data []byte) (n int, err error)
	Write(data []byte) (n int, err error)
	Close()
	DataSize() (s int)
}

// The Connector interface provides the standard functions for creating STAR node connections.
type Connector interface {
	Connect() (err error)
	Listen() (err error)
	Close()
}

var connectionTracker map[ConnectID]Connection
var connectionTrackerMutex *sync.Mutex

var listenerTracker map[ConnectID]Connector
var listenerTrackerMutex *sync.Mutex

var destinationTracker map[NodeID]ConnectID
var destinationTrackerMutex *sync.Mutex

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

func (id ConnectID) IsNone() bool {
	var c ConnectID
	return id == c
}

// Formats a ConnectID into a print-friendly string
func (id ConnectID) String() string {
	return SqrtedString(id[:], ".")
}

///////////////////////////////////////////////////////////////////////////////
/******************************* ConnectorType *******************************/
///////////////////////////////////////////////////////////////////////////////

type ConnectorType byte

const (
	// ConnectorType_TCPTLS is used by the terminal to tell an agent that a TCP
	// connector should be used when requesting a bind or a connect. This is the
	// required means of connections between S.T.A.R. nodes.
	ConnectorType_TCPTLS ConnectorType = iota + 1

	ConnectorType_ShellTCP
	ConnectorType_ShellTCPTLS
	ConnectorType_ShellUDP
	ConnectorType_ShellUDPTLS

	ConnectorType_FileServerTCP
	ConnectorType_FileServerTCPTLS
	ConnectorType_FileServerUDP
	ConnectorType_FileServerUDPTLS

	ConnectorType_PortForwardTCP
	ConnectorType_PortForwardUDP

	ConnectorType_Socks5ProxyTCP
	ConnectorType_Socks5ProxyUDP
)

///////////////////////////////////////////////////////////////////////////////
/***************************** ConnectionTracker *****************************/
///////////////////////////////////////////////////////////////////////////////

// RegisterConnection adds a Connection to the tracker
func RegisterConnection(conn Connection) ConnectID {
	connectionTrackerMutex.Lock()
	defer connectionTrackerMutex.Unlock()

	id := NewConnectID()
	connectionTracker[id] = conn
	return id
}

func GetConnectionById(connID ConnectID) (c Connection, ok bool) {
	connectionTrackerMutex.Lock()
	defer connectionTrackerMutex.Unlock()

	c, ok = connectionTracker[connID]
	return
}

func GetConnectionByString(connID string) (c Connection, ok bool) {
	connectionTrackerMutex.Lock()
	defer connectionTrackerMutex.Unlock()

	for i := range connectionTracker {
		if i.String() == connID {
			c, ok = connectionTracker[i]
		}
	}
	return
}

// UnregisterConnection removes a Connection from the tracker
func UnregisterConnection(connID ConnectID) {
	connectionTrackerMutex.Lock()
	defer connectionTrackerMutex.Unlock()

	delete(connectionTracker, connID)
}

///////////////////////////////////////////////////////////////////////////////
/****************************** ListenerTracker ******************************/
///////////////////////////////////////////////////////////////////////////////

// RegisterListener adds a Listener to the tracker
func RegisterListener(conn Connector) ConnectID {
	listenerTrackerMutex.Lock()
	defer listenerTrackerMutex.Unlock()

	id := NewConnectID()
	listenerTracker[id] = conn
	return id
}

func GetListener(connID ConnectID) (c Connector, ok bool) {
	listenerTrackerMutex.Lock()
	defer listenerTrackerMutex.Unlock()

	c, ok = listenerTracker[connID]
	return
}

func UnregisterListener(connID ConnectID) {
	listenerTrackerMutex.Lock()
	defer listenerTrackerMutex.Unlock()

	delete(listenerTracker, connID)
}

///////////////////////////////////////////////////////////////////////////////

func SetupConnectionCertificate(certPEMBlock []byte, keyPEMBlock []byte) (err error) {
	pool := x509.NewCertPool()
	ConnectionCert, err = tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	pool.AppendCertsFromPEM(certPEMBlock)
	//TODO: Change below
	ConnectionConfig = &tls.Config{Certificates: []tls.Certificate{ConnectionCert}, InsecureSkipVerify: true} //, InsecureSkipVerify: false, ClientAuth: tls.RequireAndVerifyClientCert, RootCAs: pool, ClientCAs: pool, ServerName: "star:node"}
	return
}

///////////////////////////////////////////////////////////////////////////////
