package star

import (
	"crypto/tls"
	"net"
	"time"
)

type Socks5Proxy_Connector struct {
	Type       ConnectorType
	Address    string
	DstNode    NodeID
	DstAddress string
	Listener   *net.Listener
}

type Socks5Proxy_Connection struct {
	Type       ConnectorType
	NetConn    net.Conn
	TLSConn    *tls.Conn
	DstNode    NodeID
	DstAddress string
	ID         ConnectID
	StreamID   StreamID
}

func NewSocks5ProxyConnection(address string, t ConnectorType, dstNode NodeID, dstAddress string) {
}

func NewSocks5ProxyListener(address string, t ConnectorType, dstNode NodeID, dstAddress string) {
}

///////////////////////////////////////////////////////////////////////////////

type Socks5Proxy_Format_Version byte

const (
	Socks5Proxy_Format_Version_5 Socks5Proxy_Format_Version = 0x05
)

type Socks5Proxy_Format_Auth byte

const (
	Socks5Proxy_Format_Auth_NoAuth              Socks5Proxy_Format_Auth = 0x00
	Socks5Proxy_Format_Auth_NoAcceptableMethods Socks5Proxy_Format_Auth = 0xFF
)

type Socks5Proxy_Format_AddressType byte

const (
	Socks5Proxy_Format_AddressType_IPv4   Socks5Proxy_Format_AddressType = 0x01
	Socks5Proxy_Format_AddressType_Domain Socks5Proxy_Format_AddressType = 0x03
	Socks5Proxy_Format_AddressType_IPv6   Socks5Proxy_Format_AddressType = 0x04
)

type Socks5Proxy_Format_Command byte

const (
	Socks5Proxy_Format_Command_TCPStream Socks5Proxy_Format_Command = 0x01
	Socks5Proxy_Format_Command_TCPBind   Socks5Proxy_Format_Command = 0x02
	Socks5Proxy_Format_Command_UDP       Socks5Proxy_Format_Command = 0x03
)

type Socks5Proxy_Format_Status byte

const (
	Socks5Proxy_Format_Status_RequestGranted                     Socks5Proxy_Format_Status = 0x00
	Socks5Proxy_Format_Status_GeneralFailure                     Socks5Proxy_Format_Status = 0x01
	Socks5Proxy_Format_Status_ConnectionNotAllowedByRuleset      Socks5Proxy_Format_Status = 0x02
	Socks5Proxy_Format_Status_NetworkUnreachable                 Socks5Proxy_Format_Status = 0x03
	Socks5Proxy_Format_Status_HostUnreachable                    Socks5Proxy_Format_Status = 0x04
	Socks5Proxy_Format_Status_ConnectionRefusedByDestinationHost Socks5Proxy_Format_Status = 0x05
	Socks5Proxy_Format_Status_TTLExpired                         Socks5Proxy_Format_Status = 0x06
	Socks5Proxy_Format_Status_CommandNotSupported                Socks5Proxy_Format_Status = 0x07
	Socks5Proxy_Format_Status_ProtocolError                      Socks5Proxy_Format_Status = 0x07
	Socks5Proxy_Format_Status_AddressTypeNotSupported            Socks5Proxy_Format_Status = 0x08
)

///////////////////////////////////////////////////////////////////////////////
/*************************** Socks5Proxy Connector ***************************/
///////////////////////////////////////////////////////////////////////////////

func (connector *Socks5Proxy_Connector) Connect() (err error) {
	return
}

func (connector *Socks5Proxy_Connector) Listen() (err error) {
	return
}

func (connector *Socks5Proxy_Connector) Close() {
	(*connector.Listener).Close()
}

///////////////////////////////////////////////////////////////////////////////
/*************************** Socks5Proxy Connection **************************/
///////////////////////////////////////////////////////////////////////////////

func (c Socks5Proxy_Connection) Handle() {
}

func (c Socks5Proxy_Connection) MessageDuration() (d time.Duration) {
	return 1 * time.Minute
}

func (c Socks5Proxy_Connection) Send(msg Message) (err error) {
	return
}

func (c Socks5Proxy_Connection) Read(data []byte) (n int, err error) {
	if c.TLSConn != nil {
		n, err = c.TLSConn.Read(data)
	} else if c.NetConn != nil {
		n, err = c.NetConn.Read(data)
	}
	return
}

func (c Socks5Proxy_Connection) Write(data []byte) (n int, err error) {
	if c.TLSConn != nil {
		n, err = c.TLSConn.Write(data)
	} else if c.NetConn != nil {
		n, err = c.NetConn.Write(data)
	}
	return
}

func (c Socks5Proxy_Connection) Close() {
	if c.NetConn != nil {
		c.NetConn.Close()
	}
	if c.TLSConn != nil {
		c.TLSConn.Close()
	}
	UnregisterConnection(c.ID)
	ThisNodeInfo.RemoveConnector(c.ID)
}

func (c Socks5Proxy_Connection) DataSize() (s int) {
	return 65535
}

///////////////////////////////////////////////////////////////////////////////

func ProcessMessageSocks5Proxy(msg *Message) {
	var reqMsg MessageSocks5ProxyRequest

	err := msg.GobDecodeMessage(&reqMsg)
	if err != nil {
		return
	}

	go NewSocks5ProxyConnection(reqMsg.SrcAddress, ConnectorType_PortForwardTCP, reqMsg.DstNode, reqMsg.DstAddress)
}
