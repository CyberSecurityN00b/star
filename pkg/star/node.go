package star

import (
	"crypto"
)

// The Node type serves as the overarching data structure for tracking STAR nodes.
type Node struct {
	ID             NodeID           `json:"id"`
	Type           NodeType         `json:"type"`
	Neighbors      []NodeID         `json:"neighbors"`
	PublicKey      crypto.PublicKey `json:"publickey"`
	PrivateKey     crypto.PrivateKey
	MessageTracker MessageTracker
}

///////////////////////////////////////////////////////////////////////////////
/********************************* NewNode ***********************************/
///////////////////////////////////////////////////////////////////////////////

// NewNode creates and sets up a new STAR Node
func NewNode(t NodeType) (node Node) {
	NewUID([]byte(node.ID[:]))
	node.Type = t
	return
}

///////////////////////////////////////////////////////////////////////////////
/********************************** NodeID ***********************************/
///////////////////////////////////////////////////////////////////////////////

// The NodeID type is a fixed-length byte array which should serve as a UUID
// for each Node
type NodeID [9]byte

// Formats a NodeID into a print-friendly string
func (id NodeID) String() string {
	return SqrtedString(id[:], "-")
}

///////////////////////////////////////////////////////////////////////////////
/********************************* NodeType **********************************/
///////////////////////////////////////////////////////////////////////////////

// NodeType determines what kind of STAR Node we are dealing with (e.g., a
// terminal or an agent).
type NodeType byte

const (
	// NodeTypeTerminal identifies the STAR Node as being a Terminal Node
	NodeTypeTerminal NodeType = 0x01

	// NodeTypeAgent identifies the STAR Node as being an Agent Node
	NodeTypeAgent NodeType = 0x02

	// NodeTypeRunScript is a psudeotype that is used to identify the commands
	// which are provided as part of a run script
	NodeTypeRunScript NodeType = 0x04

	// NodeTypeShell is a psuedonode that is used when connections from
	// external shells (i.e., netcat) are detected in an listener
	NodeTypeShell NodeType = 0x08
)

///////////////////////////////////////////////////////////////////////////////
/********************************** Message **********************************/
///////////////////////////////////////////////////////////////////////////////

// SendMessage handles sending a Message to a Node, to include encrypting it
func (node Node) SendMessage(msg Message) {
	//TODO: Encrypt and send over connection
}

// ProcessMessage handles a Message sent from a Node, to include decrypting it
func (node Node) ProcessMessage(msg Message) {
	//TODO: Decrypt and handle message
}
