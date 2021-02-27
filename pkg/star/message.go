package star

import (
	"crypto"
	"crypto/rand"
	"time"
)

// The Message type serves as the overarching data structure for STAR communications.
type Message struct {
	ID          MessageID
	Destination NodeID
	Meta        MessageMeta
	Type        MessageType
	Content     MessageContent
}

//////////////////////////////////////////////////////////////////////////////
/******************************** MessageID *********************************/
//////////////////////////////////////////////////////////////////////////////

// The MessageID type is a fixed-length byte array which should serve as a UUID
// for each Message
type MessageID [25]byte

// NewMessageID creates a new MessageID type filled with random bytes
func NewMessageID() (id MessageID) {
	rand.Read([]byte(id[:]))
	return
}

// Formats a MessageID into a print-friendly string
func (id MessageID) String() string {
	return SqrtedString(id[:], ":")
}

//////////////////////////////////////////////////////////////////////////////
/******************************* MessageMeta ********************************/
//////////////////////////////////////////////////////////////////////////////

// The MessageMeta type tracks metadata of STAR communications, largely for
// timestamp and tracking purposes, which are not relevant to the communication
type MessageMeta struct {
	RequestSent      time.Time
	RequestReceived  time.Time
	HandlingStarted  time.Time
	HandlingStopped  time.Time
	ResponseSent     time.Time
	ResponseReceived time.Time
}

//////////////////////////////////////////////////////////////////////////////
/******************************* MessageType ********************************/
//////////////////////////////////////////////////////////////////////////////

// The MessageType type indicates the type of Message
type MessageType byte

const (
	// MessageTypeError identifies the Message as being in relation to an
	// error that occurred on the Agent and is being relayed to the Terminal
	// user.
	MessageTypeError MessageType = iota + 1

	// MessageTypeSync identifies the Message as being a synchronization
	// request from the Terminal to Agents. The Message will be forwarded to
	// all neighboring Agents.
	MessageTypeSync

	// MessageTypeKillSwitch identifies the Message as being a self-destruct
	// request from the Terminal to Agents. The Message will *only* be
	// forwarded if the correct confirmation code is passed.
	MessageTypeKillSwitch

	// MessageTypeCommand identifies the Message as being related to the
	// execution or results of a command.
	MessageTypeCommand
)

///////////////////////////////////////////////////////////////////////////////
/****************************** MessageContent *******************************/
///////////////////////////////////////////////////////////////////////////////

// The MessageContent type is a placeholder for interfaces related to the
// different types of messages.
type MessageContent []byte

// The MessageContentRaw type enforces the handling of MessageContent that is
// not encrypted.
type MessageContentRaw MessageContent

// The MessageContentEncrypted type enforces the handling of MessageContent
// that has been encrypted.
type MessageContentEncrypted MessageContent

type messagewrapper interface {
	wrap(crypto.PublicKey) MessageContentEncrypted
	unwrap(crypto.PrivateKey) MessageContentRaw
}
