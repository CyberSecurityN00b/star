package star

import (
	"encoding/json"
	"time"
)

// The Message type serves as the overarching data structure for STAR messages.
type Message struct {
	ID           MessageID   `json:"id"`
	Source       NodeID      `json:"source"`
	Destination  NodeID      `json:"destination"`
	Type         MessageType `json:"type"`
	RequestData  []byte      `json:"request-data"`
	ResponseData []byte      `json:"response-data"`
}

var messageTracker map[MessageID]bool

///////////////////////////////////////////////////////////////////////////////
/******************************** NewMessage *********************************/
///////////////////////////////////////////////////////////////////////////////

// NewMessage creates and sets up a bare-bones STAR Message
func NewMessage() (msg Message) {
	NewUID([]byte(msg.ID[:]))
	return
}

//////////////////////////////////////////////////////////////////////////////
/******************************** MessageID *********************************/
//////////////////////////////////////////////////////////////////////////////

// The MessageID type is a fixed-length byte array which should serve as a UUID
// for each Message
type MessageID [16]byte

// Formats a MessageID into a print-friendly string
func (id MessageID) String() string {
	return SqrtedString(id[:], ":")
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
	//
	// REQUESTS = N/A
	//
	// RESPONDS = Agent
	MessageTypeError MessageType = iota + 1

	// MessageTypeSync identifies the Message as being a synchronization
	// request from the Terminal to Agents. The Message will be forwarded to
	// all neighboring Agents.
	//
	// REQUESTS = Terminal
	//
	// RESPONDS = Agent
	MessageTypeSync

	// MessageTypeKillSwitch identifies the Message as being a self-destruct
	// request from the Terminal to Agents. The Message will *only* be
	// forwarded if the correct confirmation code is passed.
	//
	// REQUESTS = Terminal
	//
	// RESPONDS = N/A
	MessageTypeKillSwitch

	// MessageTypeCommand identifies the Message as being related to the
	// execution or results of a command.
	//
	// REQUESTS = Terminal
	//
	// RESPONDS = Agent
	MessageTypeCommand

	// MessageTypeFileUpload identifies the Message as being related to the
	// transfer of a file from a Terminal to an Agent.
	//
	// REQUESTS = Terminal
	//
	// RESPONDS = Agent
	MessageTypeFileUpload

	// MessageTypeFileDownload identifies the Message as being related to the
	// transfer of a file from an Agent to a Terminal.
	//
	// REQUESTS = Terminal
	//
	// RESPONDS = Agent
	MessageTypeFileDownload

	// MessageTypeStream identifies the Message as being related to
	// bi-directional interactive traffic (i.e., a command prompt)
	//
	// REQUESTS = Agent (Provides output, seeks input)
	//
	// RESPONDS = Terminal (Provides input)
	MessageTypeStream

	// MessageTypeBind indentifies the Message as being related to
	// the creation of a Listener on an agent
	//
	// REQUESTS = Terminal
	//
	// RESPONDS = Agent
	MessageTypeBind

	// MessageTypeConnect identifies the Message as being related to
	// the creation of a Connection on an agent
	//
	// REQUESTS = Terminal
	//
	// RESPONDS = Agent
	MessageTypeConnect
)

func (msg Message) Process() {
	if msg.Type == MessageTypeStream {
		msg.HandleStream()
	}
	ThisNode.MessageProcesser(&msg)
}

///////////////////////////////////////////////////////////////////////////////
/****************************** MessageCommand *******************************/
///////////////////////////////////////////////////////////////////////////////

// MessageCommandRequest contains the necessary parameters needed by an Agent
// node to run a command.
type MessageCommandRequest struct {
	Command string `json:"cmd"`
}

// MessageCommandResponse contains information related to the finalized
// response of a command having finished running. It may contain text output,
// but such outptu does not necessarily reflect the entirety of the commands
// output.
type MessageCommandResponse struct {
	ExitStatus int `json:"exit-status"`
}

// NewMessageCommand creates a new Message of type MessageTypeCommand
func NewMessageCommand(cmd string) (msg Message) {
	msg = NewMessage()
	msg.Type = MessageTypeCommand

	d := new(MessageCommandRequest)
	j, _ := json.Marshal(d)

	msg.RequestData = j

	return
}

///////////////////////////////////////////////////////////////////////////////
/******************************* MessageError ********************************/
///////////////////////////////////////////////////////////////////////////////

// MessageError holds values related to any error messages returned by an
// Agent Node. Termainal Nodes *should not* send error messages to Agent Nodes.
type MessageErrorResponse struct {
}

///////////////////////////////////////////////////////////////////////////////
/***************************** MessageKillSwitch *****************************/
///////////////////////////////////////////////////////////////////////////////

type MessageKillSwitchRequest struct {
}

///////////////////////////////////////////////////////////////////////////////
/******************************* MessageSync *********************************/
///////////////////////////////////////////////////////////////////////////////

type MessageSyncResponse struct {
}

///////////////////////////////////////////////////////////////////////////////
/**************************** MessageFileUpload ******************************/
///////////////////////////////////////////////////////////////////////////////

type MessageFileUploadRequest struct {
}

type MessageFileUploadResponse struct {
}

///////////////////////////////////////////////////////////////////////////////
/*************************** MessageFileDownload *****************************/
///////////////////////////////////////////////////////////////////////////////

type MessageFileDownloadRequest struct {
}

type MessageFileDownloadResponse struct {
}

///////////////////////////////////////////////////////////////////////////////
/******************************* MessageBind *********************************/
///////////////////////////////////////////////////////////////////////////////

type MessageBindRequest struct {
	Type ConnectorType `json:"type"`
	Data []byte        `json:"data"`
}

type MessageBindResponse struct {
}

///////////////////////////////////////////////////////////////////////////////
/****************************** MessageConnect *******************************/
///////////////////////////////////////////////////////////////////////////////

type MessageConnectRequest struct {
}

type MessageConnectResponse struct {
}

///////////////////////////////////////////////////////////////////////////////
/****************************** Message Tracker ******************************/
///////////////////////////////////////////////////////////////////////////////

// TrackMessage tracks a MessageID in the MessagesTracker for a
// specified duration of time. Durations should be specific to each type of
// connection (i.e., a slower connection using a mailing platform may have a
// longer duration than a network based connection).
func TrackMessage(id MessageID, d time.Duration) {
	// Add the MessageID to the tracker
	messageTracker[id] = true

	time.AfterFunc(d, func() {
		delete(messageTracker, id)
	})
}

///////////////////////////////////////////////////////////////////////////////
/***************************** Encrypt / Decrypt *****************************/
///////////////////////////////////////////////////////////////////////////////

func (msg Message) Encrypt() {
	// If already encrypted, do nothing

	//TODO: Encrypt message
}

func (msg Message) Decrypt() {
	// If already decrypted, do nothing
	//TODO: Decrypt message
}

///////////////////////////////////////////////////////////////////////////////
/************************************ Send ***********************************/
///////////////////////////////////////////////////////////////////////////////

func (msg Message) Send(src ConnectID) {
	msg.Encrypt()
	dst, exists := destinationTracker[msg.Destination]

	if msg.Destination.IsBroadcastNodeID() || !exists {
		for conn := range connectionTracker {
			if conn != src {
				go connectionTracker[conn].Send(msg)
			}
		}
	} else {
		go connectionTracker[dst].Send(msg)
	}
}

///////////////////////////////////////////////////////////////////////////////
/*********************************** Handle **********************************/
///////////////////////////////////////////////////////////////////////////////

func (msg Message) Handle(src ConnectID) {
	// If part of a stream, offload to the functions in stream.go
	if msg.Type == MessageTypeStream {
		msg.HandleStream()
		return
	}

	// Have we already received this Message before?
	if messageTracker[msg.ID] {
		return
	}
	TrackMessage(msg.ID, connectionTracker[src].MessageDuration())

	// Is the MessageType supposed to be broadcasted or sent to an individual?
	if msg.Destination.IsBroadcastNodeID() {
		// Pass it along first and then process
		msg.Send(src)
		msg.Process()
	} else if msg.Destination == ThisNode.ID {
		msg.Process()
	} else {
		msg.Send(src)
	}
}
