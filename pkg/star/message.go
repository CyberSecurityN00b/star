package star

import (
	"fmt"
	"time"
)

// The Message type serves as the overarching data structure for STAR messages.
type Message struct {
	ID          MessageID
	Source      NodeID
	Destination NodeID
	Type        MessageType
	Data        []byte
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
	MessageTypeError MessageType = iota + 1

	// MessageTypeSyncRequest identifies the Message as being a synchronization
	// request from the Terminal to Agents. The Message will be forwarded to
	// all neighboring Agents.
	MessageTypeSyncRequest

	// MessageTypeSyncResponse identifies the Message as being a
	// synchronization response from Agents to the Terminal. The Message
	// will be forwarded to all neighboring Agents.
	MessageTypeSyncResponse

	// MessageTypeKillSwitch identifies the Message as being a self-destruct
	// request from the Terminal to Agents. The Message will *only* be
	// forwarded if the correct confirmation code is passed.
	MessageTypeKillSwitch

	// MessageTypeCommandRequest identifies the Message as being related to the
	// execution of a command.
	MessageTypeCommandRequest

	// MessageTypeCommandResponse identifies the Message as being related to the
	// response of a command.
	MessageTypeCommandResponse

	// MessageTypeFileUpload identifies the Message as being related to the
	// transfer of a file from a Terminal to an Agent.
	MessageTypeFileUpload

	// MessageTypeFileDownload identifies the Message as being related to the
	// transfer of a file from an Agent to a Terminal.
	MessageTypeFileDownload

	// MessageTypeStream identifies the Message as being related to
	// bi-directional interactive traffic (i.e., a command prompt)
	MessageTypeStream

	// MessageTypeBind indentifies the Message as being related to
	// the creation of a Listener on an agent
	MessageTypeBind

	// MessageTypeConnect identifies the Message as being related to
	// the creation of a Connection on an agent
	MessageTypeConnect

	// MessageTypeHello identifies the Message as being related to a
	// new node joining the constellation
	MessageTypeHello

	// MessageTypeNewBind identifies the message as being related to
	// the successful creation of a new listener. This is separate
	// from the MessageTypeBind Response in that this is sent to the
	// broadcast NodeID, so all terminals will be aware.
	MessageTypeNewBind

	// MessageTypeNewConnection identifies the message as being related to
	// the successful creation of a new connection. This is separate from the
	// MessageTypeConnection Response in that this is sent to the broadcast
	// NodeID, so all terminals will be aware.
	MessageTypeNewConnection

	// MessageTypeTerminateAgent identifies the message as being related to
	// the termination request of an agent.
	MessageTypeTerminateAgent
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
	Command string
}

// MessageCommandResponse contains information related to the finalized
// response of a command having finished running. It may contain text output,
// but such outptu does not necessarily reflect the entirety of the commands
// output.
type MessageCommandResponse struct {
	ExitStatus int
}

// NewMessageCommand creates a new Message of type MessageTypeCommandRequest
func NewMessageCommand(cmd string) (msg Message) {
	msg = NewMessage()
	msg.Type = MessageTypeCommandRequest
	msg.Data = GobEncode(MessageCommandRequest{Command: cmd})

	return
}

// NewMessageCommandResponse creates a new Message for Command Response
func NewMessageCommandResponse(status int) (msg Message) {
	msg = NewMessage()
	msg.Type = MessageTypeCommandResponse
	msg.Data = GobEncode(MessageCommandResponse{ExitStatus: status})

	return
}

///////////////////////////////////////////////////////////////////////////////
/******************************* MessageError ********************************/
///////////////////////////////////////////////////////////////////////////////

// MessageError holds values related to any error messages returned by an
// Agent Node. Termainal Nodes *should not* send error messages to Agent Nodes.
type MessageErrorResponse struct {
	Type    MessageErrorResponseType
	Context string
}

type MessageErrorResponseType byte

const (
	MessageErrorResponseTypeX509KeyPair MessageErrorResponseType = iota + 1
	MessageErrorResponseTypeConnectionLost
	MessageErrorResponseTypeBindDropped
	MessageErrorResponseTypeGobDecodeError
	MessageErrorResponseTypeAgentExitSignal
)

func NewMessageError(errorType MessageErrorResponseType, context string) (msg Message) {
	msg = NewMessage()
	msg.Type = MessageTypeError
	msg.Data = GobEncode(MessageErrorResponse{Type: errorType, Context: context})

	return
}

///////////////////////////////////////////////////////////////////////////////
/***************************** MessageKillSwitch *****************************/
///////////////////////////////////////////////////////////////////////////////

type MessageKillSwitchRequest struct {
}

func NewMessageKillSwitch() (msg Message) {
	msg = NewMessage()
	msg.Type = MessageTypeKillSwitch
	msg.Data = GobEncode(MessageKillSwitchRequest{})

	return
}

///////////////////////////////////////////////////////////////////////////////
/******************************* MessageSync *********************************/
///////////////////////////////////////////////////////////////////////////////

type MessageSyncRequest struct {
}

type MessageSyncResponse struct {
	Node Node
	Info NodeInfo
}

func NewMessageSyncRequest() (msg Message) {
	msg = NewMessage()
	msg.Type = MessageTypeSyncRequest
	msg.Data = GobEncode(MessageSyncRequest{})

	return
}

func NewMessageSyncResponse() (msg Message) {
	msg = NewMessage()
	msg.Type = MessageTypeSyncResponse
	ThisNodeInfo.Update()
	msg.Data = GobEncode(MessageSyncResponse{Node: ThisNode, Info: ThisNodeInfo})

	return
}

///////////////////////////////////////////////////////////////////////////////
/**************************** MessageFileUpload ******************************/
///////////////////////////////////////////////////////////////////////////////

type MessageFileUpload struct {
}

func NewMessageFileUpload() (msg Message) {
	msg = NewMessage()
	msg.Type = MessageTypeFileUpload
	msg.Data = GobEncode(MessageFileUpload{})

	return
}

///////////////////////////////////////////////////////////////////////////////
/*************************** MessageFileDownload *****************************/
///////////////////////////////////////////////////////////////////////////////

type MessageFileDownload struct {
}

func NewMessageFileDownload() (msg Message) {
	msg = NewMessage()
	msg.Type = MessageTypeFileDownload
	msg.Data = GobEncode(MessageFileDownload{})

	return
}

///////////////////////////////////////////////////////////////////////////////
/******************************* MessageBind *********************************/
///////////////////////////////////////////////////////////////////////////////

type MessageBindRequest struct {
	Type ConnectorType
	Data []byte
}

func NewMessageBind(t ConnectorType, data []byte) (msg Message) {
	msg = NewMessage()
	msg.Type = MessageTypeBind
	msg.Data = GobEncode(MessageBindRequest{Type: t, Data: data})

	return
}

///////////////////////////////////////////////////////////////////////////////
/****************************** MessageConnect *******************************/
///////////////////////////////////////////////////////////////////////////////

type MessageConnectRequest struct {
	Type ConnectorType
	Data []byte
}

func NewMessageConnect(t ConnectorType, data []byte) (msg Message) {
	msg = NewMessage()
	msg.Type = MessageTypeConnect
	msg.Data = GobEncode(MessageConnectRequest{Type: t, Data: data})

	return
}

///////////////////////////////////////////////////////////////////////////////
/******************************* MessageHello ********************************/
///////////////////////////////////////////////////////////////////////////////
type MessageHelloResponse struct {
	Node Node
	Info NodeInfo
}

func NewMessageHello() (msg Message) {
	msg = NewMessage()
	msg.Type = MessageTypeHello
	msg.Data = GobEncode(MessageHelloResponse{Node: ThisNode, Info: ThisNodeInfo})

	return
}

///////////////////////////////////////////////////////////////////////////////
/****************************** MessageNewBind *******************************/
///////////////////////////////////////////////////////////////////////////////
type MessageNewBindResponse struct {
	Address string
}

func NewMessageNewBind(address string) (msg Message) {
	msg = NewMessage()
	msg.Type = MessageTypeNewBind
	msg.Data = GobEncode(MessageNewBindResponse{Address: address})

	return
}

///////////////////////////////////////////////////////////////////////////////
/*************************** MessageNewConnection ****************************/
///////////////////////////////////////////////////////////////////////////////
type MessageNewConnectionResponse struct {
	Address string
}

func NewMessageNewConnection(address string) (msg Message) {
	msg = NewMessage()
	msg.Type = MessageTypeNewConnection
	msg.Data = GobEncode(MessageNewConnectionResponse{Address: address})

	return
}

///////////////////////////////////////////////////////////////////////////////
/*************************** MessageTerminateAgent ***************************/
///////////////////////////////////////////////////////////////////////////////
type MessageTerminateAgentRequest struct {
	Cleanup bool
}

func NewMessageTerminateAgent(cleanup bool) (msg Message) {
	msg = NewMessage()
	msg.Type = MessageTypeTerminateAgent
	msg.Data = GobEncode(MessageTerminateAgentRequest{Cleanup: cleanup})

	return
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
/************************************ Send ***********************************/
///////////////////////////////////////////////////////////////////////////////

func (msg Message) Send(src ConnectID) {
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
	//DEBUG
	fmt.Printf("DEBUG: Connection %s with %b messageType\n", src, msg.Type)

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
