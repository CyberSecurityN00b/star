package star

import (
	"encoding/json"
	"sync"
	"time"
)

// The Message type serves as the overarching data structure for STAR messages.
type Message struct {
	ID           MessageID   `json:"id"`
	Destination  NodeID      `json:"destination"`
	Meta         MessageMeta `json:"meta"`
	Type         MessageType `json:"type"`
	RequestData  []byte      `json:"request-data"`
	ResponseData []byte      `json:"response-data"`
}

// MessageTracker is used by STAR Nodes to track what Messages have been
// handled, whether processed locally or passed on to adjacent Nodes
type MessageTracker struct {
	IDs   []MessageID
	Mutex *sync.Mutex
}

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
/******************************* MessageMeta ********************************/
//////////////////////////////////////////////////////////////////////////////

// The MessageMeta type tracks metadata of STAR communications, largely for
// timestamp and tracking purposes, which are not relevant to the communication
type MessageMeta struct {
	RequestSent       time.Time `json:"request-sent"`
	RequestReceived   time.Time `json:"request-received"`
	ProcessingStarted time.Time `json:"processing-started"`
	ProcessingStopped time.Time `json:"processing-stopped"`
	ResponseSent      time.Time `json:"response-sent"`
	ResponseReceived  time.Time `json:"response-received"`
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
	MessageTypeError MessageType = 0x01

	// MessageTypeSync identifies the Message as being a synchronization
	// request from the Terminal to Agents. The Message will be forwarded to
	// all neighboring Agents.
	//
	// REQUESTS = Terminal
	//
	// RESPONDS = Agent
	MessageTypeSync MessageType = 0x02

	// MessageTypeKillSwitch identifies the Message as being a self-destruct
	// request from the Terminal to Agents. The Message will *only* be
	// forwarded if the correct confirmation code is passed.
	//
	// REQUESTS = Terminal
	//
	// RESPONDS = N/A
	MessageTypeKillSwitch MessageType = 0x04

	// MessageTypeCommand identifies the Message as being related to the
	// execution or results of a command.
	//
	// REQUESTS = Terminal
	//
	// RESPONDS = Agent
	MessageTypeCommand MessageType = 0x08

	// MessageTypeFileUpload identifies the Message as being related to the
	// transfer of a file from a Terminal to an Agent.
	//
	// REQUESTS = Terminal
	//
	// RESPONDS = Agent
	MessageTypeFileUpload MessageType = 0x16

	// MessageTypeFileDownload identifies the Message as being related to the
	// transfer of a file from an Agent to a Terminal.
	//
	// REQUESTS = Terminal
	//
	// RESPONDS = Agent
	MessageTypeFileDownload MessageType = 0x32

	// MessageTypeStream identifies the Message as being related to
	// bi-directional interactive traffic (i.e., a command prompt)
	//
	// REQUESTS = Agent (Provides output, seeks input)
	//
	// RESPONDS = Terminal (Provides input)
	MessageTypeStream MessageType = 0x64
)

///////////////////////////////////////////////////////////////////////////////
/******************************* MessageData *********************************/
///////////////////////////////////////////////////////////////////////////////

// Process handles a Message by identifying which secondary process function
// should be handling it
func (msg Message) Process() {
	switch msg.Type {
	case MessageTypeCommand:

	}
}

///////////////////////////////////////////////////////////////////////////////
/****************************** ProcessCommand *******************************/
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

// ProcessCommandRequest is run by an Agent Node in order to handle the values
// passed by MessageCommandRequest.
func (msg Message) ProcessCommandRequest() {

}

// ProcessCommandResponse is run by a Terminal Node in order to handle the
// output and/or exit status from a completed command.
func (msg Message) ProcessCommandResponse() {

}

///////////////////////////////////////////////////////////////////////////////
/******************************* ProcessError ********************************/
///////////////////////////////////////////////////////////////////////////////

// MessageError holds values related to any error messages returned by an
// Agent Node. Termainal Nodes *should not* send error messages to Agent Nodes.
type MessageError struct {
}

// ProcessErrorResponse is run by a Terminal Node in order to handle any error
// messages.
func (msg Message) ProcessErrorResponse() {

}

///////////////////////////////////////////////////////////////////////////////
/***************************** ProcessKillSwitch *****************************/
///////////////////////////////////////////////////////////////////////////////

type MessageKillSwitch struct {
}

func (msg Message) ProcessKillSwitchRequest() {

}

func (msg Message) ProcessKillSwitchResponse() {

}

///////////////////////////////////////////////////////////////////////////////
/******************************* ProcessSync *********************************/
///////////////////////////////////////////////////////////////////////////////

type MessageSync struct {
}

func (msg Message) ProcessSyncRequest() {
}

func (msg Message) ProcessSyncResponse() {
}

///////////////////////////////////////////////////////////////////////////////
/**************************** ProcessFileUpload ******************************/
///////////////////////////////////////////////////////////////////////////////

type MessageFileUpload struct {
}

func (msg Message) ProcessFileUploadRequest() {

}

func (msg Message) ProcessFileUploadREsponse() {

}

///////////////////////////////////////////////////////////////////////////////
/*************************** ProcessFileDownload *****************************/
///////////////////////////////////////////////////////////////////////////////

type MessageFileDownload struct {
}

func (msg Message) ProcessFileDownloadRequest() {

}

func (msg Message) ProcessFileDownloadResponse() {

}

///////////////////////////////////////////////////////////////////////////////
/****************************** ProcessStream ********************************/
///////////////////////////////////////////////////////////////////////////////

type MessageProcessStream struct {
}

func (msg Message) ProcessStreamRequest() {

}

func (msg Message) ProcessStreamResponse() {

}

///////////////////////////////////////////////////////////////////////////////
/*************************** MessagesTrackerRemove ***************************/
///////////////////////////////////////////////////////////////////////////////

// MessageTrackerTrack tracks a MessageID in the MessagesTracker for a
// specified duration of time. Durations should be specific to each type of
// connection (i.e., a slower connection using a mailing platform may have a
// longer duration than a network based connection).
func MessageTrackerRemove(id MessageID, tracker *MessageTracker, d time.Duration) {
	// Lock to make sure nothing else is accessing the tracker
	tracker.Mutex.Lock()
	defer tracker.Mutex.Unlock()

	// Add the MessageID to the tracker
	tracker.IDs = append(tracker.IDs, id)

	time.AfterFunc(d, func() {
		// Lock to make sure only one goroutine can access at a time
		tracker.Mutex.Lock()
		defer tracker.Mutex.Unlock()

		// TODO: Remove ID from the tracker
	})
}
