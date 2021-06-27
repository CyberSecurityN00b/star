package star

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Stream struct {
	ID   StreamID
	Data []byte
}

type StreamMeta struct {
	ID           StreamID
	remoteNodeID NodeID
	Type         StreamType
	// Context is the command to run for command execution, and agent's file system file path/name for upload/download
	Context       string
	writelock     *sync.Mutex
	writelocked   bool
	stdin         io.WriteCloser
	funcwriter    func([]byte)
	funccloser    func(StreamID)
	functerminate func()
}

type StreamTakeover struct {
	ID StreamID
}

var activeStreams map[StreamID]*StreamMeta
var activeStreamsMutex *sync.Mutex

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

// NewStreamMeta is called by the terminal to setup a stream meta
func NewStreamMeta(t StreamType, dstID NodeID, context string, writer func(data []byte), closer func(s StreamID)) (meta *StreamMeta) {
	meta = &StreamMeta{}
	NewUID([]byte(meta.ID[:]))
	meta.Type = t
	meta.remoteNodeID = dstID
	meta.Context = context
	meta.writelock = &sync.Mutex{}
	meta.funcwriter = writer
	meta.funccloser = closer

	NewActiveStream(meta)

	meta.SendMessageCreate()

	return
}

// NewStreamMetaMirror is called by the agent to mirror/setup a stream meta
func NewStreamMetaMirror(metaOrig *StreamMeta, dstID NodeID) (metaNew *StreamMeta) {
	metaNew = &StreamMeta{}
	metaNew.ID = metaOrig.ID
	metaNew.Type = metaOrig.Type
	metaNew.remoteNodeID = dstID
	metaNew.Context = metaOrig.Context
	metaNew.writelock = &sync.Mutex{}
	metaNew.funcwriter = nil
	metaNew.funccloser = nil

	NewActiveStream(metaNew)
	NewMessageSyncResponse().Send(ConnectID{})

	return
}

func NewStreamMetaCommand(dstID NodeID, context string, writer func(data []byte), closer func(s StreamID)) (meta *StreamMeta) {
	meta = NewStreamMeta(StreamTypeCommand, dstID, context, writer, closer)
	return
}

func NewStreamMetaShell(dstID NodeID, context string, writer func(data []byte), closer func(s StreamID)) (meta *StreamMeta) {
	meta = NewStreamMeta(StreamTypeShell, dstID, context, writer, closer)
	return
}

func NewStreamMetaDownload(dstID NodeID, context string, writer func(data []byte), closer func(s StreamID)) (meta *StreamMeta) {
	meta = NewStreamMeta(StreamTypeFileDownload, dstID, context, writer, closer)
	return
}

func NewStreamMetaUpload(dstID NodeID, context string, writer func(data []byte), closer func(s StreamID)) (meta *StreamMeta) {
	meta = NewStreamMeta(StreamTypeFileUpload, dstID, context, writer, closer)
	return
}

func NewStreamMetaFileServer(dstID NodeID, context string, writer func(data []byte), closer func(s StreamID)) (meta *StreamMeta) {
	meta = NewStreamMeta(StreamTypeFileServer, dstID, context, writer, closer)
	return
}

func NewStreamMetaPortForwardingTCP(dstID NodeID, context string, writer func(data []byte), closer func(s StreamID)) (meta *StreamMeta) {
	meta = NewStreamMeta(StreamTypePortForwardTCP, dstID, context, writer, closer)
	return
}

func NewStreamMetaPortForwardingUDP(dstID NodeID, context string, writer func(data []byte), closer func(s StreamID)) (meta *StreamMeta) {
	meta = NewStreamMeta(StreamTypePortForwardUDP, dstID, context, writer, closer)
	return
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

func (meta *StreamMeta) SendMessageCreate() {
	msg := NewMessage()
	msg.Type = MessageTypeStreamCreate
	msg.Data = GobEncode(meta)
	msg.Destination = meta.remoteNodeID
	msg.Source = ThisNode.ID
	msg.Send(ConnectID{})

	meta.writelock.Lock()
	meta.writelocked = true
}

func (meta *StreamMeta) SendMessageAcknowledge() {
	msg := NewMessage()
	msg.Type = MessageTypeStreamAcknowledge
	msg.Data = GobEncode(&Stream{ID: meta.ID})
	msg.Destination = meta.remoteNodeID
	msg.Source = ThisNode.ID
	msg.Send(ConnectID{})
}

func (meta *StreamMeta) SendMessageClose() {
	msg := NewMessage()
	msg.Type = MessageTypeStreamClose
	msg.Data = GobEncode(meta)
	msg.Destination = meta.remoteNodeID
	msg.Source = ThisNode.ID
	msg.Send(ConnectID{})
}

func (meta *StreamMeta) SendMessageWrite(data []byte) {
	flow := &Stream{}
	flow.ID = meta.ID
	flow.Data = data

	msg := NewMessage()
	msg.Type = MessageTypeStream
	msg.Data = GobEncode(flow)
	msg.Destination = meta.remoteNodeID
	msg.Source = ThisNode.ID
	meta.writelock.Lock()
	meta.writelocked = true
	msg.Send(ConnectID{})
}

func (meta *StreamMeta) Close() {
	if meta == nil {
		// o_o
		return
	}

	if meta.functerminate != nil {
		meta.functerminate()
	}
	if meta.funccloser != nil {
		meta.funccloser(meta.ID)
	}
	RemoveActiveStream(meta.ID)

	// Wrapping in a delayed functions since streams were occasionally closing before the last packet of data was handled.
	time.AfterFunc(1*time.Second, func() {
		meta.SendMessageClose()
	})
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

func NewActiveStream(tracker *StreamMeta) {
	activeStreamsMutex.Lock()
	defer activeStreamsMutex.Unlock()

	id := tracker.ID
	activeStreams[id] = tracker
	ThisNodeInfo.AddStream(tracker.ID, tracker.Type, tracker.Context, tracker.remoteNodeID)
}

func GetActiveStream(id StreamID) (tracker *StreamMeta, ok bool) {
	activeStreamsMutex.Lock()
	defer activeStreamsMutex.Unlock()

	tracker, ok = activeStreams[id]
	return
}

func RemoveActiveStream(id StreamID) {
	activeStreamsMutex.Lock()
	defer activeStreamsMutex.Unlock()

	delete(activeStreams, id)
	ThisNodeInfo.RemoveStream(id)
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

type StreamID [9]byte

// Is the StreamID an empty StreamID?
func (id StreamID) IsEmptyStreamID() bool {
	var tmp StreamID
	return tmp == id
}

func (id StreamID) String() string {
	return SqrtedString(id[:], "~")
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

type StreamType byte

const (
	StreamTypeCommand StreamType = iota + 1
	StreamTypeFileDownload
	StreamTypeFileServer
	StreamTypeFileUpload
	StreamTypeShell
	StreamTypePortForwardTCP
	StreamTypePortForwardUDP
)

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

func (msg *Message) HandleStream() {
	switch msg.Type {
	case MessageTypeStreamCreate:
		HandleStreamCreate(msg)
	case MessageTypeStream:
		HandleStreamFlow(msg)
	case MessageTypeStreamClose:
		HandleStreamClose(msg)
	case MessageTypeStreamAcknowledge:
		HandleStreamAcknowledge(msg)
	}
}

func HandleStreamAcknowledge(msg *Message) {
	var streamMsg Stream

	err := msg.GobDecodeMessage(&streamMsg)
	if err == nil {
		meta, ok := GetActiveStream(streamMsg.ID)
		if ok && meta.writelocked {
			meta.writelock.Unlock()
			meta.writelocked = false
		}
	}
}

func HandleStreamCreate(msg *Message) {
	// Create new meta if none exists
	var streamMsg StreamMeta

	err := msg.GobDecodeMessage(&streamMsg)
	if err == nil {
		meta := NewStreamMetaMirror(&streamMsg, msg.Source)
		meta.SendMessageAcknowledge()
		switch meta.Type {
		case StreamTypeCommand:
			// Agent will handle this one
			args := strings.Split(meta.Context, " ")
			var c *exec.Cmd
			if len(args) == 0 {
				meta.Close()
			} else if len(args) == 1 {
				c = exec.Command(args[0])
			} else {
				c = exec.Command(args[0], args[1:]...)
			}
			c.Stdout = meta
			c.Stderr = meta
			c.Env = os.Environ()
			meta.stdin, err = c.StdinPipe()
			if err != nil {
				defer meta.Close()
			}
			meta.funcwriter = func(data []byte) {
				_, err = meta.stdin.Write(data)
				if err != nil {
					meta.Close()
				}
			}

			meta.functerminate = func() {
				if c.Process != nil {
					c.Process.Kill()
				}
			}

			err = c.Start()
			if err == nil {
				go func() {
					err = c.Wait()
					NewMessageError(MessageErrorResponseTypeCommandEnded, fmt.Sprintf("%v(%v)", c.Args, err)).Send(ConnectID{})
					meta.Close()
				}()
			} else {
				meta.Close()
			}
		case StreamTypeShell:
			// Terminal will handle this one
			meta.funcwriter = func(data []byte) {
				ThisNode.Printer(meta.remoteNodeID, meta.ID, fmt.Sprintf("%s", data))
			}
			meta.functerminate = func() {}
		case StreamTypeFileDownload:
			// Terminal is requesting a file from the agent; agent should open file and send it

			// Open the file
			f, err := os.Open(meta.Context)
			if err != nil {
				NewMessageError(MessageErrorResponseTypeFileDownloadOpenFileError, err.Error()).Send(ConnectID{})
				meta.Close()
				break
			}
			r := bufio.NewReader(f)

			meta.funcwriter = func(data []byte) {}
			meta.functerminate = func() {
				// Close the file
				f.Close()
			}

			// Read from the file
			go func() {
				buff := make([]byte, 65535)
				for {
					n, err := r.Read(buff)
					if err == nil && n > 0 {
						meta.Write(buff[:n])
					} else {
						break
					}
				}
				name, _ := filepath.Abs(f.Name())
				NewMessageError(MessageErrorResponseTypeFileDownloadCompleted, name).Send(ConnectID{})
				meta.Close()
			}()
		case StreamTypeFileUpload:
			// Terminal is pushing a file to the agent; agent should open file and write to it

			// Open the file
			f, err := os.OpenFile(meta.Context, os.O_CREATE|os.O_WRONLY|os.O_EXCL|os.O_TRUNC, 0700)
			if err != nil {
				NewMessageError(MessageErrorResponseTypeFileUploadOpenFileError, err.Error()).Send(ConnectID{})
				meta.Close()
				break
			}
			name, _ := filepath.Abs(f.Name())

			meta.funcwriter = func(data []byte) {
				// Write to the file
				f.Write(data)
			}
			meta.functerminate = func() {
				// Close the file
				NewMessageError(MessageErrorResponseTypeFileUploadCompleted, name).Send(ConnectID{})
				f.Close()
			}
		case StreamTypeFileServer:
			c, ok := GetConnectionByString(meta.Context)
			if !ok {
				NewMessageError(MessageErrorResponseTypeFileServerConnectionNotFound, meta.Context)
				break
			}

			meta.funcwriter = func(data []byte) {
				c.Write(data)
			}
			meta.functerminate = func() {
				c.Close()
			}
		case StreamTypePortForwardTCP:
			var c net.Conn
			c, err = net.Dial("tcp", meta.Context)

			if err != nil {
				NewMessageError(0, err.Error()).Send(ConnectID{})
				return
			}

			meta.funcwriter = func(data []byte) {
				c.Write(data)
			}
			meta.functerminate = func() {
				c.Close()
			}

			go func() {
				buff := make([]byte, 65535)
				for {
					n, err := c.Read(buff)
					if err == nil && n > 0 {
						meta.Write(buff[:n])
					} else {
						if c != nil {
							c.Close()
						}
						if meta != nil {
							meta.Close()
						}
						return
					}
				}
			}()
		case StreamTypePortForwardUDP:
			var c net.Conn
			c, err = net.Dial("udp", meta.Context)

			if err != nil {
				NewMessageError(0, err.Error()).Send(ConnectID{})
				return
			}

			meta.funcwriter = func(data []byte) {
				c.Write(data)
			}
			meta.functerminate = func() {
				c.Close()
			}

			go func() {
				buff := make([]byte, 65535)
				for {
					n, err := c.Read(buff)
					if err == nil && n > 0 {
						meta.Write(buff[:n])
					} else {
						if c != nil {
							c.Close()
						}
						if meta != nil {
							meta.Close()
						}
						return
					}
				}
			}()
		default:
			meta.Close()
		}
	} else {
		NewMessageError(MessageErrorResponseTypeGobDecodeError, msg.ID.String())
	}
}

func HandleStreamFlow(msg *Message) {
	// Write to meta.ReadChannel
	var streamMsg Stream

	err := msg.GobDecodeMessage(&streamMsg)
	if err == nil {
		stream, ok := GetActiveStream(streamMsg.ID)
		if !ok {
			return
		}
		if stream.funcwriter != nil {
			stream.funcwriter(streamMsg.Data)
		}
		stream.SendMessageAcknowledge()
	}
}

func HandleStreamClose(msg *Message) {
	var streamMsg StreamMeta

	err := msg.GobDecodeMessage(&streamMsg)
	if err != nil {
		return
	}

	stream, ok := GetActiveStream(streamMsg.ID)
	if !ok {
		return
	}
	if stream.functerminate != nil {
		stream.functerminate()
	}
	if stream.funccloser != nil {
		stream.funccloser(stream.ID)
	}
	RemoveActiveStream(stream.ID)
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

func (stream *StreamMeta) Write(p []byte) (n int, err error) {
	for i := 0; i < len(p); i += 65535 {
		n = i + 65535
		if n > len(p) {
			n = len(p)
		}
		stream.SendMessageWrite(p[i:n])
	}
	return n, nil
}
