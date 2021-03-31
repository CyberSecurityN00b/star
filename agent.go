package main

import (
	"bytes"
	"embed"
	"encoding/gob"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/CyberSecurityN00b/star/pkg/star"
)

//go:embed connection.crt connection.key
var fs embed.FS

func main() {
	initAgent()
	parameterHandlingAgent()

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
	star.ThisNode.StreamProcessor = AgentProcessStream

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

// Allows for the creation of listeners (bind) and connections (connect) via
// command-line arguments.
func parameterHandlingAgent() {
	for _, arg := range os.Args[1:] {
		setup := strings.Split(arg, ":")
		if setup[0] == "b" || setup[0] == "l" {
			// [b]ind/[l]istener

			if len(setup) == 2 {
				star.NewTCPListener(":" + setup[1])
			} else if len(setup) == 3 {
				star.NewTCPListener(setup[1] + ":" + setup[2])
			}
		} else if setup[0] == "r" || setup[0] == "c" {
			// [r]everse/[c]onnect

			if len(setup) == 2 {
				star.NewTCPConnection(":" + setup[1])
			} else if len(setup) == 3 {
				star.NewTCPConnection(setup[1] + ":" + setup[2])
			}
		}
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
	case star.MessageTypeShell:
		AgentProcessShellRequest(msg)
	case star.MessageTypeDebug:
		AgentProcessDebugRequest(msg)
	case star.MessageTypeFileServer:
		AgentProcessFileServerRequest(msg)
	}
}

func AgentProcessBind(msg *star.Message) {
	var reqMsg star.MessageBindRequest
	var b bytes.Buffer

	b.Write(msg.Data)
	err := gob.NewDecoder(&b).Decode(&reqMsg)
	if err == nil {
		switch reqMsg.Type {
		case star.ConnectorTypeTCP:
			var address string
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
	} else {
		errMsg := star.NewMessageError(star.MessageErrorResponseTypeGobDecodeError, fmt.Sprintf("%d", msg.Type))
		errMsg.Destination = msg.Source
		errMsg.Send(star.ConnectID{})
	}
}

func AgentProcessConnect(msg *star.Message) {
	var reqMsg star.MessageConnectRequest
	var b bytes.Buffer

	b.Write(msg.Data)
	err := gob.NewDecoder(&b).Decode(&reqMsg)
	if err == nil {
		switch reqMsg.Type {
		case star.ConnectorTypeTCP:
			var address string
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
	} else {
		errMsg := star.NewMessageError(star.MessageErrorResponseTypeGobDecodeError, fmt.Sprintf("%d", msg.Type))
		errMsg.Destination = msg.Source
		errMsg.Send(star.ConnectID{})
	}
}

func AgentProcessKillSwitch(msg *star.Message) {
	var reqMsg star.MessageKillSwitchRequest
	var b bytes.Buffer

	b.Write(msg.Data)
	err := gob.NewDecoder(&b).Decode(&reqMsg)
	if err == nil {
		// TODO: Cleanup
		os.Exit(1)
	} else {
		errMsg := star.NewMessageError(star.MessageErrorResponseTypeGobDecodeError, fmt.Sprintf("%d", msg.Type))
		errMsg.Destination = msg.Source
		errMsg.Send(star.ConnectID{})
	}
}

func AgentProcessSyncRequest(msg *star.Message) {
	var reqMsg star.MessageSyncRequest
	var b bytes.Buffer

	b.Write(msg.Data)
	err := gob.NewDecoder(&b).Decode(&reqMsg)
	if err == nil {
		syncMsg := star.NewMessageSyncResponse()
		syncMsg.Destination = msg.Source
		syncMsg.Send(star.ConnectID{})
	} else {
		errMsg := star.NewMessageError(star.MessageErrorResponseTypeGobDecodeError, fmt.Sprintf("%d", msg.Type))
		errMsg.Send(star.ConnectID{})
	}
}

func AgentProcessTerminateRequest(msg *star.Message) {
	var reqMsg star.MessageTerminateRequest
	var b bytes.Buffer
	b.Write(msg.Data)
	err := gob.NewDecoder(&b).Decode(&reqMsg)
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
		case star.MessageTerminateTypeShell:
			// TODO: terminate shell
		case star.MessageTerminateTypeStream:
			// TODO: terminate stream
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
	} else {
		errMsg := star.NewMessageError(star.MessageErrorResponseTypeGobDecodeError, fmt.Sprintf("%d", msg.Type))
		errMsg.Destination = msg.Source
		errMsg.Send(star.ConnectID{})
	}
	syncMsg := star.NewMessageSyncResponse()
	syncMsg.Send(star.ConnectID{})
}

func AgentProcessShellRequest(msg *star.Message) {

}

func AgentProcessDebugRequest(msg *star.Message) {

}

func AgentProcessFileServerRequest(msg *star.Message) {

}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

func AgentProcessStream(stream *star.Stream) {

}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
