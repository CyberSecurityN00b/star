package main

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/gob"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/CyberSecurityN00b/star/pkg/star"
)

//go:embed connection.crt connection.key
var fs embed.FS
var activeNode star.NodeID
var activeStream star.StreamID
var tickerSynchronization *time.Ticker

func main() {
	initTerminal()

	// Send a "hello" message to any existing connections
	helloMsg := star.NewMessageHello()
	helloMsg.Send(star.ConnectID{})

	runTerminal()
}

///////////////////////////////////////////////////////////////////////////////

func initTerminal() {
	star.STARCoreSetup()
	star.ThisNode = star.NewNode(star.NodeTypeTerminal)
	star.ThisNode.MessageProcesser = TerminalProcessMessage

	star.ThisNodeInfo.Setup()

	// Setup connection cert
	conncrt, err := fs.ReadFile("connection.crt")
	if err != nil {
		terminalCommandQuit(err, "There was an error when attempting to read \"connection.crt\" from the embedded file system.")
	}
	connkey, err := fs.ReadFile("connection.key")
	if err != nil {
		terminalCommandQuit(err, "There was an error when attempting to read \"connection.key\" from the embedded file system.")
	}
	err = star.SetupConnectionCertificate(conncrt, connkey)
	if err != nil {
		terminalCommandQuit(err, "There was an error when attempting to create the connection's X509KeyPair.")
	}

	// Setup settings
	terminalSettings = make(map[string]terminalSetting)
	terminalSettings["history.tracklength"] = terminalSetting{100, "The number of commands to track in the history."}
	terminalSettings["history.displaylength"] = terminalSetting{10, "The number of commands to show when displaying history (doesn't include `:h all`)."}
	terminalSettings["display.ansicolor"] = terminalSetting{true, "Use ANSI color codes in STAR output."}
	terminalSettings["display.timestamp"] = terminalSetting{"2006.01.02-15.04.05", "GoLang timestamp format for logs/notices."}
	terminalSettings["sync.minutes"] = terminalSetting{5, "Send a Synchronization Request to all agents every N minutes. (Changes take effect at the next ticker synchronization; values less than 1 are ignored.)"}
	terminalSettings["sync.mute"] = terminalSetting{true, "Mutes Synchronization Responses from agents. (Not applicable to errors.)"}
	terminalSettings["sync.muteerrors"] = terminalSetting{false, "Mutes Synchronization Response errors from agents. (Not applicable to responses.)"}

	// Setup history
	historyItems = make(map[uint]historyItem)

	// Setup agent tracker
	agentFriendlyTracker = make(map[string]*agentInfo)
	agentNodeIDTracker = make(map[star.NodeID]*agentInfo)

	// Synchronization ticker
	tickerSynchronization = time.NewTicker(time.Duration(terminalSettings["sync.minutes"].Data.(int)) * time.Minute)
	go func() {
		for {
			select {
			case <-tickerSynchronization.C:
				printInfo("Synchronizing with agents...")
				syncMsg := star.NewMessageSyncRequest()
				syncMsg.Send(star.ConnectID{})

				next := terminalSettings["sync.minutes"].Data.(int)
				if next >= 1 {
					tickerSynchronization.Reset(time.Duration(next) * time.Minute)
				}
			}
		}
	}()

	printInfo(fmt.Sprintf("Terminal Initiated! Terminal ID is %s.", star.ThisNode.ID))
	printInfo("Good luck and have fun!")
}

func runTerminal() {
	in := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("")
		text, _ := in.ReadString('\n')
		text = strings.Replace(text, "\n", "", -1)
		handleTerminalInput(text)
	}
}

///////////////////////////////////////////////////////////////////////////////

func handleTerminalInput(input string) {
	if len(input) == 0 {
		return
	}

	// Add to history
	n := activeNode
	s := activeStream
	if len(input) > 2 {
		if input[0] == ':' && input[1] != ':' {
			n = star.ThisNode.ID
		}
	}
	HistoryPush(historyItem{time.Now(), input, n, s})

	// Handle
	inputs := strings.Split(input, " ")
	switch inputs[0] {
	case ":?", ":help":
		topic := ""
		if len(inputs) >= 2 {
			topic = inputs[1]
		}
		terminalCommandHelp(topic)
	case ":b", ":bind":
		if len(inputs) == 2 {
			// Single address string, default to terminal
			terminalCommandBind(star.ThisNode.ID, inputs[1:]...)
		} else if len(inputs) > 2 {
			if inputs[1] == "all" {
				// Use broadcast NodeID to send address string to all Nodes
				terminalCommandBind(star.NodeID{}, inputs[2:]...)
			} else if strings.HasPrefix(inputs[1], "agent") {
				node, ok := agentFriendlyTracker[inputs[1]]
				if !ok {
					// Invalid agentID
					printError("No such agent as " + inputs[1] + "!")
				} else {
					// Send address string(s) to Node
					terminalCommandBind(node.Node.ID, inputs[2:]...)
				}
			} else {
				// No agent, multiple address strings, send to terminal
				terminalCommandBind(star.ThisNode.ID, inputs[1:]...)
			}
		} else {
			terminalCommandHelp(":b")
		}
	case ":c", ":connect":
		if len(inputs) == 2 {
			// Single address string, default to terminal
			terminalCommandConnect(star.ThisNode.ID, inputs[1:]...)
		} else if len(inputs) > 2 {
			if inputs[1] == "all" {
				// Use broadcast NodeID to send address string to all Nodes
				terminalCommandConnect(star.NodeID{}, inputs[2:]...)
			} else if strings.HasPrefix(inputs[1], "agent") {
				node, ok := agentFriendlyTracker[inputs[1]]
				if !ok {
					// Invalid agentID
					printError("No such agent as " + inputs[1] + "!")
				} else {
					// Send address string(s) to Node
					terminalCommandConnect(node.Node.ID, inputs[2:]...)
				}
			} else {
				// No agent, multiple address strings, send to terminal
				terminalCommandConnect(star.ThisNode.ID, inputs[1:]...)
			}
		} else {
			terminalCommandHelp(":c")
		}
	case ":d", ":down", ":download":
		terminalCommandDownload()
	case ":h", ":history":
		if len(inputs) >= 2 {
			if inputs[1] == "all" {
				terminalCommandHistory(true, activeNode, activeStream)
			}
			// TODO: Convert agent/string to ID
			terminalCommandHistory(false, activeNode, activeStream)
		} else {
			terminalCommandHistory(false, activeNode, activeStream)
		}
	case ":i", ":info", ":information":
		terminalCommandInformation()
	case ":j", ":jump":
		terminalCommandJump()
	case ":k", ":kill", ":killswitch":
		terminalCommandKillSwitch()
	case ":l", ":list":
		terminalCommandList()
	case ":s", ":set", ":setting", ":settings":
		if len(inputs) == 1 {
			terminalCommandSet("", "")
		} else if len(inputs) == 2 {
			terminalCommandSet(inputs[1], "")
		} else {
			terminalCommandSet(inputs[1], star.StringifySubarray(inputs, 2, len(inputs)))
		}
	case ":r", ":run", ":runfile":
		terminalCommandRunFile()
	case ":t", ":terminate":
		terminalCommandTerminate()
	case ":u", ":up", ":upload":
		terminalCommandUpload()
	case ":q", ":quit":
		terminalCommandQuit(nil, "")
	case "::":
		if len(input) > 3 {
			terminalCommandSendCommand(input[3:])
		} else {
			terminalCommandSendCommand("")
		}
	default:
		if inputs[0][0] == ':' {
			terminalCommandHelp("")
			fmt.Println()
			printError("It looks like you were attempting to enter in a command? If so, commands are case sensitive. If not, run `:? ::`.")
		} else {
			terminalCommandSendCommand(input)
		}
	}
	return
}

///////////////////////////////////////////////////////////////////////////////
/****************************** Terminal Output ******************************/
///////////////////////////////////////////////////////////////////////////////

type ANSIColor string

const (
	ANSIColor_Error ANSIColor = "\033[0;31m%s\033[0m"
	ANSIColor_Info  ANSIColor = "\033[0;36m%s\033[0m"
	ANSIColor_Debug ANSIColor = "\033[1;31m%s\033[0m"
	ANSIColor_Time  ANSIColor = "\033[7m%s\033[0m"
)

func ANSIColorize(text string, color ANSIColor) string {
	c, ok := terminalSettings["display.ansicolor"].Data.(bool)
	if !ok {
		c = false
	}
	if c {
		return fmt.Sprintf(string(color), text)
	} else {
		return text
	}
}

func printError(text string) {
	fmt.Println(ANSIColorize(time.Now().Format(terminalSettings["display.timestamp"].Data.(string)), ANSIColor_Time), ANSIColorize("[ STAR | error ]> "+text, ANSIColor_Error))
}

func printInfo(text string) {
	fmt.Println(ANSIColorize(time.Now().Format(terminalSettings["display.timestamp"].Data.(string)), ANSIColor_Time), ANSIColorize("[ STAR | info  ]> "+text, ANSIColor_Info))
}

func printDebug(text string) {
	fmt.Println(ANSIColorize(time.Now().Format(terminalSettings["display.timestamp"].Data.(string)), ANSIColor_Time), ANSIColorize("[ STAR | debug ]> "+text, ANSIColor_Debug))
}

///////////////////////////////////////////////////////////////////////////////
/************************* Terminal Command Handling *************************/
///////////////////////////////////////////////////////////////////////////////

func terminalCommandHelp(topic string) {
	fmt.Println("********************************************************************************")
	switch strings.ToLower(topic) {
	case ":?", ":help":
		fmt.Println("--> COMMAND HELP FOR: :?, :help")
		fmt.Println()
		fmt.Println("USAGE: :?, :? <cmd>, :? <topic>")
		fmt.Println("EXAMPLES:")
		fmt.Println("\t:? :bind")
		fmt.Println("\t:? library")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tUsing `:?` by itself prints a list of STAR commands and topics. Specifying a command or topic provides more detailed help specific to that command or topic.")
	case ":b", ":bind":
		fmt.Println("--> COMMAND HELP FOR: :b, :bind")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("EXAMPLES:")
		fmt.Println("\t<<<>>>")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\t<<<>>>")
	case ":c", ":connect":
		fmt.Println("--> COMMAND HELP FOR: :c, :connect")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("EXAMPLES:")
		fmt.Println("\t<<<>>>")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\t<<<>>>")
	case ":d", ":down", ":download":
		fmt.Println("--> COMMAND HELP FOR: :d, :down, :download")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("EXAMPLES:")
		fmt.Println("\t<<<>>>")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\t<<<>>>")
	case ":h", ":history":
		fmt.Println("--> COMMAND HELP FOR: :h, :history")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
	case ":i", ":info", ":information":
		fmt.Println("--> COMMAND HELP FOR: :i, :info, :information")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("EXAMPLES:")
		fmt.Println("\t<<<>>>")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\t<<<>>>")
	case ":j", ":jump":
		fmt.Println("--> COMMAND HELP FOR: :j, :jump")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("EXAMPLES:")
		fmt.Println("\t<<<>>>")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\t<<<>>>")
	case ":k", ":kill", ":killswitch":
		fmt.Println("--> COMMAND HELP FOR: :k, :kill, :killswitch")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("EXAMPLES:")
		fmt.Println("\t<<<>>>")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\t<<<>>>")
	case ":l", ":list":
		fmt.Println("--> COMMAND HELP FOR: :l, :list")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("EXAMPLES:")
		fmt.Println("\t<<<>>>")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\t<<<>>>")
	case ":r", ":run", ":runfile":
		fmt.Println("--> COMMAND HELP FOR: :r, :run, :runfile")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("EXAMPLES:")
		fmt.Println("\t<<<>>>")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\t<<<>>>")
	case ":s", ":set", ":setting", ":settings":
		fmt.Println("--> COMMAND HELP FOR: :s, :set, :setting, :settings")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("EXAMPLES:")
		fmt.Println("\t<<<>>>")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\t<<<>>>")
	case ":t", ":terminate":
		fmt.Println("--> COMMAND HELP FOR: :t, :terminate")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("EXAMPLES:")
		fmt.Println("\t<<<>>>")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\t<<<>>>")
	case ":u", ":up", ":upload":
		fmt.Println("--> COMMAND HELP FOR: :u, :up, :upload")
		fmt.Println()
		fmt.Println("TODO: Write this section when command is functional.")
		fmt.Println()
		fmt.Println("USAGE: ")
		fmt.Println("EXAMPLES:")
		fmt.Println("\t<<<>>>")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\t<<<>>>")
	case ":q", ":quit":
		fmt.Println("--> COMMAND HELP FOR: :q, :quit")
		fmt.Println()
		fmt.Println()
		fmt.Println("USAGE: :q")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tQuits the terminal. Does *NOT* quit any agents.")
	case "::":
		fmt.Println("--> COMMAND HELP FOR: ::")
		fmt.Println()
		fmt.Println("USAGE: :: <command to pass to agent>")
		fmt.Println("EXAMPLES:")
		fmt.Println("\t:: :i")
		fmt.Println("\t:: /bin/bash")
		fmt.Println()
		fmt.Println("DESCRIPTION:")
		fmt.Println("\tUse `:: <cmd>` to pass a command to an agent and not have it interpreted by the terminal. This is useful for scenarios where you have 'nested terminals' or are interacting with another tool which requires starting a command string with the ':' character. You do *NOT* need to use :: to pass a command to the terminal if it doesn't start with the ':' character.")
	case "agent", "agents":
		fmt.Println("--> ABOUT AGENTS")
		fmt.Println()
		fmt.Println("TODO: Write this section when STAR is functional.")
	case "connection", "connections":
		fmt.Println("--> ABOUT CONNECTIONS")
		fmt.Println()
		fmt.Println("TODO: Write this section when STAR is functional.")
	case "constellation", "constellations":
		fmt.Println("--> ABOUT CONSTELLATIONS")
		fmt.Println()
		fmt.Println("TODO: Write this section when STAR is functional.")
	case "library", "libraries":
		fmt.Println("--> ABOUT LIBRARIES")
		fmt.Println()
		fmt.Println("TODO: Write this section when STAR is functional.")
	case "terminal", "terminals":
		fmt.Println("--> ABOUT TERMINALS")
		fmt.Println()
		fmt.Println("TODO: Write this section when STAR is functional.")
	default:
		fmt.Println("------------------------------ STAR Help Overview ------------------------------")
		fmt.Println("********************************************************************************")

		if topic != "" {
			fmt.Println()
			fmt.Println("There is no help for `%s`!", topic)
			fmt.Println()
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		fmt.Fprintln(w, ":? :help \t Displays this help screen.")
		fmt.Fprintln(w, ":: \t Used to pass commands starting with : to an agent.")
		fmt.Fprintln(w, ":b :bind \t Creates a STAR listener and binds it.")
		fmt.Fprintln(w, ":c :connect \t Connects to a STAR listener.")
		fmt.Fprintln(w, ":d :down :download \t Downloads a file from the terminal to the agent.")
		fmt.Fprintln(w, ":h :history \t Displays the command history for an agent.")
		fmt.Fprintln(w, ":i :info :information \t Shows information for a specific agent.")
		fmt.Fprintln(w, ":j :jump \t Jump (change focus) to another agent.")
		fmt.Fprintln(w, ":k :kill :killswitch \t Panic button! Destroy and cleanup constellation.")
		fmt.Fprintln(w, ":l :list \t Lists agents, connections, and commands.")
		fmt.Fprintln(w, ":r :run :runfile \t Runs a prepared file of commands.")
		fmt.Fprintln(w, ":s :set :setting :settings \t View/set configuration settings.")
		fmt.Fprintln(w, ":t :terminate \t Terminates an agent, connection, or command.")
		fmt.Fprintln(w, ":u :up :upload \t Uploads a file from the agent to the terminal.")
		fmt.Fprintln(w, ":q :quit \t Quits the current terminal.")
		w.Flush()

		fmt.Println()
		fmt.Println("Use `:? <cmd>` for more details on the above commands (i.e., `:? :bind`).")
		fmt.Println()
		fmt.Println("Use `:? <topic>` for more information on the following topics:")
		fmt.Println("\tagent")
		fmt.Println("\tconnections")
		fmt.Println("\tconstellation")
		fmt.Println("\tlibrary")
		fmt.Println("\tterminal")
		w.Flush()
	}
	fmt.Println("********************************************************************************")
}

func terminalCommandBind(node star.NodeID, addresses ...string) {
	if node.IsBroadcastNodeID() || node == star.ThisNode.ID {
		for _, address := range addresses {
			printInfo("Setting up listener on " + address)
			star.NewTCPListener(address)
		}
	}

	if node != star.ThisNode.ID {
		for _, address := range addresses {
			// TODO: Send to agent
			print("Not yet implemented for agent to bind to: " + address)
		}
	}
	return
}

func terminalCommandConnect(node star.NodeID, addresses ...string) (err error) {
	if node.IsBroadcastNodeID() || node == star.ThisNode.ID {
		for _, address := range addresses {
			printInfo("Connecting to " + address)
			star.NewTCPConnection(address)
		}
	}

	if node != star.ThisNode.ID {
		for _, address := range addresses {
			// TODO: Send to agent
			print("Not yet implemented for agent to connect to: " + address)
		}
	}
	return
}

func terminalCommandDownload() (err error) {
	printError("Download is not yet implemented!")
	return
}

func terminalCommandHistory(all bool, node star.NodeID, stream star.StreamID) (err error) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)

	// "Filter" the history items
	selectHistoryItems := make(map[uint]historyItem)
	if all {
		for i, h := range historyItems {
			selectHistoryItems[i] = h
		}
	} else {
		for i, h := range historyItems {
			if (h.Node == node || h.Node == star.ThisNode.ID) && (h.Stream.IsEmptyStreamID() || h.Stream == stream) {
				selectHistoryItems[i] = h
			}
		}
	}

	// Sort the keys
	keys := make([]uint, len(selectHistoryItems))
	i := 0
	for k := range selectHistoryItems {
		keys[i] = k
		i++
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	for _, k := range keys {
		fmt.Fprintln(w, selectHistoryItems[k].Timestamp.Format(terminalSettings["display.timestamp"].Data.(string)), "\t", k, "\t", selectHistoryItems[k].String)
	}
	w.Flush()
	return
}

func terminalCommandInformation() (err error) {
	fmt.Printf("Terminal ID: %v\n", star.ThisNode.ID)
	return
}

func terminalCommandJump() (err error) {
	printError("Jump is not yet implemented!")
	return
}

func terminalCommandKillSwitch() (err error) {
	printError("Killswitch is not yet implemented!")
	return
}

func terminalCommandList() (err error) {
	printError("List is not yet implemented!")
	return
}

func terminalCommandRunFile() (err error) {
	printError("Runscripts are not yet implemented!")
	return
}

func terminalCommandSet(setting string, value string) (err error) {
	printInfo("Here are the current terminal settings. Use `:s <setting>` to view more info.")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	if setting == "" {
		// Sort keys
		keys := make([]string, len(terminalSettings))
		i := 0
		for key := range terminalSettings {
			keys[i] = key
			i++
		}
		sort.Strings(keys)

		// Print settings
		for i := range keys {
			fmt.Fprintln(w, fmt.Sprintf("%s\t%v\t%T", keys[i], terminalSettings[keys[i]].Data, terminalSettings[keys[i]].Data))
		}
	} else if value == "" {
		if _, ok := terminalSettings[setting]; ok {
			fmt.Fprintln(w, fmt.Sprintf("NAME: \t %s", setting))
			fmt.Fprintln(w, fmt.Sprintf("TYPE: \t %T", terminalSettings[setting].Data))
			fmt.Fprintln(w, fmt.Sprintf("VALUE: \t %v", terminalSettings[setting].Data))
			fmt.Fprintln(w, fmt.Sprintf("DESCRIPTION: \t %s", terminalSettings[setting].Description))
		} else {
			printError(fmt.Sprintf("No such setting as %s! Run `:settings` for a full list of settings!", value))
		}
	} else {
		if s, ok := terminalSettings[setting]; ok {
			switch s.Data.(type) {
			case bool:
				s.Data, _ = strconv.ParseBool(value)
			case float32, float64:
				s.Data, _ = strconv.ParseFloat(value, 64)
			case int, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
				s.Data, _ = strconv.ParseInt(value, 10, 64)
			case string:
				s.Data = value
			default:
				printDebug("Error when attempt to change setting, unexpected setting value?")
			}
			terminalSettings[setting] = s
			fmt.Fprintln(w, fmt.Sprintf("%s\t%v\t%T\t%s", setting, terminalSettings[setting].Data, terminalSettings[setting].Data, terminalSettings[setting].Description))
		} else {
			printError(fmt.Sprintf("No such setting as %s! Run `:settings` for a full list of settings!", setting))
		}
	}
	w.Flush()
	return
}

func terminalCommandTerminate() (err error) {
	printError("Terminate is not yet implemented!")
	return
}

func terminalCommandUpload() (err error) {
	printError("Upload is not yet implemented!")
	return
}

func terminalCommandQuit(err error, errmsg string) {
	if err != nil {
		fmt.Println(err)
		printError(errmsg)
		printInfo("Quitting due to error!")
	} else {
		printInfo("Goodbye!")
	}
	os.Exit(0)
}

func terminalCommandSendCommand(cmd string) (err error) {
	printInfo("You attempted to send: " + cmd)
	printError("Sending commands is not yet implemented.")
	return
}

///////////////////////////////////////////////////////////////////////////////

func TerminalProcessMessage(msg *star.Message) {
	switch msg.Type {
	case star.MessageTypeCommandResponse:
		TerminalProcessCommandResponse(msg)
	case star.MessageTypeError:
		TerminalProcessMessageError(msg)
	case star.MessageTypeSyncResponse:
		TerminalProcessSyncResponse(msg)
	case star.MessageTypeNewBind:
		TerminalProcessMessageNewBind(msg)
	case star.MessageTypeNewConnection:
		TerminalProcessMessageNewConnection(msg)
	case star.MessageTypeHello:
		TerminalProcessMessageHello(msg)
	}
}

func TerminalProcessCommandResponse(msg *star.Message) {
	var resmsg star.MessageCommandResponse
	var b bytes.Buffer

	b.Write(msg.Data)
	err := gob.NewDecoder(&b).Decode(&resmsg)
	if err == nil {
		// TODO: Handle Command Response
	} else {
		printError(fmt.Sprintf("%s attempted to report the completion of a command, but there was an error decoding the data.", FriendlyAgentName(msg)))
	}
}

func TerminalProcessMessageError(msg *star.Message) {
	var errmsg star.MessageErrorResponse
	var b bytes.Buffer

	b.Write(msg.Data)
	err := gob.NewDecoder(&b).Decode(&errmsg)
	if err == nil {
		switch errmsg.Type {
		case star.MessageErrorResponseTypeX509KeyPair:
			printError(fmt.Sprintf("%s has reported an error with the creation of the X509 Key pair. Context: %s", FriendlyAgentName(msg), errmsg.Context))
		case star.MessageErrorResponseTypeConnectionLost:
			printError(fmt.Sprintf("%s has reported that it has lost/dropped the connection with %s.", FriendlyAgentName(msg), errmsg.Context))
		case star.MessageErrorResponseTypeBindDropped:
			printError(fmt.Sprintf("%s has reported that it has lost/dropped the listening bind on %s", FriendlyAgentName(msg), errmsg.Context))
		case star.MessageErrorResponseTypeGobDecodeError:
			printError(fmt.Sprintf("%s has reported an error with attempting to gob decode a message of type %s.", FriendlyAgentName(msg), errmsg.Context))
		case star.MessageErrorResponseTypeAgentExitSignal:
			printError(fmt.Sprintf("%s has reported that it was terminated with the signal interrupt %s.", FriendlyAgentName(msg), errmsg.Context))
		default:
			printError(fmt.Sprintf("%s has reported an unknown error. Context: %s", FriendlyAgentName(msg), errmsg.Context))
		}
	} else {
		printError(fmt.Sprintf("% attempted to report an error, but there was another error when decoding the data.", FriendlyAgentName(msg)))
	}
}

func TerminalProcessSyncResponse(msg *star.Message) {
	var resmsg star.MessageSyncResponse
	var b bytes.Buffer

	b.Write(msg.Data)
	err := gob.NewDecoder(&b).Decode(&resmsg)
	if err == nil {
		// TODO: Handle Sync Response

		if !terminalSettings["sync.mute"].Data.(bool) {
			printError(fmt.Sprintf("%s has synchronized.", FriendlyAgentName(msg)))
		}
	} else {
		if !terminalSettings["sync.muteerrors"].Data.(bool) {
			printError(fmt.Sprintf("%s attempted to report a synchronization response, but there was an error decoding the data.", FriendlyAgentName(msg)))
		}
	}
}

func TerminalProcessMessageNewBind(msg *star.Message) {
	var resmsg star.MessageNewBindResponse
	var b bytes.Buffer

	b.Write(msg.Data)
	err := gob.NewDecoder(&b).Decode(&resmsg)
	if err == nil {
		printInfo(fmt.Sprintf("%s has reported a new bind/listner on %s.", FriendlyAgentName(msg), resmsg.Address))
	} else {
		printError(fmt.Sprintf("%s attempted to report a new bind/listener, but there was an error when decoding the data.", FriendlyAgentName(msg)))
	}
}

func TerminalProcessMessageNewConnection(msg *star.Message) {
	var resmsg star.MessageNewConnectionResponse
	var b bytes.Buffer

	b.Write(msg.Data)
	err := gob.NewDecoder(&b).Decode(&resmsg)
	if err == nil {
		printInfo(fmt.Sprintf("%s has reported a new connection with %s.", FriendlyAgentName(msg), resmsg.Address))
	} else {
		printError(fmt.Sprintf("%s attempted to report a new connection, but there was an error when decoding the data.", FriendlyAgentName(msg)))
	}
}

func TerminalProcessMessageHello(msg *star.Message) {
	var resmsg star.MessageHelloResponse
	var b bytes.Buffer

	b.Write(msg.Data)
	err := gob.NewDecoder(&b).Decode(&resmsg)
	if err == nil {
		UpdateNode(&resmsg.Node, &resmsg.Info)
	} else {
		printError(fmt.Sprintf("%s attempted to report an initial connection with the constellation, but there was an error when decoding the data.", FriendlyAgentName(msg)))
	}
}

func FriendlyAgentName(msg *star.Message) string {
	if msg.Source.IsBroadcastNodeID() {
		return "An unknown agent"
	} else if msg.Source == star.ThisNode.ID {
		return "This terminal"
	} else {
		return fmt.Sprintf("Agent %s", msg.Source)
	}
}

///////////////////////////////////////////////////////////////////////////////
/********************************** History **********************************/
///////////////////////////////////////////////////////////////////////////////
type historyItem struct {
	Timestamp time.Time
	String    string
	Node      star.NodeID
	Stream    star.StreamID
}

var historyItems map[uint]historyItem
var historyIndex uint

func HistoryPush(item historyItem) {
	historyIndex++
	historyItems[historyIndex] = item

	// Enforce history.length
	l, ok := terminalSettings["history.tracklength"].Data.(uint)
	if ok {
		if historyIndex > l && historyIndex > 0 {
			oldestAllowed := historyIndex - l
			for i := range historyItems {
				if i < oldestAllowed {
					delete(historyItems, i)
				}
			}
		}
	}
}

func HistoryPop() {
	delete(historyItems, historyIndex)
	historyIndex--
}

///////////////////////////////////////////////////////////////////////////////
/********************************* Settings **********************************/
///////////////////////////////////////////////////////////////////////////////

type terminalSetting struct {
	Data        interface{}
	Description string
}

var terminalSettings map[string]terminalSetting

///////////////////////////////////////////////////////////////////////////////
/********************************** Agents ***********************************/
///////////////////////////////////////////////////////////////////////////////

type agentInfo struct {
	Node         *star.Node
	Info         *star.NodeInfo
	FriendlyName string
}

var agentFriendlyTracker map[string]*agentInfo
var agentNodeIDTracker map[star.NodeID]*agentInfo

var agentFriendlyNameTracker int
var shellFriendlyNameCounter int
var terminalFriendlyNameCounter int
var unknownFriendlyNameCounter int

func UpdateNode(node *star.Node, info *star.NodeInfo) {
	var i *agentInfo
	i, ok := agentNodeIDTracker[node.ID]
	if !ok {
		var name string
		switch node.Type {
		case star.NodeTypeAgent:
			agentFriendlyNameTracker++
			name = fmt.Sprintf("agent%06d", agentFriendlyNameTracker)
		case star.NodeTypeShell:
			shellFriendlyNameCounter++
			name = fmt.Sprintf("shell%03d", shellFriendlyNameCounter)
		case star.NodeTypeTerminal:
			terminalFriendlyNameCounter++
			name = fmt.Sprintf("term%03d", terminalFriendlyNameCounter)
		default:
			unknownFriendlyNameCounter++
			name = fmt.Sprintf("unk%03d", unknownFriendlyNameCounter)
		}

		i = &agentInfo{Node: node, Info: info, FriendlyName: name}
		agentNodeIDTracker[node.ID] = i
		agentFriendlyTracker[name] = i
	}

	i.Node = node
	i.Info = info
}

///////////////////////////////////////////////////////////////////////////////
