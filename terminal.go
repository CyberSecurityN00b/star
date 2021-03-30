package main

import (
	"bufio"
	"bytes"
	"embed"
	"encoding/gob"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	showWelcomeText()
	initTerminal()

	// Send a "hello" message to any existing connections
	helloMsg := star.NewMessageHello()
	helloMsg.Send(star.ConnectID{})

	runTerminal()
}

///////////////////////////////////////////////////////////////////////////////

func showWelcomeText() {

	fmt.Println("=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=")
	fmt.Println("*             _____        _____           ___        ______                  |")
	fmt.Println("|            /  ___|      |_   _|         / _ \\       | ___ \\                 *")
	fmt.Println("*            \\  --.         | |          / /_\\ \\      | |_/ /                 |")
	fmt.Println("|             `--. \\        | |          |  _  |      |    /                  *")
	fmt.Println("*            /\\__/ /        | |          | | | |      | |\\ \\                  |")
	fmt.Println("|            \\____/ imple   \\_/ actical  \\_| |_/ gent \\_| \\_| elay            *")
	fmt.Println("*                                                                             |")
	fmt.Println("=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=")
	fmt.Println("")
}

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
	historyItemsMutex = &sync.Mutex{}

	// Setup agent tracker
	agentFriendlyTracker = make(map[string]*agentInfo)
	agentNodeIDTracker = make(map[star.NodeID]*agentInfo)
	agentTrackerMutex = &sync.Mutex{}
	AgentTrackerUpdateInfo(&star.ThisNode, &star.ThisNodeInfo)

	// Synchronization ticker
	tickerSynchronization = time.NewTicker(time.Duration(terminalSettings["sync.minutes"].Data.(int)) * time.Minute)
	go func() {
		for {
			select {
			case <-tickerSynchronization.C:
				TerminalSynchronize()

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

	if inputs[0] != "::" || input[0] == ':' {
		fmt.Println("/*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*\\")
	}

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
				node, ok := AgentTrackerGetInfoByFriendly(inputs[1])
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
				node, ok := AgentTrackerGetInfoByFriendly(inputs[1])
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
		if len(inputs) == 2 {
			if inputs[1] == "all" {
				terminalCommandHistory(true, activeNode, activeStream)
			}
			node, ok := AgentTrackerGetInfoByFriendly(inputs[1])
			if !ok {
				terminalCommandList("all")
				printError(fmt.Sprintf("%s is not a valid identifier, use one of the above!", inputs[1]))
			} else {
				terminalCommandHistory(false, node.Node.ID, activeStream)
			}
		} else {
			terminalCommandHistory(false, activeNode, activeStream)
		}
	case ":i", ":info", ":information":
		if len(inputs) == 2 {
			terminalCommandInformation(inputs[1])
		} else if len(inputs) == 1 {
			terminalCommandInformation("")
		} else {
			terminalCommandHelp(":i")
		}
	case ":j", ":jump":
		if len(inputs) == 2 {
			terminalCommandJump(inputs[1])
		} else {
			terminalCommandHelp(":j")
		}
	case ":k", ":kill", ":killswitch":
		terminalCommandKillSwitch()
	case ":l", ":list":
		if len(inputs) >= 2 {
			terminalCommandList(inputs[1])
		} else {
			terminalCommandList("all")
		}
	case ":s", ":set", ":setting", ":settings":
		if len(inputs) == 1 {
			terminalCommandSet("", "")
		} else if len(inputs) == 2 {
			terminalCommandSet(inputs[1], "")
		} else {
			terminalCommandSet(inputs[1], star.StringifySubarray(inputs, 2, len(inputs)))
		}
	case ":sync":
		TerminalSynchronize()
	case ":r", ":run", ":runfile":
		terminalCommandRunFile()
	case ":t", ":terminate":
		if len(inputs) == 1 {
			terminalCommandTerminate("")
		} else if len(inputs) == 2 {
			terminalCommandTerminate(inputs[1])
		} else {
			terminalCommandHelp(":t")
		}
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

	if inputs[0] != "::" || input[0] == ':' {
		fmt.Println("\\*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*/")
	}

	return
}

///////////////////////////////////////////////////////////////////////////////
/****************************** Terminal Output ******************************/
///////////////////////////////////////////////////////////////////////////////

type ANSIColor string

const (
	ANSIColor_Error  ANSIColor = "\033[0;31m%s\033[0m"
	ANSIColor_Info   ANSIColor = "\033[0;36m%s\033[0m"
	ANSIColor_Debug  ANSIColor = "\033[1;31m%s\033[0m"
	ANSIColor_Time   ANSIColor = "\033[7m%s\033[0m"
	ANSIColor_Focus  ANSIColor = "\033[7m%s\033[0m"
	ANSIColor_Notice ANSIColor = "\033[33m%s\033[0m"
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

func printNotice(text string) {
	fmt.Println(ANSIColorize(time.Now().Format(terminalSettings["display.timestamp"].Data.(string)), ANSIColor_Time), ANSIColorize("[ STAR | !!!!! ]> "+text, ANSIColor_Notice))
}

///////////////////////////////////////////////////////////////////////////////
/************************* Terminal Command Handling *************************/
///////////////////////////////////////////////////////////////////////////////

func terminalCommandHelp(topic string) {
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
	case ":sync":
		fmt.Println("--> COMMAND HELP FOR: :sync")
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
		fmt.Println("------------------------------ STAR Help Overview -----------------------------")
		fmt.Println("=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=")

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
		fmt.Fprintln(w, ":sync \t Force constellation synchronization.")
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
			bindMsg := star.NewMessageBindTCP(address)
			bindMsg.Destination = node
			bindMsg.Send(star.ConnectID{})
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
			conMsg := star.NewMessageConnectTCP(address)
			conMsg.Destination = node
			conMsg.Send(star.ConnectID{})
		}
	}
	return
}

func terminalCommandDownload() (err error) {
	printError("Download is not yet implemented!")
	return
}

func terminalCommandHistory(all bool, node star.NodeID, stream star.StreamID) (err error) {
	historyItemsMutex.Lock()
	defer historyItemsMutex.Unlock()

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

func terminalCommandInformation(context string) (err error) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
	agent, ok := AgentTrackerGetInfoByFriendly(context)

	if !ok || context == "" {
		terminalCommandList("all")
	} else {
		fmt.Fprintln(w, "NODE.ID: ", "\t", agent.Node.ID)
		fmt.Fprintln(w, "OS.EGID: ", "\t", agent.Info.OS_egid)
		fmt.Fprintln(w, "OS.EUID: ", "\t", agent.Info.OS_euid)
		fmt.Fprintln(w, "OS.GID: ", "\t", agent.Info.OS_gid)
		fmt.Fprintln(w, "OS.GROUPS: ", "\t", agent.Info.OS_groups)
		fmt.Fprintln(w, "OS.PAGESIZE: ", "\t", agent.Info.OS_pagesize)
		fmt.Fprintln(w, "OS.PID: ", "\t", agent.Info.OS_pid)
		fmt.Fprintln(w, "OS.PPID: ", "\t", agent.Info.OS_ppid)
		fmt.Fprintln(w, "OS.UID: ", "\t", agent.Info.OS_uid)
		fmt.Fprintln(w, "OS.DIR: ", "\t", agent.Info.OS_workingdir)
		fmt.Fprintln(w, "OS.HOSTNAME: ", "\t", agent.Info.OS_hostname)
		w.Flush()
		fmt.Println()
		fmt.Println("ENVIRONMENT VARIABLES:")
		for _, e := range agent.Info.OS_environ {
			fmt.Println("\t", e)
		}
	}
	return
}

func terminalCommandJump(context string) (err error) {
	identifiers := strings.Split(context, ":")
	agent, ok := AgentTrackerGetInfoByFriendly(identifiers[0])
	if !ok {
		terminalCommandList("all")
		printError(fmt.Sprintf("%s is not a valid identifier! Use one of the above agents!", identifiers[0]))
	} else if context == "" {
		terminalCommandHelp(":j")
		printError("Must specify agent or agent:stream to jump to!")
	} else if !strings.HasPrefix(context, "agent") {
		printError(fmt.Sprintf("%s is not an agent! Only agents can be jumped to!", context))
	} else {
		activeNode = agent.Node.ID
		activeStream = star.StreamID{}
		printInfo(fmt.Sprintf("Changing agent focus to %s(%s)", agent.FriendlyName, agent.Node.ID))
		if len(identifiers) > 1 {
			for i, id := range agent.Info.StreamIDs {
				streamname := fmt.Sprintf("stream%03d", i)
				if streamname == identifiers[1] {
					if agent.Info.StreamTypes[i] == star.StreamTypeCommand {
						activeStream = id
						printInfo(fmt.Sprintf("Changing stream focus to %s(%s)", streamname, id))
					} else {
						printError(fmt.Sprintf("%s for %s is not a Command type stream; only Command type streams can have focus. No stream focus set.", streamname, agent.FriendlyName))
					}
				}
			}
		}
	}
	return
}

func terminalCommandKillSwitch() (err error) {
	killMsg := star.NewMessageKillSwitch()
	killMsg.Send(star.ConnectID{})
	return
}

func terminalCommandList(context string) (err error) {
	agentTrackerMutex.Lock()
	defer agentTrackerMutex.Unlock()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)

	if context == "all" {
		fmt.Println("Agents:")
		for _, a := range agentFriendlyTracker {
			focus := ""
			if a.Node.ID == activeNode {
				if activeStream.IsEmptyStreamID() {
					focus = ANSIColorize("CURRENT FOCUS", ANSIColor_Focus)
				} else {
					focus = ANSIColorize("CURRENT FOCUS (STREAM)", ANSIColor_Focus)
				}
			}
			fmt.Fprintln(w, "    ", a.FriendlyName, "\t", a.Info.OS_hostname, "\t", focus, "\t", fmt.Sprintf("Last synced %0.1f minutes ago", time.Since(a.LastSynced).Minutes()))
		}
		w.Flush()
	} else {
		agent, ok := agentFriendlyTracker[context]
		if ok {
			fmt.Println("Connections:")
			//Sort then print
			keys := make([]uint, len(agent.Info.ConnectionIDs))
			ki := 0
			for k := range agent.Info.ConnectionIDs {
				keys[ki] = k
				ki++
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
			for _, i := range keys {
				fmt.Fprintln(w, "    ", fmt.Sprintf("%s:conn%03d", agent.FriendlyName, i), "\t", agent.Info.ConnectionIDs[i], "\t", agent.Info.ConnectionInfos[i])
			}
			w.Flush()
			fmt.Println()

			fmt.Println("Listeners:")
			//Sort then print
			keys = make([]uint, len(agent.Info.ListenerIDs))
			ki = 0
			for k := range agent.Info.ListenerIDs {
				keys[ki] = k
				ki++
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
			for _, i := range keys {
				fmt.Fprintln(w, "    ", fmt.Sprintf("%s:listener%03d", agent.FriendlyName, i), "\t", agent.Info.ListenerIDs[i], "\t", agent.Info.ListenerInfos[i])
			}
			w.Flush()
			fmt.Println()

			fmt.Println("Shells:")
			keys = make([]uint, len(agent.Info.ShellIDs))
			ki = 0
			for k := range agent.Info.ShellIDs {
				keys[ki] = k
				ki++
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
			for _, i := range keys {
				fmt.Fprintln(w, "    ", fmt.Sprintf("%s:shell%03d", agent.FriendlyName, i), "\t", agent.Info.ShellIDs[i], "\t", agent.Info.ShellInfos[i])
			}
			w.Flush()
			fmt.Println()

			fmt.Println("Streams:")
			keys = make([]uint, len(agent.Info.StreamIDs))
			ki = 0
			for k := range agent.Info.StreamIDs {
				keys[ki] = k
				ki++
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
			for _, i := range keys {
				var streamtype string
				switch agent.Info.StreamTypes[i] {
				case star.StreamTypeCommand:
					streamtype = "Command"
				case star.StreamTypeFileUpload:
					streamtype = "Upload"
				case star.StreamTypeFileDownload:
					streamtype = "Download"
				case star.StreamTypeShell:
					streamtype = "Shell"
				case star.StreamTypeAgentDownload:
					streamtype = "Agent"
				default:
					streamtype = "Unknown"
				}

				focus := ""
				if agent.Info.StreamIDs[i] == activeStream {
					focus = ANSIColorize("CURRENT FOCUS", ANSIColor_Focus)
				}

				fmt.Fprintln(w, "    ", fmt.Sprintf("stream%03d", i), "\t", agent.Info.StreamIDs[i], "\t", streamtype, "\t", agent.Info.StreamInfos[i], "\t", focus)
			}
			w.Flush()
			fmt.Println()
		} else {
			terminalCommandList("all")
			printError(fmt.Sprintf("%s is not a valid identifier! Use one of the above!", context))
		}
	}

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

func terminalCommandTerminate(context string) (err error) {
	identifiers := strings.Split(context, ":")
	agent, ok := AgentTrackerGetInfoByFriendly(identifiers[0])
	if !ok {
		terminalCommandList("all")
		printError(fmt.Sprintf("%s is not a valid identifier! Use one of the above agents!", identifiers[0]))
	} else if context == "" {
		terminalCommandHelp(":t")
		printError("Must explicitly specify agent, agent:connection, agent:listener, agent:shell, or agent:stream!")
	} else if !strings.HasPrefix(context, "agent") {
		printError(fmt.Sprintf("%s is not an agent! Terminating termination attempt."))
	} else {
		if len(identifiers) == 1 {
			termMsg := star.NewMessageTerminate(star.MessageTerminateTypeAgent, 0)
			termMsg.Destination = agent.Node.ID
			termMsg.Send(star.ConnectID{})
			AgentTrackerRemoveInfo(agent.Node.ID)
		} else if len(identifiers) == 2 {
			match := regexp.MustCompile(`^(conn|listener|shell|stream)(\d+)$`).FindStringSubmatch(identifiers[1])
			if len(match) == 3 {
				index, _ := strconv.ParseUint(match[2], 10, 64)
				switch match[1] {
				case "conn":
					termMsg := star.NewMessageTerminate(star.MessageTerminateTypeConnection, uint(index))
					termMsg.Destination = agent.Node.ID
					termMsg.Send(star.ConnectID{})
				case "listener":
					termMsg := star.NewMessageTerminate(star.MessageTerminateTypeListener, uint(index))
					termMsg.Destination = agent.Node.ID
					termMsg.Send(star.ConnectID{})
				case "shell":
					termMsg := star.NewMessageTerminate(star.MessageTerminateTypeShell, uint(index))
					termMsg.Destination = agent.Node.ID
					termMsg.Send(star.ConnectID{})
				case "stream":
					termMsg := star.NewMessageTerminate(star.MessageTerminateTypeStream, uint(index))
					termMsg.Destination = agent.Node.ID
					termMsg.Send(star.ConnectID{})
				default:
					// Shouldn't ever reach here, but, uh, oh well.
					terminalCommandList(identifiers[0])
					printError(fmt.Sprintf("%s has an invalid sub-identifier! Must be one of the ones listed above!", context))
					return
				}
			} else {
				terminalCommandList(identifiers[0])
				printError(fmt.Sprintf("%s has an invalid sub-identifier! Must be one of the ones listed above!", context))
				return
			}
		} else {
			terminalCommandHelp(":t")
			printError("Invalid number of separators!")
			return
		}
	}
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
	var resMsg star.MessageCommandResponse
	var b bytes.Buffer

	b.Write(msg.Data)
	err := gob.NewDecoder(&b).Decode(&resMsg)
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
			printNotice(fmt.Sprintf("%s has reported that it has lost/dropped the connection with %s.", FriendlyAgentName(msg), errmsg.Context))
		case star.MessageErrorResponseTypeBindDropped:
			printNotice(fmt.Sprintf("%s has reported that it has lost/dropped the listening bind on %s", FriendlyAgentName(msg), errmsg.Context))
		case star.MessageErrorResponseTypeGobDecodeError:
			printError(fmt.Sprintf("%s has reported an error with attempting to gob decode a message of type %s.", FriendlyAgentName(msg), errmsg.Context))
		case star.MessageErrorResponseTypeAgentExitSignal:
			printNotice(fmt.Sprintf("%s has reported that it was terminated with the signal interrupt %s.", FriendlyAgentName(msg), errmsg.Context))
			AgentTrackerRemoveInfo(msg.Source)
		case star.MessageErrorResponseTypeUnsupportedConnectorType:
			printError(fmt.Sprintf("%s has reported that an unsupported connector type was specified. Context: %s", FriendlyAgentName(msg), errmsg.Context))
		case star.MessageErrorResponseTypeInvalidTerminationIndex:
			printError(fmt.Sprintf("%s has reported that an invalid termination index was specified. Context: %s", FriendlyAgentName(msg), errmsg.Context))
		default:
			printError(fmt.Sprintf("%s has reported an unknown error. Context: %s", FriendlyAgentName(msg), errmsg.Context))
		}
	} else {
		printError(fmt.Sprintf("% attempted to report an error, but there was another error when decoding the data.", FriendlyAgentName(msg)))
	}
}

func TerminalProcessSyncResponse(msg *star.Message) {
	var resMsg star.MessageSyncResponse
	var b bytes.Buffer

	b.Write(msg.Data)
	err := gob.NewDecoder(&b).Decode(&resMsg)
	if err == nil {
		AgentTrackerUpdateInfo(&resMsg.Node, &resMsg.Info)

		if !terminalSettings["sync.mute"].Data.(bool) {
			printInfo(fmt.Sprintf("%s has synchronized.", FriendlyAgentName(msg)))
		}
	} else {
		if !terminalSettings["sync.muteerrors"].Data.(bool) {
			printError(fmt.Sprintf("%s attempted to report a synchronization response, but there was an error decoding the data.", FriendlyAgentName(msg)))
		}
	}
}

func TerminalProcessMessageNewBind(msg *star.Message) {
	var resMsg star.MessageNewBindResponse
	var b bytes.Buffer

	b.Write(msg.Data)
	err := gob.NewDecoder(&b).Decode(&resMsg)
	if err == nil {
		printInfo(fmt.Sprintf("%s has reported a new bind/listener on %s.", FriendlyAgentName(msg), resMsg.Address))
	} else {
		printError(fmt.Sprintf("%s attempted to report a new bind/listener, but there was an error when decoding the data.", FriendlyAgentName(msg)))
	}

	// Resynchronize
	TerminalSynchronize()
}

func TerminalProcessMessageNewConnection(msg *star.Message) {
	var resMsg star.MessageNewConnectionResponse
	var b bytes.Buffer

	b.Write(msg.Data)
	err := gob.NewDecoder(&b).Decode(&resMsg)
	if err == nil {
		printInfo(fmt.Sprintf("%s has reported a new connection with %s.", FriendlyAgentName(msg), resMsg.Address))
	} else {
		printError(fmt.Sprintf("%s attempted to report a new connection, but there was an error when decoding the data.", FriendlyAgentName(msg)))
	}

	// Resynchronize
	TerminalSynchronize()
}

func TerminalProcessMessageHello(msg *star.Message) {
	var resMsg star.MessageHelloResponse
	var b bytes.Buffer

	b.Write(msg.Data)
	err := gob.NewDecoder(&b).Decode(&resMsg)
	if err == nil {
		AgentTrackerUpdateInfo(&resMsg.Node, &resMsg.Info)
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
		n, ok := agentNodeIDTracker[msg.Source]
		if ok {
			return fmt.Sprintf("%s", n.FriendlyName)
		} else {
			return fmt.Sprintf("%s", msg.Source)
		}
	}
}

func TerminalSynchronize() {
	printInfo("Synchronizing with agents...")
	syncMsg := star.NewMessageSyncRequest()
	syncMsg.Send(star.ConnectID{})
	AgentTrackerUpdateInfo(&star.ThisNode, &star.ThisNodeInfo)
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
var historyItemsMutex *sync.Mutex
var historyIndex uint

func HistoryPush(item historyItem) {
	historyItemsMutex.Lock()
	defer historyItemsMutex.Unlock()

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
	historyItemsMutex.Lock()
	defer historyItemsMutex.Unlock()

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
	LastSynced   time.Time
}

var agentFriendlyTracker map[string]*agentInfo
var agentNodeIDTracker map[star.NodeID]*agentInfo
var agentTrackerMutex *sync.Mutex

var agentFriendlyNameTracker int
var shellFriendlyNameCounter int
var terminalFriendlyNameCounter int
var unknownFriendlyNameCounter int

func AgentTrackerUpdateInfo(node *star.Node, info *star.NodeInfo) {
	agentTrackerMutex.Lock()
	defer agentTrackerMutex.Unlock()

	var i *agentInfo
	i, ok := agentNodeIDTracker[node.ID]
	if !ok {
		var name string
		switch node.Type {
		case star.NodeTypeAgent:
			agentFriendlyNameTracker++
			name = fmt.Sprintf("agent%03d", agentFriendlyNameTracker)
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
	i.LastSynced = time.Now()

	agentNodeIDTracker[node.ID] = i
	agentFriendlyTracker[i.FriendlyName] = i
}

func AgentTrackerRemoveInfo(id star.NodeID) {
	n, ok := AgentTrackerGetInfoByNodeID(id)
	if ok {
		agentTrackerMutex.Lock()
		defer agentTrackerMutex.Unlock()

		delete(agentFriendlyTracker, n.FriendlyName)
		delete(agentNodeIDTracker, id)
	}
}

func AgentTrackerGetInfoByFriendly(name string) (ai *agentInfo, ok bool) {
	agentTrackerMutex.Lock()
	defer agentTrackerMutex.Unlock()
	ai, ok = agentFriendlyTracker[name]
	return
}

func AgentTrackerGetInfoByNodeID(id star.NodeID) (ai *agentInfo, ok bool) {
	agentTrackerMutex.Lock()
	defer agentTrackerMutex.Unlock()
	ai, ok = agentNodeIDTracker[id]
	return
}

///////////////////////////////////////////////////////////////////////////////
