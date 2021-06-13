<p align="center"><img src="./_imgs/startarot.jpg" alt="STAR Tarot Card" width="300"/><br/></p>

# **S**imple **T**actical **A**gent **R**elay (**STAR**)

S.T.A.R. is intended as a post-exploitation framework for ethical hackers and security researchers. It serves as a sort of peer-to-peer C2, and can be used in environments with no/partial internet access.

The inspiration for the tool is due to the author working on HackTheBox's Dante ProLab and not liking the "feel" of existing C2/pivoting tools that were attempted. S.T.A.R. is made more for the author's needs/wants than anything else, but if anyone else can find benefit from it, all the better.

## Installation

1. _It is assumed that you already have the latest version of golang installed on your machine._
1. Clone the repository to your local machine with `git clone https://github.com/CyberSecurityN00b/star.git`
1. From within the repository, run `./build-star.sh`
1. You should now have a batch of agents (in `./bin/agents/`) and terminals (in `./bin/terminals/`); additionally, you will have a terminal compiled for your local machine at `./bin/star_terminal`.

For each new engagement, you should update the respository and re-run `./build-star.sh`. It is highly discouraged to use the same binaries between engagements. Node development is such that constants should not be expected to be the same between updates and a new SSL/TLS cert is generated each time as well.

_Note: Until all features are developed, nodes will not enforce the requirement that connecting nodes have the expected SSL/TLS certificaiton. Once development is completed, this will be implemented and batches of nodes will not be able to communicate with other batches of nodes._

## Concepts and Terminology

| Term | Definition |
| --- | --- |
| **Agent** | An agent is a node that is placed on a remote computer for post-exploitaiton purposes. Agents should only be placed on computers where RCE is intended. If RCE is not intended, use a terminal instead. |
| **Connection** | A connection is an existing link between S.T.A.R. nodes or, in the case of fileservers and shells, an external 3rd party. |
| **Constellation** | A collection of interconnected agent/terminal nodes. Best practice is to create a separate constellation per engagement. |
| **FileServer** | A S.T.A.R. fileserver allows for an agent to serve a file that is located elsewhere within the constellation. The file is not transferred until the request is made, and is not saved to the agent's local file system. |
| **Listener** | A listener is an open port waiting for one or more connections. These may be S.T.A.R. connections, shell connections, or requests to fileservers. |
| **Node** | A node is either an agent or terminal that is part of the S.T.A.R. constellation. |
| **Shell** | Shells allow for a remote computer to connect to the constellation using netcat or similar. These are useful where a S.T.A.R. node is not appropriate for the device or the security researcher has not yet attained post-exploitation status on the device. Note: Shells only allow the security researcher to run commands on the device, S.T.A.R. commands do not work with shells. |
| **Stream** | A stream is used for I/O within the constellatoin. Streams are used by shells, fileservers, and RCE commands.  |
| **Terminal** | A terminal is a node that is used to interact with agents in the constellation. A terminal should be used instead of an agent where RCE is not intend, such as a proxy point controlled by the security researcher. |

## Using

Use a terminal on the security researcher's computer to interact with the constellation. Run agents on remote machines or any machine where RCE is acceptable.

Agents can be configured with hard-coded connection instructions, either to create a listener or attempt a connection, when run. At the time of this writing, agents will listen on port `42069` by default.

When either agents or terminals are run, connection instructions can be passed as command-line arguments for either creating listeners or attempting connections. Some examples:
* **`star_agent b:12345`** - Creates a listener bound on port `12345`
* **`star_agent b:10.10.10.10:1111`** - Creates a listener bound on port `1111` of the interface with an IPv4 address of `10.10.10.10`
* **`star_agent c:www.example.com:8080`** - Attempts to connect to a S.T.A.R. node listening on port `8080` of `www.example.com`.

All of the above commands can be combined, i.e.: `star_agent b:12345 b:10.10.10.10:111 c:www.example.com:8080`. In this instance, the agent will attempt all specified listeners and connections, in addition to the hard-coded ones.

## Commands

S.T.A.R. Commands:
| Commands | Description |
| --- | --- |
| :?<br/>:help |  Displays generic or cmd specific help. |
| :: | Passes on text to the focused agent. Only really useful when passing text that starts with a ':'. |
| :b<br/>:bind | Creates a S.T.A.R. node listener and binds it to a port. |
| :c<br/>:connect | Connects to a S.T.A.R. node listener. |
| :clear | Clears the terminal screen, cause apparently some people are into that. |
| :chat | Communicate with other security researchers in the constellation. |
| :d<br/>:down<br/>:download | Downloads a file from the agent to the terminal. |
| :h<br/>:history | Displays the command/chat history. |
| :i<br/>:info<br/> | Shows information for a specific agent. |
| :j<br/>:jump | Changes focus (or "jumps to") another agent or stream. |
| :k<br/>:kill<br/>:killswitch | Panic button! Destroy and cleans up constellation. _Note: Will not be fully implemented until development is complete._ |
| :l<br/>:list | Lists agents, connections, and streams (commands). |
| :pf<br/>:portforward | Port forwarding. _**Not yet implemented.**_ |
| :p<br/>:proxy | SOCKS5 proxy. _**Not yet implemented.**_ |
| :s<br/>:set<br/>:setting<br/>:settings | View/set configuration settings. |
| :sync | Forces constellation synchronization. |
| :t<br/>:terminate | Terminate an agent, connection, or stream (command). |
| :u<br/>:up<br/>:upload | Uploads a file from the terminal to the agent. |
| :q<br/>:quit | Quits the current terminal. |

Build-In Local Commands:
| Commands | Description |
| --- | --- |
| :lcat | Outputs the contents of a local file. |
| :lcd | Changes the directory for the local terminal. |
| :lls<br/>:ldir | Lists the files in the local terminal's working directory. |
| :lmkdir | Creates a directory locally and changes the terminal's working directory to it. |
| :lpwd | Prints the local terminal's working directory. |
| :ltmpdir | Creates a temporary directory locally and changes the terminal's working directory to it. |

Build-In Remote Commands:
| Commands | Description |
| --- | --- |
| :rcat | Outputs the contents of a remote file. |
| :rcd | Changes the directory for the remote agent. |
| :rls<br/>:ldir | Lists the files in the remote agent's working directory. |
| :rmkdir | Creates a directory remotely and changes the agent's working directory to it. |
| :rpwd | Prints the remote agents's working directory. |
| :rtmpdir | Creates a temporary directory remotely and changes the agents's working directory to it. |

## Misc.

### Artwork

TODO: Credit

### Legal*ish*

This tool is intended for ethical hackers and security researchers. The author is not responsible for any negative impact, intentional or otherwise, made through the use of this tool.

### Future Development

Once all currently planned features are implemented, development of this tool by the author will be limited to maintenance, bug fixes, and security issues. New features are not at all likely to be implemented; feature requests in the nature of exploitation, enumeration, etc. will not be entertained.