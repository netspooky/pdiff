# pDiff - Binary Protocol Differ

This is a simple script to do some basic differential analysis of a pcap and provide insight 
into unknown protocols.

You can analyze a pcap using a bpf filter, but it is not required.

There are a number of flags you can use to limit or expand your search.

| Flag | Description |
|------|-------------|
| -p file.pcap | Specify the pcap to analyze |
| -f "bpf filter" | BPF Filter to use |
| -m number | The number of most common bytes to list per byte offset |
| -n | Number of bytes to read for analysis (Default: 30) |
| -l | Number of packet lengths to count for frequency (Default: 20) |
| -x | Enable hex mode, view a hex dump of each packet, as well as packet metadata |
| -a | Turns on printable chars for frequency analysis |
| -t number | Total number of packets to read (Default: All) |
| -o | Offset to start at within the packet's payload (Default: 0) |

Things to note:

- Bytes and offsets are 0 indexed, packets are 1 indexed.
- Packets are ignored when they don't meet the minimum length for packet payload (default 2)
- Currently only supports TCP and UDP

PRs are welcome! This tool, like many other packet parsing tools, may have some unexpected bugs. Use at your own risk.

## Requirements

- python3 
- scapy
- tcpdump

## Example Usage

Read file with filter, in output bytes show printable characters

    python3 pDiff.py -p some_random.pcap -f "tcp dst port 1900" -a

Read file with filter, show the output of each packet in hex, only scan 10 packets of the pcap

    python3 pDiff.py -p some_random.pcap -f "udp dst port 5555" -x -t 10

Read file without filter, show the output of each packet in hex, start at offset 2 within packet, read 10 bytes

    python3 pDiff.py -p some_random.pcap -x -o 2 -n 10 

Read file with filter, do statistics on 60 bytes instead of default 30

    python3 pDiff.py -p randompcap2.pcap -f "dst net 192.168.1.0/24 && (udp dst port 5555 or udp dst port 9999)" -n 60

## Tips 

- Eyeball sequence numbers by observing the frequency of certain bytes and if they look sequential.
- Pick out delimiters and possibly padding of certain data types when all the values of a particular byte are the same.
