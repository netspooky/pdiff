from scapy.all import *
import sys
import hexdump
from collections import Counter 
import argparse

parser = argparse.ArgumentParser(description='pDiff')
parser.add_argument('-p', dest='inFile', help='Pcap File to Analyze')
parser.add_argument('-f', dest='pFilter', help='BPF Filter to use')
parser.add_argument('-m', dest='maxComp', help='Number of most common bytes to list per byte (Default: 20)')
parser.add_argument('-o', dest='bOffs', help='Offset to start at (Default: 0)')
parser.add_argument('-n', dest='bRange', help='Number of bytes to read (Default: 30)')
parser.add_argument('-l', dest='numLengths', help='Number of packet lengths to count for frequency (Default: 20)')
parser.add_argument('-x', dest='hexMode', help='Enable hex mode, view a hex dump of each packet, as well as packet metadata',action="store_true")
parser.add_argument('-a', dest='asciiPrint', help='Turns on printable chars for frequency analysis',action="store_true")
parser.add_argument('-t', dest='packetLimit', help='Total number of packets to read (Default: All)')

# Globals
minLength = 2   # Minimum payload length for a packet to be parsed
pBytes = {}     # This dict holds the actual bytes that will be analyzed
pLens = []      # A list to contain all of the packet lengths for averages

def iteratePackets(packets,packetLimit,bOffs):
    i = 0 # For the number of packets in the pcap
    n = 0 # This is to count the number of packets we processed.        
    for packet in packets:
        tcpPL = bytes(packet.payload.payload.payload)
        i = i+1 
        packetLimit = packetLimit - 1
        if len(tcpPL) > minLength:
            n = n+1 
            pLens.append(len(tcpPL))
            if hexMode:
                if TCP in packet:
                  print("\033[1;33mPACKET #{} - \033[38;5;219mSRC \033[1;36m{}:{} | \033[38;5;141mDST \033[1;36m{}:{}\033[0m".format(i,packet[IP].src,packet[TCP].sport,packet[IP].dst,packet[TCP].dport))
                elif UDP in packet:
                  print("\033[1;33mPACKET #{} - \033[38;5;219mSRC \033[1;36m{}:{} | \033[38;5;141mDST \033[1;36m{}:{}\033[0m".format(i,packet[IP].src,packet[UDP].sport,packet[IP].dst,packet[UDP].dport))
                hexdump.hexdump(tcpPL)
            x = bOffs # Byte number in given packet
            for b in tcpPL[bOffs:]:
                bNum = "p"+str(i) # The packet number
                pBytes[str(x)][bNum] = b # The actual payload data
                if x == (bRange+bOffs) - 1:
                    break
                x = x + 1
        if packetLimit == 0:
            break
    return n, i # Number of packets we processed, and total number of packets

# This function is used to list the most common values across a given set of packets.
# The optional -a flag is used to toggle printable characters being displayed next to the value.
def listCommon(pBytes,numPackets,totalPackets):
    print("\nListing top {} most common byte values found in {} packets! {} packets ignored.\n\033[0m".format(maxComp,numPackets,totalPackets-numPackets))
    for j in pBytes.keys():
      mc = Counter(pBytes[j].values()).most_common(maxComp) # Get most common values
      if len(mc) > 0:
        tBytes = len(pBytes[j])
        print("\033[1;33m[ Byte {} (0x{:02x})] Total: {}".format(j,int(j),tBytes))
        for m in mc:
            if asciiPrint: # This handles the printing of ascii characters 
                if m[0] < 127 and chr(m[0]).isprintable():
                  mPrint = chr(m[0])
                  print("  \033[38;5;219m0x{:02x}\033[0m - {}/{} ({}%)\t'{}'".format(m[0],m[1],tBytes,round((m[1]/tBytes)*100,2),mPrint)) 
                else:
                  print("  \033[38;5;219m0x{:02x}\033[0m - {}/{} ({}%)".format(m[0],m[1],tBytes,round((m[1]/tBytes)*100,2))) 
            else:
                print("  \033[38;5;219m0x{:02x}\033[0m - {}/{} ({}%)".format(m[0],m[1],tBytes,round((m[1]/tBytes)*100,2))) 

# This function is a simple way to determine the most common 
# lengths of packets and display the frequency per given length.
# Use the -l flag to override the default number of 20
def commonLengths(pLens,numLengths):
    c = Counter(pLens)
    mc = c.most_common(numLengths)
    print("\n{} most common packet lengths".format(numLengths))
    print("  Len\tFrequency")
    print("-----------------------")
    for l in mc:
        print("  {}\t{}".format(l[0],l[1]))

if __name__ == '__main__':
    ### Begin Argument Parsing ###
    args    = parser.parse_args()
    inFile  = args.inFile
    if args.bOffs:
        bOffs = int(args.bOffs)
    else: 
        bOffs = 0 # Where in the payload to start analysis
    if args.bRange:
        bRange = int(args.bRange)
    else:
        bRange = 30 # How many bytes to look at in each payload
    if args.pFilter:
        pFilter = args.pFilter
    else:
        pFilter = "" # Default filter is "none"
    if args.maxComp:
        maxComp = int(args.maxComp)
    else:
        maxComp = 10 # Default number of bytes to list in comparison
    if args.numLengths:
        numLengths = int(args.numLengths)
    else:
        numLengths = 20 # Default number of packet lengths to list in comparison
    if args.hexMode:
        hexMode = 1
    else:
        hexMode = 0
    if args.asciiPrint:
        asciiPrint = 1
    else:
        asciiPrint = 0
    if args.packetLimit:
        packetLimit = int(args.packetLimit)
    else:
        packetLimit = 0 # Default number of bytes to list in comparison
    ### End of Argument Parsing ###

    for k in range(bOffs,(bRange+bOffs)): # this initializes the list of bytes to log based on the range of bytes we want to look at
        pBytes[str(k)] = {}

    packets = sniff(offline=inFile,filter=pFilter) # Grabs the initial packet object 
    numPackets, totalPackets = iteratePackets(packets,packetLimit,bOffs) # Passes it to the packet iterator
    listCommon(pBytes,numPackets,totalPackets) # Lists the most common packets
    commonLengths(pLens,numLengths) # Prints the common lengths
