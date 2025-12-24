from CSVPacket import Packet, CSVPackets
import sys
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-stats', action='store_true', help='Show port statistics')
parser.add_argument('--countip', action='store_true', help='Count distinct IP addresses')
parser.add_argument('csvfile', help='CSV file to analyze')
parser.add_argument('--protocol', type=int, help='Filter by IP protocol number')
parser.add_argument('--connto', action='store_true', help='Count connections to services (ports 1-1024)')

args = parser.parse_args()

IPProtos = [0 for x in range(256)]
numBytes = 0
numPackets = 0
csvfile = open(args.csvfile,'r')

tcp_ports = {}
udp_ports = {}
ip_counts = {}
prot_ip = {}
connto_data = {}

for pkt in CSVPackets(csvfile):
    # pkt.__str__ is defined...
    #print pkt
    numBytes += pkt.length
    numPackets += 1
    proto = pkt.proto & 0xff
    IPProtos[proto] += 1
    if args.stats:
        if proto == 6 and pkt.tcpdport is not None:  # TCP
            port = pkt.tcpdport
            if 1 <= port <= 1024:
                tcp_ports[port] = tcp_ports.get(port, 0) + 1
        elif proto == 17 and pkt.udpdport is not None:  # UDP
            port = pkt.udpdport
            if 1 <= port <= 1024:
                udp_ports[port] = udp_ports.get(port, 0) + 1
    
    if args.countip:
        # Only count if protocol matches (if --protocol filter is set)
        if args.protocol is None or proto == args.protocol:
            if pkt.ipsrc is not None:
                ip_counts[pkt.ipsrc] = ip_counts.get(pkt.ipsrc, 0) + 1
                prot_ip[pkt.ipsrc] = proto
            if pkt.ipdst is not None:
                ip_counts[pkt.ipdst] = ip_counts.get(pkt.ipdst, 0) + 1
                prot_ip[pkt.ipdst] = proto

    if args.connto:
        if pkt.ipdst is not None:
            dport = None
            proto_name = None
            if proto == 6 and pkt.tcpdport is not None:  # TCP
                dport = pkt.tcpdport
                proto_name = 'tcp'
            elif proto == 17 and pkt.udpdport is not None:  # UDP
                dport = pkt.udpdport
                proto_name = 'udp'
            
            if dport is not None and 1 <= dport <= 1024:
                if pkt.ipdst not in connto_data:
                    connto_data[pkt.ipdst] = {'ports': set(), 'sources': set()}
                connto_data[pkt.ipdst]['ports'].add((proto_name, dport))
                if pkt.ipsrc is not None:
                    sport = pkt.tcpsport if proto == 6 else pkt.udpsport
                    if sport is not None:
                        connto_data[pkt.ipdst]['sources'].add((pkt.ipsrc, sport))

if args.stats:
    print ("numPackets:%u numBytes:%u" % (numPackets,numBytes))
    for i in range(256):
        if IPProtos[i] != 0:
            print ("%3u: %9u" % (i, IPProtos[i]))
    
    tcp_ports_keys = sorted(tcp_ports.keys())
    udp_ports_keys = sorted(udp_ports.keys())
    # Print TCP port statistics
    print("\nTCP Destination Ports (1-1024):")
    for port in tcp_ports_keys:
        print("  TCP port %d: %d packets" % (port, tcp_ports[port]))
    
    # Print UDP port statistics
    print("\nUDP Destination Ports (1-1024):")
    for port in udp_ports_keys:
        print("  UDP port %d: %d packets" % (port, udp_ports[port]))

if args.countip:
    ips_sorted = sorted(ip_counts.items(), key=lambda i: i[1], reverse= True)
    for ip, count in ips_sorted:
        print(f"{ip}, {prot_ip[ip]}: {count}")

if args.connto:
    # Sort by number of distinct sources (descending)
    sorted_dests = sorted(connto_data.items(), key=lambda x: len(x[1]['sources']), reverse=True)
    
    for ipdst, data in sorted_dests:
        num_sources = len(data['sources'])
        # Sort ports for consistent output
        sorted_ports = sorted(data['ports'], key=lambda x: (x[0], x[1]))
        ports_str = ', '.join([f"{proto}/{port}" for proto, port in sorted_ports])
        print(f"{ipdst} has {num_sources} distinct ipsrc on ports: {ports_str}")
    

