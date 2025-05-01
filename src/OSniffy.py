#!/usr/bin/env python3

import argparse
import reader
import settings

OSniffy = """
 ██████╗ ███████╗███╗   ██╗██╗███████╗███████╗██╗   ██╗
██╔═══██╗██╔════╝████╗  ██║██║██╔════╝██╔════╝╚██╗ ██╔╝
██║   ██║███████╗██╔██╗ ██║██║█████╗  █████╗   ╚████╔╝
██║   ██║╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝    ╚██╔╝
╚██████╔╝███████║██║ ╚████║██║██║     ██║        ██║
 ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝        ╚═╝
 """

parser = argparse.ArgumentParser(description="A simple sniffing tool made by @lassa97", usage="%(prog)s [options] [FILE]", add_help=False)
parser.add_argument("-s", "--sniffer", help="Run the program in sniffer mode", action="store_true")
parser.add_argument("-r", "--reader", help="Read a capture file", action="store_true")
parser.add_argument("-f", "--file", help="The path of the .pcap file", default="/dev/null")
parser.add_argument("-v", "--version", action="version", help="Show program's version number and exit", version="%(prog)s 1.0")
args = parser.parse_args()
if args.sniffer:
    if settings.os.getenv("USER") == "root":
        print(OSniffy)
        import sniffer
        print("Running in sniffer mode...")
        sniffer.main()
    else:
        print("You should run the sniffer using sudo")
elif args.reader:
    if args.file is "/dev/null":
        print(OSniffy)
        parser.print_help()
    else:
        print(OSniffy)
        print("Reading {FILE}...".format(FILE=args.file))
        reader.main(args.file)
else:
    print(OSniffy)
    parser.print_help()
