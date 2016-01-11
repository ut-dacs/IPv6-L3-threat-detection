# detect.rb

Search for network level threats in flow data:


'''
Usage: detect.rb [options]
    -R, --read DIR                   Specify input directory to read from (fbitdump style)
    -s, --syn-only                   Check for SYN-only flows, i.e. scanning threats
    -p, --pingsweep                  Check for ping sweeps
    -i, --icmp                       Check for strange ICMP types/codes
        --cc-fl                      Check for Flow Label based Covert Channel
        --cc-tc                      Check for Traffic Class based Covert Channel
        --fl-flood                   Check for flooding based on Flow Label
        --frag-flood                 Check for flooding based on Fragmentation ID
        --hopopt-flood               Check for flooding based on IPv6 Hop-by-Hop Options
        --frag-overlap               Check for overlapping fragments
    -h, --help                       Prints this help
'''
