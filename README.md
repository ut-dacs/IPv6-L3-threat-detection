# detect.rb

Search for network level threats in flow data:


```
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
```


# gen_attack.py

Generate synthetic attacks:

```
usage: gen_attack.py [-h] [--cc-flowlabel] [--no-payload] [--cc-traffic-class]
                     [--fl-flood] [--frag-flood] [--hopopt-flood]
                     [--frag-overlap] -d DESTINATION [-s SOURCE] [-g] -o
                     OUTFILE

optional arguments:
  -h, --help            show this help message and exit
  --cc-flowlabel        Create covert channel in Flow Label
  --no-payload          Create trace without L4/L5
  --cc-traffic-class    Create covert channel in Traffic Class fields
  --fl-flood            Create flow label DoS attack
  --frag-flood          Create fragment flood attack
  --hopopt-flood        Create Hop-by-Hop header flood attack
  --frag-overlap        Create overlapping fragment with port rewrite attempt
                        in second packet
  -d DESTINATION, --destination DESTINATION
                        Destination IPv6 address
  -s SOURCE, --source SOURCE
                        Source IPv6 address
  -g, --generate
  -o OUTFILE, --outfile OUTFILE
                        PCAP output file ID

```
