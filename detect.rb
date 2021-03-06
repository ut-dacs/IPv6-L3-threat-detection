#!/usr/bin/env ruby

require 'optparse'

options = {}
OptionParser.new do |opts|
    opts.banner = "Usage: detect.rb [options]"
    opts.on("-R", "--read DIR", "Specify input directory to read from (fbitdump style)") do |o|
        options[:input_dir] = o
    end
    opts.on("-s", "--syn-only", "Check for SYN-only flows, i.e. scanning threats") do |o|
        options[:syn_only] = o
    end
    opts.on("-p", "--pingsweep", "Check for ping sweeps") do |o|
        options[:pingsweep] = o
    end
    opts.on("-i", "--icmp", "Check for strange ICMP types/codes") do |o|
        options[:icmp] = o
    end
    opts.on("--cc-fl", "Check for Flow Label based Covert Channel") do |o|
        options[:ccfl] = o
    end
    opts.on("--cc-tc", "Check for Traffic Class based Covert Channel") do |o|
        options[:cctc] = o
    end
    opts.on("--fl-flood", "Check for flooding based on Flow Label") do |o|
        options[:fl_f] = o
    end
    opts.on("--frag-flood", "Check for flooding based on Fragmentation ID") do |o|
        options[:frag_f] = o
    end
    opts.on("--hopopt-flood", "Check for flooding based on IPv6 Hop-by-Hop Options") do |o|
        options[:hopopt_f] = o
    end
    opts.on("--frag-overlap", "Check for overlapping fragments") do |o|
        options[:frag_o] = o
    end
	opts.on("-h", "--help", "Prints this help") do
		puts opts
		exit
	end
end.parse!

FBITDUMP = '/usr/local/bin/fbitdump'
FBITDUMP_XML = 'fbitdump.xml'

# find high number of SYN-only flows, thus scanning tools

if options[:syn_only]
    syn_only_filter = "%flg & 2 = 2"
    output = %x(#{FBITDUMP} -R '#{options[:input_dir]}' -o 'fmt:%sa6 %dstport %fl' -A'%sa6,%dstport' '#{syn_only_filter}' -P '%fl > 100' -q)

    output.lines.each do |line|
        (sa6, dstport, fl) = line.split
        puts "Got #{sa6} with #{fl} SYN-only flows towards port #{dstport}"
    end
end

if options[:pingsweep]
    pingsweep_filter = "%proto IPv6-ICMP"
    output = %x(#{FBITDUMP} -R '#{options[:input_dir]}' -o 'fmt:%sa6 %fl' -A'%sa6' '#{pingsweep_filter}' -P '%fl > 1000' -q)

    output.lines.each do |line|
        (sa6, fl) = line.split
        puts "Got #{sa6} with #{fl} ICMP6 flows"
    end
end


if options[:icmp]
    IGNORE_TYPES    = [1,2,3,4,128,129,134,135,136,137] - [128,129]
    STRANGE_TYPES   = (0..256).to_a - IGNORE_TYPES
    icmp_type_filter = STRANGE_TYPES.map{|e| "%icmptype & 0xff00 == #{e << 8}"}.join(" or ")
    icmp_filter = "%proto IPv6-ICMP and #{icmp_type_filter}"
    output = %x(#{FBITDUMP} -q -R '#{options[:input_dir]}' -m%ts -o 'fmt:%ts %sa6 %da6 %icmptype' '#{icmp_filter}')
    output.lines.each do |line|
        (date, ts, sa6, da6, icmptype) = line.split
        puts "#{ts} #{sa6} -> #{da6} type:code #{icmptype.to_i >> 8}:#{icmptype.to_i & 0x00ff}" if icmptype.to_i & 0x00ff > 0
    end

    #TODO: check for 128/129 (ping) and other normal ICMP types, but for strange codes
    # %icmptype && 0x00ff should give the type, no further math needed
end


# Related to "Flow-based Detection of IPv6-specific Network Layer Attacks" paper:

if options[:ccfl]
    extra_element =  '%v6fl'
    output_format =  "fmt:%sa6 %da6 %srcport %dstport %proto %fl %pkt"
    output = %x(#{FBITDUMP} -q -C ~/fbitdump.xml -R '#{options[:input_dir]}'  -o'#{output_format}' '%pkt 1 and %v6fl > 0 and not %proto IPv6-Frag' -P'%pkt >= 50' -A'%sa6,%da6,%srcport,%dstport,%proto')
    output.lines.each do |line|
        (sa6, da6, sp, dp, pr, fl) = line.split
        output2 = %x(#{FBITDUMP} -q -C ~/fbitdump.xml -R '#{options[:input_dir]}'  -A'%sa6,%da6,%srcport,%dstport,%proto,#{extra_element}' -N1 -o'#{output_format} #{extra_element}' '%sa6 #{sa6} and %da6 #{da6} and %srcport #{sp} and %dstport #{dp} and %proto #{pr}')

        if output2.lines.length > 10
            puts "CCFL #{sa6} -> #{da6} #{fl} vs #{output2.lines.length}"
            puts output2.lines
            puts "-"*20
        end
    end


end

if options[:fl_f]
    output_format =  "fmt:%sa6 %pkt %byt %fl"
    output = %x(#{FBITDUMP} -q -C ~/fbitdump.xml -R '#{options[:input_dir]}'  -A'%sa6' -o'#{output_format}' '%v6fl > 0 and %pkt 1' -P'%pkt >= 100' )
    output.lines.each do |line|
        (sa6, pkt, byt, fl) = line.split
        output2 = %x(#{FBITDUMP} -q -C ~/fbitdump.xml -R '#{options[:input_dir]}' -A'%sa6,%da6prf' '%v6fl > 0 and %pkt 1 and %sa6 #{sa6}' | grep "#{sa6}" )
        if output2.lines.length >= pkt.to_i # pkt == fl in the original query
            puts "FL_F suspicious traffic from #{sa6}, #{pkt} packets in #{fl} flows, second query gave #{output2.lines.length} records"
        end
    end
end



if options[:cctc]
    extra_element =  '%v6tc'
    output_format =  "fmt:%sa6 %da6 %srcport %dstport %proto %fl %pkt"
    # the post-aggr filter fl >= 100 selects flows that consist of more than 100 flow records, thus something other than the -A fields differs for each of the flow records
    # this was %pkt before, but %fl is more efficient: it makes sure there was something different from the fields in the -A
    output = %x(#{FBITDUMP} -q -C ~/fbitdump.xml -R '#{options[:input_dir]}'  -o'#{output_format}' '%v6tc > 0 and not %proto IPv6-Frag' -P'%fl >= 50' -A'%sa6,%da6,%srcport,%dstport,%proto')
    output.lines.each do |line|
        (sa6, da6, sp, dp, pr, fl) = line.split
        output2 = %x(#{FBITDUMP} -q -C ~/fbitdump.xml -R '#{options[:input_dir]}'  -A'%sa6,%da6,%srcport,%dstport,%proto,#{extra_element}' -o'#{output_format} #{extra_element}' '%sa6 #{sa6} and %da6 #{da6} and %srcport #{sp} and %dstport #{dp} and %proto #{pr}' | grep "#{sa6}[[:space:]]*#{da6}")

        if output2.lines.length > 10
            puts "CCTC #{sa6} -> #{da6} #{fl} vs #{output2.lines.length}"
            puts output2.lines
            puts "-"*20
        end
    end

end

if options[:frag_f]
    output = %x(#{FBITDUMP} -q -C ~/fbitdump.xml -R '#{options[:input_dir]}' '%proto 44 and %pkt >= 500 and %td < 5000 ' )
    output.lines.each do |line|
        puts "FRAG_F #{line}"
    end

    # in case of 'spread' attack, towards generated addresses
    output = %x(#{FBITDUMP} -q -C ~/fbitdump.xml -R '#{options[:input_dir]}' -A'%sa6' -o'fmt:%td,%sa6,%pkt,%pps' '%proto 44 and %pkt 1' -P'%pkt >= 200 and %td < 5000' )
    output.lines.each do |line|
        puts "FRAG_F SPREAD: #{line}"
    end
end

if options[:hopopt_f]
    output = %x(#{FBITDUMP} -q -C ~/fbitdump.xml -R '#{options[:input_dir]}' '%proto 0'  -A'%sa6,%da6,%srcport,%dstport,%proto' -P'%pkt > 10' )
    output.lines.each do |line|
        puts "HOPOPT_F #{line}"
    end

    # Spread version
    output = %x(#{FBITDUMP} -q -C ~/fbitdump.xml -R '#{options[:input_dir]}' -A'%sa6' -o'fmt:%sa6,%pkt,%pps' '%proto 0 and %pkt 1' -P'%pkt >= 10' )
    output.lines.each do |line|
        puts "HOPOPT_F SPREAD: #{line}"
    end
end


if options[:frag_o]
    output_format =  "fmt:%sa6 %da6 %srcport %dstport %proto %fl %v6fragoverlap %v6fragminoffset %v6fragnxt %v6fragnxtsrc %v6fragnxtdst"
    output = %x(#{FBITDUMP} -q -C ~/fbitdump.xml -R '#{options[:input_dir]}' -o'#{output_format}' '%proto 44 and %v6fragminoffset > 0 and %v6fragminoffset < 20' )
    output.lines.each do |line|
        puts "FRAG_O #{line}"
    end
end
