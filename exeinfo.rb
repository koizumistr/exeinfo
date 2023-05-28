require_relative 'exeheaderparser'
require 'optparse'

params = {}
opt = OptionParser.new
opt.version = [1, 0]
opt.banner = "Usage: exeinfo.rb [option] EXE_FILE"
opt.on('-t', 'output relocation table')
opt.on('-r', 'also output reserved regions')

begin
  opt.parse!(ARGV, into: params)
#p ARGV
#p params
rescue
  puts opt.help
  exit(-1)
end

if ARGV.length != 1
  puts opt.help
  exit(-2)
end

if not params[:r].nil? then
  level = 2
elsif not params[:t].nil? then
  level = 1
else
  level = 0
end

File.open(ARGV[0], "rb") do |file|
  t = ExeHeaderParser.new
  t.parseheader(file, level)
  if not t.parsed then
    puts t.message
    exit
  end

  puts sprintf("magic number: %4x", t.magic)
  puts sprintf("bytes in last page: %d", t.cblp)
  puts sprintf("pages: %d", t.cp)
  puts (t.cp - 1) * 512 + t.cblp
  puts file.size
  puts sprintf("relocations: %d", t.crlc)
  puts sprintf("header size (in paragraph): %d", t.cparhder)
  puts sprintf("minalloc: %4x (%d)", t.minalloc, t.minalloc)
  puts sprintf("maxalloc: %4x (%d)", t.maxalloc, t.maxalloc)
  puts sprintf("ss: %04x", t.ss)
  puts sprintf("sp: %04x", t.sp)
  puts sprintf("checksum: %04x", t.checksum)
  puts sprintf("ip: %04x", t.ip)
  puts sprintf("cs: %04x", t.cs)
  puts sprintf("relocation table offset: %x", t.lfarlc)
  puts sprintf("overlay num: %x", t.ovno)

  if level > 1 then
    puts "-- reserved 1 --"
    puts t.re1
  end

  if level > 0 then
    puts "-- relocation table --"
    t.crlc.times do |i|
      puts sprintf("[%04x %04x]", t.offset(i), t.segment(i))
    end
  end

  if level > 1 then
    puts "-- reserved 2 --"
    puts t.re2
  end
end
