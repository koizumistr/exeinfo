class ExeHeaderParser
  attr_reader :magic, :cblp, :cp, :crlc, :cparhder, :minalloc, :maxalloc, :ss, :sp, :checksum,
              :ip, :cs, :lfarlc, :ovno, :re1, :re2

  def readword
    @f.readbyte + @f.readbyte * 256
  end

  def parseheader(file, level = 0)
    @f = file  
    if file.size < 0x1b then
      print "Error"
      exit
    end
    if file.readbyte != 0x4d then #M
      print "Error2"
      exit
    end
    if file.readbyte != 0x5a then #Z
      print "Error3"
      exit
    end

    @magic = 0x4d5a
    @cblp = readword
    @cp = readword
    @crlc = readword
    @cparhder = readword
    @minalloc = readword
    @maxalloc = readword
    @ss = readword
    @sp = readword
    @checksum = readword
    @ip = readword
    @cs = readword
    @lfarlc = readword
    @ovno = readword

    if level == 0 then
      return
    end

    if level > 1 then
      @re1 = String.new
      (@lfarlc - 0x1c).times do
        @re1 = @re1 + " " + sprintf("%02x", file.readbyte)
      end
    else
      (@lfarlc - 0x1c).times { file.readbyte }
    end

    @offset = Array.new
    @segment = Array.new
    @crlc.times do |i|
      @offset[i] = readword
      @segment[i] = readword
    end

    if level > 1 then
      @re2 = String.new
      (@cparhder * 16 - @lfarlc - @crlc * 4).times do
        @re2 = @re2 + " " + sprintf("%02x", file.readbyte)
      end
    else
      (@cparhder * 16 - @lfarlc - @crlc * 4).times {file.readbyte}
    end
#    puts file.readbyte # XXXX
  end

  def offset(i)
    @offset[i]
  end
  def segment(i)
    @segment[i]
  end
end
# (cp - 1) * 512 + cblp = filesize
