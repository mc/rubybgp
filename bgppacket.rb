require 'ipaddr'

require 'bgpconst.rb'

module BgpPacket
	class Plain
		@type
	end

	class Open
		def initialize(asn, id, holdtimer=30, version=4)
			@asn = asn
			@id = id
			@hold = holdtimer
			@ver = version
		end

		def to_s
			p = Array.new
			0.upto(3) do |x|
				p[x] = 4294967295
			end
			p[4] = 29
			p[5] = BGPHEADER_TYPE::OPEN
			p[6] = @ver.to_i
			p[7] = @asn.to_i
			p[8] = @hold.to_i
			p[9] = @id.hton
			p[10] = 0
			p.pack("NNNNnccnna4c")
		end

		def len
			return 30
		end
	end
	class KeepAlive
		def initialize
		end

		def to_s
			p = Array.new
			0.upto(3) do |x|
				p[x] = 4294967295
			end
			p[4] = 19
			p[5] = BGPHEADER_TYPE::KEEPALIVE
			p.pack("NNNNnc")
		end

		def len
			return 20
		end
	end
end

