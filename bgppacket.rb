require 'ipaddr'

require 'bgpconst.rb'
require 'bgpcap.rb'

module BGP::Packet
	class Plain
		@type
	end
	
	class Header
	end

	class Open
		def initialize(asn, id, holdtimer=30, version=4)
			@asn = asn
			@id = id
			@hold = holdtimer
			@ver = version
			@caps = Array.new
		end

		def self.from_s(str, len)
			res = str.unpack("Cnna4C")
			obj = BGP::Packet::Open.new(res[1], IPAddr.ntop(res[3]), res[2], res[0])
			str.slice!(0..9)
			len = len - 10

			while (len > 0)
				opttype = str[0]
				optlen = str[1]
				str.slice!(0..1)
				optparm = str.slice!(0..(optlen-1))

				puts "recv opt #{opttype} : #{optlen}"

				if (opttype == 2)  # OPTION: CAPABILITY as defined in RFC3392
					puts BGP::CAP::Plain.from_s(optparm, optlen).inspect
				end

				len = len - optlen - 2
			end

			return obj
		end

		def to_s
			p = Array.new
			0.upto(3) do |x|
				p[x] = 4294967295
			end
			p[4] = 29
			p[5] = BGP::MSG_TYPE::OPEN
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
			p[5] = BGP::MSG_TYPE::KEEPALIVE
			p.pack("NNNNnc")
		end

		def len
			return 20
		end
	end
end

