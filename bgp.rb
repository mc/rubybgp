require 'socket'
require 'ipaddr'

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
			p[5] = BGPNOTIFICATION::OPEN
			p[6] = @ver
			p[7] = @asn
			p[8] = @hold
			p[9] = @id.hton
			p[10] = 0
			p.pack("NNNNnccnna4c")
		end
	end
end

module BGPNOTIFICATION
	OPEN = 1
	UPDATE = 2
	NOTIFICATION = 3
	KEEPALIVE = 4
end

class BgpSession
	def initialize(ip)
		@@socket = TCPSocket.new(ip, 179)
		@@socket.puts( BgpPacket::Open.new(999, IPAddr.new("20.30.40.50"), 30, 4) )
		input
	end

	def input
		data = Array.new
		data[0] = ""
		while (data[0] == "") ## XXX is_empty?
			data = @@socket.recvfrom(19)
		end
		puts(data.inspect)
		header = data[0]

		length = (((header[16] * 8) + header[17]) - 19)
		if (length < 0 || length > (4096-19))
			raise Error
		end

		flagsint = header[18]
		
		data = @@socket.recvfrom(length)
		body = data[0]

		case flagsint
			when BGPNOTIFICATION::OPEN
				puts "open\n"
				if length >= 10
					parse_open(body)
				else
					raise Error
				end
			when BGPNOTIFICATION::UPDATE
				parse_update(body)
			when BGPNOTIFICATION::NOTIFICATION
			when BGPNOTIFICATIOn::KEEPALIVE
		end

	end

	def parse_open(body)
		#################  12241
		res = body.unpack("Cnna4C")

		packet = BgpPacket::Open.new(res[1], IPAddr.ntop(res[3]), res[2], res[0])
		puts packet.inspect

		optlen  = res[4]

		# XXX parse opt parms XXX #
	end

	def parse_update(body)
		wlen = (body[0] * 8) + body[1]

	end
end

BgpSession.new("localhost")
