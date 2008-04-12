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

module BGPHEADER_TYPE
	OPEN = 1
	UPDATE = 2
	NOTIFICATION = 3
	KEEPALIVE = 4
end

module BGPFSM
	IDLE = 1
end

class BgpSession
	def initialize(local, remote)
		@local = local
		@remote = remote

		@socket = TCPSocket.new(@remote.ip, 179)
		@fsm = BGPFSM::IDLE

		establish

		input

		p = BgpPacket::KeepAlive.new()
		@socket.send( p.to_s, p.len )
		while (1==1)
			input
		end
	end

	def establish
		p = BgpPacket::Open.new(@local.asn, IPAddr.new(@local.router_id), 30, 4)
		@socket.send( p.to_s, p.len )
	end

	def input
		data = Array.new
		data[0] = ""
		while (data[0] == "") ## XXX is_empty?
			data = @socket.recvfrom(19)
		end
		header = data[0]

		length = (((header[16] * 8) + header[17]) - 19)
		if (length < 0 || length > (4096-19))
			raise Error
		end

		flagsint = header[18]
		
		if ( length > 0 )
			data = @socket.recvfrom(length)
			body = data[0]
		else
			body = nil
		end


		case flagsint
			when BGPHEADER_TYPE::OPEN
				if length >= 10
					parse_open(body)
				else
					raise Error
				end
			when BGPHEADER_TYPE::UPDATE
				parse_update(body)
			when BGPHEADER_TYPE::NOTIFICATION
				parse_notification(body)
			when BGPHEADER_TYPE::KEEPALIVE
				packet = BgpPacket::KeepAlive.new()
				@socket.send(packet.to_s, packet.len)
		end

	end

	def parse_open(body)
		#################  12241
		res = body.unpack("Cnna4C")

		packet = BgpPacket::Open.new(res[1], IPAddr.ntop(res[3]), res[2], res[0])

		optlen  = res[4]

		# XXX parse opt parms XXX #
	end

	def parse_update(body)
		wlen = (body[0] * 8) + body[1]

	end
end

class BgpPeer
	attr_accessor :asn, :router_id, :ip

	def initialize(asn)
		@asn = asn
	end
end

myself = BgpPeer.new("999")
myself.router_id = "10.20.30.40"

rpeer = BgpPeer.new("7675")
rpeer.ip = "127.0.0.1"

BgpSession.new(myself, rpeer)

