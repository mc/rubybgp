require 'socket'
require 'ipaddr'

require 'bgpconst.rb'
require 'bgppacket.rb'

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

