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

		p = BgpPacket::KeepAlive.new()
		@socket.send( p.to_s, p.len )
		while (1==1)
			input
		end
	end

	def establish
		p = BgpPacket::Open.new(@local.asn, IPAddr.new(@local.router_id), 30, 4)
		@socket.send( p.to_s, p.len )
		@fsm = BGPFSM::OPENSENT

		input
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
			when BGP_MSG_TYPE::OPEN
				if length >= 10
					parse_open(body)
				else
					raise Error
				end
				@fsm = BGPFSM::OPENCONFIRM
			when BGP_MSG_TYPE::UPDATE
				parse_update(body, length)
			when BGP_MSG_TYPE::NOTIFICATION
				parse_notification(body)
			when BGP_MSG_TYPE::KEEPALIVE
				packet = BgpPacket::KeepAlive.new()
				@socket.send(packet.to_s, packet.len)
				if ( @fsm == BGPFSM::OPENSENT ||
				     @fsm == BGPFSM::OPENCONFIRM )
					@fsm = BGPFSM::ESTABLISHED
				end
		end

	end

	def parse_open(body)
		puts "recv open"
		#################  12241
		res = body.unpack("Cnna4C")
		packet = BgpPacket::Open.new(res[1], IPAddr.ntop(res[3]), res[2], res[0])

		optlen  = res[4]
		body.slice!(0..9)
		while (optlen > 0)
			captype = body[0]
			caplen = body[1]
			body.slice!(0..1)
			capparm = body.slice!(0..(caplen-1))

			puts "Received capability #{captype} : #{caplen}"
			optlen = optlen - ( caplen + 2 )
		end
	end

	def parse_update(body, tlen)
		puts "recv update"

		wlen = body.unpack("n")
		body.slice!(0..(wlen[0] + 1))

		palen = body.unpack("n")
		body.slice!(0..(palen[0] + 1))

		alen = (tlen + 19) - 23 - palen[0] - wlen[0]
		body.slice!(0..alen)

		puts "recv update (#{alen} = (#{tlen} + 19) - #{palen[0]} - #{wlen[0]})"
	end

	def parse_notification(body)
		puts "recv notif"
	end
end

