require 'socket'
require 'ipaddr'

require 'bgpconst.rb'
require 'bgppacket.rb'

class BGP::Session
	def initialize(local, remote)
		@local = local
		@remote = remote

		@socket = TCPSocket.new(@remote.ip, 179)
		@fsm = BGP::FSM::IDLE

		establish

		p = BGP::Packet::KeepAlive.new()
		@socket.send( p.to_s, p.len )
		while (1==1)
			input
		end
	end

	def establish
		p = BGP::Packet::Open.new(@local.asn, IPAddr.new(@local.router_id), 30, 4)
		@socket.send( p.to_s, p.len )
		@fsm = BGP::FSM::OPENSENT

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
			when BGP::MSG_TYPE::OPEN
				packet = BGP::Packet::Open.from_s(body, length)
				puts packet.inspect
			when BGP::MSG_TYPE::UPDATE
				packet = BGP::Packet::Update.from_s(body, length)
				puts packet.inspect
			when BGP::MSG_TYPE::NOTIFICATION
				parse_notification(body)
			when BGP::MSG_TYPE::KEEPALIVE
				packet = BGP::Packet::KeepAlive.new()
				@socket.send(packet.to_s, packet.len)
				if ( @fsm == BGP::FSM::OPENSENT ||
				     @fsm == BGP::FSM::OPENCONFIRM )
					@fsm = BGP::FSM::ESTABLISHED
				end
		end

	end

	def parse_notification(body)
		puts "recv notif"
	end
end

