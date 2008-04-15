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
			puts "  ---------------------------------------------------------------"
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

		if (header[16] && header[17])
			length = (((header[16] * 256) + header[17]) - 19)
		else
			puts "warnung, kaputtes bgp packet ... " + header.inspect
		end

		if (length < 0 || length > (4096-19))
			puts "warnung: BGP Packet hat falsche groesse " + length.inspect + " :: " + header.inspect
		end

		flagsint = header[18]
		
		if ( length > 0 )
			read_byte = 0
			body = ""
			while (read_byte < length)
				data = @socket.recvfrom(length - read_byte)
				puts "##debug## (" + data[0].length.to_s + "//" + length.to_s + ")" + data.inspect
				puts "#########  " + header.inspect
				puts "########### " + header[16].inspect + " :: " + header[17].inspect
				body.concat(data[0])
				read_byte = read_byte + data[0].length
			end
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

