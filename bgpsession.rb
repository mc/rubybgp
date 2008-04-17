require 'socket'
require 'ipaddr'

require 'bgpconst.rb'
require 'bgppacket.rb'

class SessionError < StandardError
end

class BGP::Session
	# No particular useful example, this will bounce all packets
	# back to the peer:
	#
	# myself = BGP::Peer.new(asn_local)
	# remote = BGP::Peer.new(asn_remote)
	# session = BGP::Session.new(asn_local, asn_remote)
	# session.run do  |sess, packet|
	#   sess.send(packet)
	# end
	def initialize(local, remote)
		@local = local
		@remote = remote

		@socket = TCPSocket.new(@remote.ip, 179)
		@fsm = BGP::FSM::IDLE

		establish

		p = BGP::Packet::KeepAlive.new()
		begin
			send(p)
		rescue
			raise SessionError
		end
	end

	def run
		while (1==1)
			begin
				i = input
			rescue
				return
			end

			
			yield self, i
		end
	end

	def establish
		p = BGP::Packet::Open.new(@local.asn, IPAddr.new(@local.router_id), 30, 4)
		begin
			send(p)
		rescue
			raise SessionError
		end
		@fsm = BGP::FSM::OPENSENT

		input
	end

	def send(packet)
		return @socket.send( packet.to_s, packet.len )
	end

	def socket_receive(length)
		data = @socket.recvfrom(length)
		return data
	end

	def input
		data = Array.new
		data[0] = ""
		while (data[0] == "") ## XXX is_empty?
			begin
				data = @socket.recvfrom(19)
			rescue
				raise SessionError
			end
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
				begin
					data = socket_receive(length - read_byte)
				rescue
					raise SessionError
				end
				body.concat(data[0])
				read_byte = read_byte + data[0].length
			end
		else
			body = nil
		end


		case flagsint
			when BGP::MSG_TYPE::OPEN
				return (BGP::Packet::Open.from_s(body, length))
			when BGP::MSG_TYPE::UPDATE
				return (BGP::Packet::Update.from_s(body, length))
			when BGP::MSG_TYPE::NOTIFICATION
				return nil
			when BGP::MSG_TYPE::KEEPALIVE
				packet = BGP::Packet::KeepAlive.new()
				begin
					send(packet)
				rescue
					raise SessionError
				end
				if ( @fsm == BGP::FSM::OPENSENT ||
				     @fsm == BGP::FSM::OPENCONFIRM )
					@fsm = BGP::FSM::ESTABLISHED
				end
				return nil
		end
		return nil
	end
end

