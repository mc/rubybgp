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
		attr_accessor :asn, :id, :hold, :ver, :caps
		def initialize(asn, id, holdtimer=30, version=4)
			@asn = asn
			@id = id
			@hold = holdtimer
			@ver = version
			@caps = nil
		end

		def self.from_s(str, len)
			res = str.unpack("Cnna4C")
			obj = BGP::Packet::Open.new(res[1], IPAddr.ntop(res[3]), res[2], res[0])
			caps = Array.new
			str.slice!(0..9)
			len = len - 10

			while (len > 0)
				opttype = str[0]
				optlen = str[1]
				str.slice!(0..1)
				optparm = str.slice!(0..(optlen-1))

				if (opttype == 2)  # OPTION: CAPABILITY as defined in RFC3392
					caps.push(BGP::CAP::Plain.from_s(optparm, optlen).inspect )
				end

				obj.caps = caps
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

	class Update
		attr_accessor :wroutes, :mp_pfx_w, :mp_pfx, :pfx
		attr_accessor :mp_afi, :mp_safi, :mp_nexthop
		attr_accessor :med, :origin, :aspath, :aspath_type, :nexthop

		def initialize
			@wroutes  = nil
			@mp_pfx_w = nil
			@mp_pfx   = nil
			@pfx      = nil
		end

		def self.from_s(str, len)
			packet = BGP::Packet::Update.new

			wlen    = str.slice!(0..1).unpack("n")
			if (wlen[0] > 0)
				wstr   = str.slice!(0..(wlen[0]) - 1)
				decode_withdrawn(packet, wstr, wlen[0])
			end

			palen  = str.slice!(0..1).unpack("n")
			if (palen[0] > 0)
				pastr = str.slice!(0..(palen[0] - 1))
				pa = decode_pathattr(packet, pastr, palen[0])
			end

			alen   = (len + 19) - 23 - palen[0] - wlen[0]

			if (alen > 0)
				astr  = str.slice!(0..alen - 1)
				nli = decode_nli(packet, astr, alen)
			end
			return packet
		end

		def to_s
		end

		def withdraw_route(pfx, len)
			if (@wroutes == nil)
				@wroutes = Array.new
			end
			@wroutes.push( [pfx, len] )
		end

		def announce_route(pfx, len)
			if (@pfx == nil)
				@pfx = Array.new
			end
			@pfx.push( [pfx, len] )
		end


private
		def self.decode_withdrawn(packet, body, len)
			while (len > 0)
				plen = body.slice!(0)
				if (plen <= 8)
					network = body.slice!(0..0).unpack("a")
					network << ("\0\0\0");
					slen = 1
				elsif (plen <= 16)
					network = body.slice!(0..1).unpack("aa")
					network.concat("\0\0");
					slen = 2
				elsif (plen <= 24)
					network = body.slice!(0..2).unpack("aaa")
					network.concat("\0");
					slen = 3
				else
					network = body.slice!(0..3).unpack("aaaa")
					slen = 4
				end
				packet.withdraw_route(IPAddr.ntop(network), plen)
				len = len - slen - 1
			end
		end

		def self.decode_nli(packet, body, len)
			while (len > 0)
				nli_len = body.slice!(0)

				if (nli_len <= 8)
					network = body.slice!(0..0).unpack("a")[0]
					network.concat("\0\0\0")
					slen = 1
				elsif (nli_len <= 16)
					network = body.slice!(0..1).unpack("a2")[0]
					network.concat("\0\0")
					slen = 2
				elsif (nli_len <= 24)
					network = body.slice!(0..2).unpack("a3")[0]
					network.concat("\0")
					slen = 3
				else
					network = body.slice!(0..3).unpack("a4")[0]
					slen = 4
				end
				packet.announce_route(IPAddr.ntop(network), nli_len)
				len = len - slen - 1
			end
		end

		def self.decode_pathattr(packet, body, len)
			while (len > 0)
				(attrflag, attrtype) = body.slice!(0..1).unpack("CC")
				if ( (attrflag & 16) == 16 ) # Extended Length
					attrlen = body.slice!(0..1).unpack("n")[0]
					len = len - 3
				else
					attrlen = body.slice!(0..0).unpack("C")[0]
					len = len - 4 
				end
					len = len - attrlen
				if (attrlen > 0)
					attrbody = body.slice!(0..(attrlen - 1))
				end

				if ( (attrflag & 32) == 32 )
					# puts "  Partialflag"
				end
				if ( (attrflag & 64) == 64 )
					# puts "  Transitiveflag"
				end
				if ( (attrflag & 128) == 128 )
					# puts "  Optionalflag"
				end
				
				case attrtype
					when BGP::PATH_ATTR::ORIGIN
						packet.origin = attrbody[0]     # IGP EGP INCOMPLETE

					when BGP::PATH_ATTR::AS_PATH
						(ptype, plen) = attrbody.slice!(0..1).unpack("CC")
						packet.aspath_type = ptype      # UNORDERED / SEQUENCE
						aspath = Array.new
						while (plen > 0)
							aspath.push((attrbody.slice!(0..1).unpack("n"))[0])
							plen = plen - 1
						end
						packet.aspath = aspath

					when BGP::PATH_ATTR::NEXT_HOP
						ip = attrbody.slice!(0..3).unpack("a4")[0]
						packet.nexthop = IPAddr.ntop(ip)

					when BGP::PATH_ATTR::MULTI_EXIT_DISC
						packet.med = attrbody.slice!(0..3).unpack("N")[0]

					when BGP::PATH_ATTR::MP_REACH_NLRI
						mp_pfx = Array.new
						(mp_afi, mp_safi, nh_len) = attrbody.slice!(0..3).unpack("nCC")
						mp_nexthop = IPAddr.ntop( attrbody.slice!(0..(nh_len - 1)) )
						attrbody.slice!(0..0) # reserved, ignore
					
						nlri_len = attrlen - nh_len - 4 - 1
						while (nlri_len > 0)
							plen = attrbody.slice!(0)

							slen = plen / 8
							if ((plen % 8) > 0)
								slen = slen + 1
							end
							prefix = attrbody.slice!(0..(slen-1))

							if (mp_afi == 2) # IPv6
								blen = 16 - slen
								while (blen > 0)
									prefix.concat("\0")
									blen = blen - 1
								end
							end

							mp_pfx.push([IPAddr.ntop(prefix), plen])

							nlri_len = nlri_len - slen - 1
						end

						packet.mp_afi     = mp_afi
						packet.mp_safi    = mp_safi
						packet.mp_nexthop = mp_nexthop
						packet.mp_pfx     = mp_pfx

					when BGP::PATH_ATTR::MP_UNREACH_NLRI
						mp_pfx_w = Array.new
						(mp_afi, mp_safi) = attrbody.slice!(0..2).unpack("nC")
					
						nlri_len = attrlen - 3
						while (nlri_len > 0)
							plen = attrbody.slice!(0)

							slen = plen / 8
							if ((plen % 8) > 0)
								slen = slen + 1
							end
							prefix = attrbody.slice!(0..(slen-1))

							if (afi == 2) # IPv6
								blen = 16 - slen
								while (blen > 0)
									prefix.concat("\0")
									blen = blen - 1
								end
							end

							@mp_pfx_w.push([IPAddr.ntop(prefix), plen])

							nlri_len = nlri_len - slen - 1
						end

						packet.mp_afi     = mp_afi
						packet.mp_safi    = mp_safi
						packet.mp_pfx_w   = mp_pfx_w

					when BGP::PATH_ATTR::LOCAL_PREF
						puts "   LOCAL_PREF"
					when BGP::PATH_ATTR::ATOMIC_AGGREGATE
						puts "   ATOMIC_AGG"
					when BGP::PATH_ATTR::AGGREGATOR
						puts "   AGG"
					when BGP::PATH_ATTR::COMMUNITY
						puts "   COMM"
					when BGP::PATH_ATTR::ORIGINATOR_ID
						puts "   ORIGINATOR_ID"
					when BGP::PATH_ATTR::CLUSTER_LIST
						puts "   CLUSTER"
					when BGP::PATH_ATTR::DPA
						puts "   DPA"
					when BGP::PATH_ATTR::ADVERTISER
						puts "   ADV"
					when BGP::PATH_ATTR::RCID_PATH
						puts "   RCID"
					when BGP::PATH_ATTR::EXT_COMMUNITIES
						puts "   EXT_COMM"
					when BGP::PATH_ATTR::AS4_PATH
						puts "   ASN32_P"
					when BGP::PATH_ATTR::AS4_AGGREGATOR
						puts "   ASN32_A"
					when BGP::PATH_ATTR::SSA
						puts "   SSA"
					when BGP::PATH_ATTR::CONNECTOR_ATTR
						puts "   CONN_ATTR"
				end

			end
		end
	end
end

