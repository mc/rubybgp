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

				if (optlen != nil && optlen > 0)
					optparm = str.slice!(0..(optlen-1))
				else
					optlen = 0
					puts "warnung: optlen = " + optlen.inspect
				end

				if (opttype == BGP::OPT::CAPABILITY)
					caps.push(BGP::CAP::Plain.from_s(optparm, optlen))
				end

				len = len - optlen - 2
			end
			obj.caps = caps

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
		attr_accessor :mp_afi, :mp_safi, :mp_nexthop, :community
		attr_accessor :med, :origin, :aspath, :aspath_type, :nexthop
		attr_accessor :asn32_path, :asn32path_type, :agg32_asn, :agg32_id
		attr_accessor :agg_asn, :agg_id, :atomic_aggregate

		def initialize
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

		def add_community(comm)
			if (@community == nil)
				@community = Array.new
			end
			@community.push(comm)
		end

		def set_atomic_aggregate
			@atomic_aggregate = true
		end

		def set_aggregator(asn, id)
			@agg_asn = asn
			@agg_id  = id
		end

		def set_asn32_aggregator(asnl, asnh, id)
			@agg32_asn = "#{asnl}.#{asnh}"
			@agg32_id  = id
		end


private
		def self.decode_withdrawn(packet, body, len)
			while (len > 0)
				plen = body.slice!(0)
				if (plen <= 8)
					network = body.slice!(0..0).unpack("a")[0]
					network.concat("\0\0\0")
					slen = 1
				elsif (plen <= 16)
					network = body.slice!(0..1).unpack("a2")[0]
					network.concat("\0\0")
					slen = 2
				elsif (plen <= 24)
					network = body.slice!(0..2).unpack("a3")[0]
					network.concat("\0")
					slen = 3
				else
					network = body.slice!(0..3).unpack("a4")[0]
					slen = 4
				end
				if (network.length == 4)
					packet.withdraw_route(IPAddr.ntop(network), plen)
				else
					puts "warnung: falsche netzwerklaenge in " + network.inspect
				end
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
				if (network.length == 4)
					packet.announce_route(IPAddr.ntop(network), nli_len)
				else
					puts "warnung: falsche netzwerklaenge in " + network.inspect
				end
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

				if (attrlen == nil)
					puts "warnung, attrlen == nil"
					attrlen = 0
					len = 0
				end

				len = len - attrlen

				if (attrlen > 0)
					attrbody = body.slice!(0..(attrlen - 1))
				else
					attrbody = nil
				end
				# puts attrbody.inspect

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
						packet.origin = attrbody[0]

					when BGP::PATH_ATTR::AS_PATH
						(ptype, plen) = attrbody.slice!(0..1).unpack("CC")
						packet.aspath_type = ptype
						aspath = Array.new
						while (plen && plen > 0)
							aspath.push((attrbody.slice!(0..1).unpack("n"))[0])
							plen = plen - 1
						end
						packet.aspath = aspath

					when BGP::PATH_ATTR::NEXT_HOP
						ip = attrbody.slice!(0..3).unpack("a4")[0]
						
						if (ip.length == 4)
							packet.nexthop = IPAddr.ntop(ip)
						else
							puts "warnung: falsche nexthoplaenge  in " + ip.inspect
						end

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

							if (mp_afi == BGP::AFI::IPV6)
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

							if (afi == BGP::AFI::IPV6)
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

					when BGP::PATH_ATTR::COMMUNITY
						while (attrlen > 0)
							(comml, commr) = attrbody.slice!(0..3).unpack("nn")
							packet.add_community( [comml, commr] )
							attrlen = attrlen - 4
						end

					when BGP::PATH_ATTR::ATOMIC_AGGREGATE
						packet.set_atomic_aggregate

					when BGP::PATH_ATTR::AGGREGATOR
						(asn, routerid) = attrbody.slice(0..5).unpack("na4")
						packet.set_aggregator(asn, IPAddr.ntop(routerid))

					when BGP::PATH_ATTR::AS4_PATH
						(ptype, plen) = attrbody.slice!(0..1).unpack("CC")
						packet.asn32path_type = ptype
						aspath = Array.new
						while (plen && plen > 0)
							(asnl, asnh) = attrbody.slice!(0..3).unpack("nn")
							aspath.push("#{asnl}.#{asnh}")
							plen = plen - 1
						end
						packet.asn32_path = aspath

					when BGP::PATH_ATTR::AS4_AGGREGATOR
						if (attrlen == 8)
							(asnl, asnh,  routerid) = attrbody.slice!(0..7).unpack("nna4")
							packet.set_asn32_aggregator(asnl, asnh, IPAddr.ntop(routerid))
						else
							puts "warning, attrlen = #{attrlen} instead of 8"
						end
						
					when BGP::PATH_ATTR::LOCAL_PREF
						puts "   LOCAL_PREF"
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
					when BGP::PATH_ATTR::SSA
						puts "   SSA"
					when BGP::PATH_ATTR::CONNECTOR_ATTR
						puts "   CONN_ATTR"
				end # case
			end
		end
	end
end

