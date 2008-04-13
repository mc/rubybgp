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

	class Update
		def initialize
		end

		def self.from_s(str, len)
			packet = BGP::Packet::Update.duplicate

			wlen    = str.slice!(0..1).unpack("n")
			if (wlen[0] > 0)
				wstr   = str.slice!(0..(wlen[0]) - 1)
				@wroutes = decode_withdrawn(wstr, wlen[0])
			else
				@wroutes = nil
			end

			palen  = str.slice!(0..1).unpack("n")
			if (palen[0] > 0)
				pastr = str.slice!(0..(palen[0] - 1))
				decode_pathattr(pastr, palen[0])
			end

			alen   = (len + 19) - 23 - palen[0] - wlen[0]

			if (alen > 0)
				astr  = str.slice!(0..alen - 1)
				decode_nli(astr, alen)
			end
			packet
		end

		def to_s
		end

private
		def self.decode_withdrawn(body, len)
			@pfx_w = Array.new
			plen = body.slice!(0)
			if (plen <= 8)
				network = body.slice!(0..0).unpack("a")
				network << ("\0\0\0");
			elsif (plen <= 16)
				network = body.slice!(0..1).unpack("aa")
				network.concat("\0\0");
			elsif (plen <= 24)
				network = body.slice!(0..2).unpack("aaa")
				network.concat("\0");
			else
				network = body.slice!(0..3).unpack("aaaa")
			end
			@pfx_w.push( [prefix = IPAddr.ntop(network), plen] )
		end

		def self.decode_nli(body, len)
			@pfx = Array.new
			while (len > 0)
				nli_len = body.slice!(0)

				if (nli_len <= 8)
					network = body.slice!(0..0).unpack("a")[0]
					network.concat("\0\0\0")
				elsif (nli_len <= 16)
					network = body.slice!(0..1).unpack("a2")[0]
					network.concat("\0\0")
				elsif (nli_len <= 24)
					network = body.slice!(0..2).unpack("a3")[0]
					network.concat("\0")
				else
					network = body.slice!(0..3).unpack("a4")[0]
				end
				prefix = IPAddr.ntop(network)
				@pfx.push( [prefix, nli_len] )

				len = len - nli_len - 1

			end
		end

		def self.decode_pathattr(body, len)
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

				# puts " PAlen: #{attrlen} (#{attrbody.inspect})"

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
						@origin = attrbody[0]     # IGP EGP INCOMPLETE

					when BGP::PATH_ATTR::AS_PATH
						puts "   AS_PATH"
						(ptype, plen) = attrbody.slice!(0..1).unpack("CC")
						@aspath_type = ptype      # UNORDERED / SEQUENCE
						@aspath = Array.new       # PATH
						while (plen > 0)
							@aspath.push(attrbody.slice!(0..1).unpack("n"))[0]
							plen = plen - 1
						end

					when BGP::PATH_ATTR::NEXT_HOP
						ip = attrbody.slice!(0..3).unpack("a4")[0]
						@nexthop = IPAddr.ntop(ip)

					when BGP::PATH_ATTR::MULTI_EXIT_DISC
						@med = attrbody.slice!(0..3).unpack("N")[0]

					when BGP::PATH_ATTR::MP_REACH_NLRI
						@mp_pfx = Array.new
						(@mp_afi, @mp_safi, nh_len) = attrbody.slice!(0..3).unpack("nCC")
						@mp_nexthop = IPAddr.ntop( attrbody.slice!(0..(nh_len - 1)) )
						attrbody.slice!(0..0) # reserved, ignore
					
						nlri_len = attrlen - nh_len - 4 - 1
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

							@mp_pfx.push([IPAddr.ntop(prefix), plen])

							nlri_len = nlri_len - slen - 1
						end

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

