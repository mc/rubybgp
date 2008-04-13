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
			puts "recv update"

			wlen    = str.slice!(0..1).unpack("n")
			if (wlen[0] > 0)
				wstr   = str.slice!(0..(wlen[0]) - 1)
				wroutes = decode_withdrawn(wstr, wlen[0])
			end

			palen  = str.slice!(0..1).unpack("n")
			if (palen[0] > 0)
				pastr = str.slice!(0..(palen[0] - 1))
				path_attr = decode_pathattr(pastr, palen[0])
			end

			alen   = (len + 19) - 23 - palen[0] - wlen[0]
			puts "recv update (NLI:#{alen} = (T:#{len} + 19) - P:#{palen[0]} - W:#{wlen[0]})"

			if (alen > 0)
				astr  = str.slice!(0..alen - 1)
				nli   = decode_nli(astr, alen)
			end

		end

		def to_s
		end

private
		def self.decode_withdrawn(body, len)
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
			prefix = IPAddr.ntop(network)
			puts "W: #{prefix}/#{plen}"
		end

		def self.decode_nli(body, len)
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
				len = len - nli_len - 1

				puts "A: #{prefix}/#{nli_len}"
			end
		end

		def self.decode_pathattr(body, len)
			while (len > 0)
				puts "decoding PA"
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
					puts "  Partialflag"
				end
				if ( (attrflag & 64) == 64 )
					puts "  Transitiveflag"
				end
				if ( (attrflag & 128) == 128 )
					puts "  Optionalflag"
				end
				
				case attrtype
				when BGP::PATH_ATTR::ORIGIN
					puts "   ORIGIN"
					if attrbody[0] == 0
						puts "     IGP"
					elsif attrbody[0] == 1
						puts "     EGP"
					elsif attrbody[0] == 2
						puts "     INC"
					else
						puts "     Unknown"
					end
				when BGP::PATH_ATTR::AS_PATH
					puts "   AS_PATH"
					(ptype, plen) = attrbody.slice!(0..1).unpack("CC")
					if (ptype == 1)
						puts "    UNORDERED"
					elsif (ptype == 2)
						puts "    SEQUENCE"
					end
					path = Array.new
					while (plen > 0)
						path.push(attrbody.slice!(0..1).unpack("n"))[0]
						plen = plen - 1
					end
					puts "     " + path.join(" ").to_s
				when BGP::PATH_ATTR::NEXT_HOP
					puts "   NEXT_HOP"
					ip = attrbody.slice!(0..3).unpack("a4")[0]
					nh = IPAddr.ntop(ip)
					puts "     #{nh}"
				when BGP::PATH_ATTR::MULTI_EXIT_DISC
					puts "   MED:"
					med = attrbody.slice!(0..3).unpack("N")[0]
					puts "     #{med}"
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
				when BGP::PATH_ATTR::MP_REACH_NLRI
					puts "   MP_REACH_NLRI"
					(afi, safi, nh_len) = attrbody.slice!(0..3).unpack("nCC")
					nh = attrbody.slice!(0..(nh_len - 1))
					attrbody.slice!(0..0) # reserved, ignored.
					
					nlri_len = attrlen - nh_len - 4 - 1
					while (nlri_len > 0)
						plen = attrbody.slice!(0)
						slen = plen / 8
						if ((plen % 8) > 0)
							slen = slen + 1
						end

						prefix = attrbody.slice!(0..(slen-1))
						puts "     #{afi}/#{safi} #{nh.inspect} #{prefix.inspect}/#{plen}"

						nlri_len = nlri_len - slen - 1
					end
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

