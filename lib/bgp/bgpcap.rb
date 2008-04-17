require 'bgpconst'

module BGP
	module CAP
		class Plain
			def initialize
			end

			def to_s
			end

			def self.from_s(str, len)
				@caps = Array.new

				res = str.unpack("CC")
				captype = res[0]
				caplen = res[1]
				str.slice!(0..1)

				case captype
					when BGP::CAP::MULTIPROTOCOL
						c = BGP::CAP::MultiProtocol.new(str, caplen)
					when BGP::CAP::ROUTEREFRESH
						c = BGP::CAP::RouteRefresh.new(str, caplen)
					when BGP::CAP::COOPROUTEFILT
						c = BGP::CAP::CoopRouteFilt.new(str, caplen)
					when BGP::CAP::MULTROUTEDEST
						c = BGP::CAP::MultRouteDest.new(str, caplen)
					when BGP::CAP::GRACEFULRESTART
						c = BGP::CAP::GracefulRestart.new(str, caplen)
					when BGP::CAP::ASN32
						c = BGP::CAP::Asn32.new(str, caplen)
					when BGP::CAP::DYNAMICCAP
						c = BGP::CAP::DynamicCap.new(str, caplen)
					when BGP::CAP::MULTISESSION
						c = BGP::CAP::MultiSession.new(str, caplen)
					when BGP::CAP::C_ROUTEREFRESH
						c = BGP::CAP::C_RouteRefresh.new(str, caplen)
				end
				@caps.push(c)
			end
		end

		class MultiProtocol
			def initialize(capparm, caplen)
				res = capparm.unpack("nCC")
				@afi = res[0]
				 # res[1] is reserved and should be ignored.
				@safi = res[2]
			end
		end

		class RouteRefresh
			def initialize(capparm, caplen)
				@type = BGP::CAP::ROUTEREFRESH
			end
		end

		class C_RouteRefresh
			def initialize(capparm, caplen)
				@type = BGP::CAP::C_ROUTEREFRESH
			end
		end

		class CoopRouteFilt
		end

		class MultRouteDest
		end

		class GracefulRestart
		end
		
		class Asn32
		end

		class DynamicCap
		end

		class MultiSession
		end
	end
end
