module BGP
	class Peer
		attr_accessor :asn, :router_id, :ip

		def initialize(asn)
			@asn = asn
		end
	end
end

