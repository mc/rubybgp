# http://www.iana.org/assignments/bgp-parameters

module BGP::MSG_TYPE
	OPEN         = 1  # RFC 4271
	UPDATE       = 2  # RFC 4271
	NOTIFICATION = 3  # RFC 4271
	KEEPALIVE    = 4  # RFC 4271
	REFRESH      = 5  # RFC2918
end

module BGP::PATH_ATTR
	ORIGIN           = 1	# RFC4271]
	AS_PATH          = 2	# [RFC4271]
	NEXT_HOP         = 3	# [RFC4271]
	MULTI_EXIT_DISC  = 4	# [RFC4271]
	LOCAL_PREF       = 5	# [RFC4271]
	ATOMIC_AGGREGATE = 6	# [RFC4271]
	AGGREGATOR       = 7	# [RFC4271]
	COMMUNITY        = 8	# [RFC1997]
	ORIGINATOR_ID    = 9	# [RFC4456]
	CLUSTER_LIST     = 10	# [RFC4456]
	DPA              = 11	# [Chen]
	ADVERTISER       = 12	# [RFC1863]
	RCID_PATH        = 13	# [RFC1863]
	MP_REACH_NLRI    = 14	# [RFC4760]	
	MP_UNREACH_NLRI  = 15	# [RFC4760]	
	EXT_COMMUNITIES  = 16	# [Rosen][RFC4360]
	AS4_PATH         = 17	# [RFC4893]	
	AS4_AGGREGATOR   = 18	# [RFC4893] 
	SSA              = 19	# [Nalawade]
	CONNECTOR_ATTR   = 20	# [Nalawade]
end



module BGP::FSM
	IDLE        = 1
	OPENSENT    = 2
	OPENCONFIRM = 3
	ESTABLISHED = 4
end

module BGP
module CAP
	MULTIPROTOCOL   = 1  # RFC 4760 / 2858
	ROUTEREFRESH    = 2  # RFC 2918
	COOPROUTEFILT   = 3  # [Rekhter]
	MULTROUTEDEST   = 4  # RFC 3107
	GRACEFULRESTART = 64 # RFC 4724
	ASN32           = 65 # RFC 4893
	DYNAMICCAP      = 67 # [Chen]
	MULTISESSION    = 68 # [Appanna]
	C_ROUTEREFRESH  = 128 # Cisco Route Refresh
end
end

