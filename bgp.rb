require 'bgppeer.rb'
require 'bgpsession.rb'

myself = BGP::Peer.new("999")
myself.router_id = "10.20.30.40"

rpeer = BGP::Peer.new("7675")
rpeer.ip = "127.0.0.1"

BGP::Session.new(myself, rpeer)

