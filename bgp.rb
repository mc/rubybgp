require 'bgppeer.rb'
require 'bgpsession.rb'

myself = BgpPeer.new("999")
myself.router_id = "10.20.30.40"

rpeer = BgpPeer.new("7675")
rpeer.ip = "127.0.0.1"

BgpSession.new(myself, rpeer)

