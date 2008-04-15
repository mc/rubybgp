require 'bgppeer.rb'
require 'bgpsession.rb'


myself = BGP::Peer.new("65535")
myself.router_id = "10.20.30.40"

rpeer = BGP::Peer.new("65534")
rpeer.ip = "10.20.30.50"

session = BGP::Session.new(myself, rpeer)

puts "running"
session.run do |s, p|
	puts "--"
	puts s.inspect
	puts p.inspect
end

