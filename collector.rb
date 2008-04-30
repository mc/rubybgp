$:.push('./lib')
$:.push('./lib/bgp')

require 'rubygems'
require 'IRC'
require 'dbi'

require 'bgppeer.rb'
require 'bgpsession.rb'
require 'collector-bg.rb'

Thread.abort_on_exception = true

myself = BGP::Peer.new("65535")
myself.router_id = "10.20.30.40"

rpeer = BGP::Peer.new("21083")
rpeer.ip = "194.8.57.1"

@sql_rir = DBI.connect("DBI:Mysql:rir:localhost", "root")
@sql_ld = DBI.connect("DBI:Mysql:bgp:localhost", "root")

@sql_q = 0

@irc = IRC.new("BGP4-2", "irc.uni-erlangen.de", 6667)
IRCEvent.add_callback('endofmotd') { |event| 
	@irc.add_channel('#denog.bots')
	@irc.send_message('#denog.bots', "Hello world!")
}

IRCEvent.add_callback('privmsg') { |event|
	irc_message_handler(event, @irc)
}

t_irc = Thread.new {
	while (1 == 1)
		@irc.connect
		sleep(30)
	end
}

t_bgp = Thread.new {
	while (1==1)
		session = BGP::Session.new(myself, rpeer)

		@counter   = 0
		@withdrawn = 0
		@announced = 0
		session.run do |s, p|
			bgp_event_handler(s,p, @irc)
		end

		session = nil
		sleep(10)
	end
}

while (1==1)
	sleep(10)
end
