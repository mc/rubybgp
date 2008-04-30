def irc_send(text)
	### safety net for burst
	if (@counter < 45000)
		puts text
	else
		@irc.send_message("#denog.bots", text)
	end
end

def bgp_event_handler(s, p, irc)
	begin
		### counter
		@counter += 1
		if (p.respond_to?("pfx") && p.pfx)
			@announced += p.pfx.size
		end
		if (p.respond_to?("wroutes") && p.wroutes)
			@withdrawn += p.wroutes.size
		end
		
		### ASN_32 detection
		if (p.respond_to?("asn32_path") && p.asn32_path != nil)
			@irc.send_message("#denog.bots","ASN32_P: #{p.asn32_path.join('_')}; " +
			         "ASN_P: #{p.aspath.join('_')} [" + p.pfx.join(', ') + "]")
		elsif (p.respond_to?("aspath") && p.aspath && p.aspath.include?(23456) )
			@irc.send_message("#denog.bots","AS_TRANS w/o ASN32_P: #{p.aspath.join('_')} [" + p.pfx.join(', ') + "]")
		end

		if (p.respond_to?("agg32_asn") && p.agg32_asn)
			puts "."
			puts "ASN32_AGG: #{p.agg32_asn}@#{p.agg32_id}; " +
			         "ASN_P: #{p.aspath.join('_')} [" + p.pfx.join(', ') + "]"
		end

		### print stat every 1000 packets
		if ((@counter % 1000) == 0)
			irc_send("#{@counter} packets;  W:#{@withdrawn}  A:#{@announced}  (Q:#{@sql_q})")
			@withdrawn = 0
			@announced = 0
			@sql_q     = 0
		end
		
		### long AS Paths
		if (p.respond_to?("aspath") && p.aspath && p.aspath.size > 20)
			irc_send("Overlong AS Path[#{p.aspath.size}]: #{p.aspath.join('_')}")
		end

		### private ASN detection
		if (p.respond_to?("aspath") && p.aspath)
			pasn = false
			p.aspath.each { |asn|
				if ( (asn >= 64512) && (asn <=65535) )
					pasn = true
				end
			}
			if (pasn == true)
				irc_send("Private ASN in Path #{p.aspath.join('_')}")
			end
		end

		### new asn?
		if (p.respond_to?("aspath") && p.aspath)
			p.aspath.each { |asn|
				if (db_seen_asn?(asn))
					db_upd_seen_asn(asn)
				else
					db_ins_seen_asn(asn)
					irc_send("NEW_ASN: #{asn} (#{db_asn_ntos(asn)})")
				end
			}
		end
		
		### new pfx?
		if (p.respond_to?("pfx") && p.pfx)
			p.pfx.each { |pfx|
				prefix = pfx[0]
				plen   = pfx[1]
				if (db_seen_pfx?(prefix, plen))
					db_upd_seen_pfx(prefix, plen)
				else
					db_ins_seen_pfx(prefix, plen)
					d = db_pfx_ntos(prefix, plen)
					if (d == nil)
						str = ""
					else
						str = "(#{d['country']}:" + "#{d['status']}:" + "#{d['netname']}) "
					end
					irc_send("NEW_PFX: #{prefix}/#{plen} "+str+"[#{p.aspath.join(' ')}]")
				end
			}
		end

		# special pfx
		if (p.respond_to?("pfx") && p.pfx)
			p.pfx.each { |pfx|
				desc = db_pfx_special?(pfx[0], pfx[1])
				if desc != false
					d = db_pfx_ntos(pfx[0], pfx[1])
					if (d == nil)
						str = ""
					else
						str = "(#{d['country']}:" + "#{d['status']}:" + "#{d['netname']}) "
					end
					irc_send("#{desc} #{pfx[0]}/#{pfx[1]} #{str} [#{p.aspath.join("_")}]")
				end
			}
		end

		### special withdrawn
		if (p.respond_to?("wroutes") && p.wroutes)
			p.wroutes.each { |pfx|
				desc = db_pfx_special?(pfx[0], pfx[1])
				if desc != false
					d = db_pfx_ntos(pfx[0], pfx[1])
					if (d == nil)
						str = ""
					else
						str = "(#{d['country']}:" + "#{d['status']}:" + "#{d['netname']}) "
					end
					irc_send("#{desc} #{pfx[0]}/#{pfx[1]} #{str}")
				end
			}
		end

		### bogus
		if (p.respond_to?("pfx") && p.pfx)
			p.pfx.each { |pfx|
				status = pfx_check_bogus(pfx[0], pfx[1])
				if (status != nil)
					irc_send("#{status}: #{pfx[0]}/#{pfx[1]} [#{p.aspath.join("_")}]")
				end
			}
		end

	rescue
		if (@counter < 45000) # safety net for burst phase.
			puts $!
		else
			puts "== i broke. #{$!}"
		end
	end
end


def irc_message_handler(event, irc)
	begin
		if ((event.event_type =~ /PRIVMSG/i) && 
		   (event.hostmask == "^many@127.0.0.1"))
			case event.message
				when /^\+reload$/
					load 'bgppeer.rb'
					load 'bgpsession.rb'
					load 'collector-bg.rb'
					irc_send("reload triggered")
				when /^\+run /
					event.message.gsub!("+run ", "")
					begin
						eval event.message
					rescue
						@irc.send_message("#denog.bots", "++ huh?  (#{$!})")
					end
			end
		end
	

	rescue
		if (@counter < 45000) # safety net for burst phase.
			puts $!
		else
			puts("#denog.bots", "-- i broke. #{$!}")
		end
	end
end

def db_asn_ntos(num)
	if (! @asns)
		@asns = Hash.new
	end
	
	if (@asns[num] == "")
		asn = @sql_rir.quote(num.to_s)
		row = @sql_rir.select_one("SELECT name FROM asn WHERE ASN=#{asn}")
		@sql_q += 1
		if row != nil
			@asns[num] = row[0]
		else
			return nil
		end
	end

	return @asns[num]
end

def db_asn_ston(sym)
end

def db_seen_asn?(num)
	if (! @asns)
		@asns = Hash.new
	end

	if (@asns[num] == ".")
		return true
	end

	asn = @sql_ld.quote(num.to_s)
	row = @sql_ld.select_one("SELECT * FROM seen_as WHERE asn=#{asn}")
	@sql_q += 1
	if row != nil
		@asns[num] = "."
		return true
	else
		return false
	end
end

def db_ins_seen_asn(num)
	asn = @sql_ld.quote(num.to_s)
	if (@asns[num] == "." && @counter < 45000)
		return true
	end
	@sql_ld.do("INSERT INTO seen_as (asn, firstseen, lastseen) VALUES " +
		"(#{asn}, NOW(), NOW())")
	@sql_q += 1
	@asns[num] = "."
end

def db_upd_seen_asn(num)
	asn = @sql_ld.quote(num.to_s)
	if (@asns[num] == "." && @counter < 45000)
		return true
	end
	@sql_ld.do("UPDATE seen_as SET lastseen=NOW() WHERE asn=#{asn}")
	@sql_q += 1
	@asns[num] = "."
end


def db_pfx_ntos(pfx, plen)
	prefix = @sql_rir.quote(pfx.to_s)
	length = @sql_rir.quote(plen.to_s)
	row = @sql_rir.select_one("SELECT netname, country, status FROM prefix "+
		"WHERE network=#{prefix} and plen=#{length}");
	@sql_q += 1
	if row != nil
		return row
	else
		return nil
	end
end

def db_seen_pfx?(pfx, plen)
	prefix = @sql_ld.quote(pfx.to_s + "/" + plen.to_s)
	row = @sql_ld.select_one("SELECT * FROM seen_pfx "+
		"WHERE pfx=#{prefix}")
	@sql_q += 1
	if row != nil
		return true
	else
		return false
	end
end

def db_ins_seen_pfx(pfx, plen)
	prefix = @sql_ld.quote(pfx.to_s + "/" + plen.to_s)
	@sql_ld.do("INSERT INTO seen_pfx (pfx, firstseen, lastseen) VALUES " +
		"(#{prefix}, NOW(), NOW())")
	@sql_q += 1
end

def db_upd_seen_pfx(pfx, plen)
	prefix = @sql_ld.quote(pfx.to_s + "/" + plen.to_s)
	@sql_ld.do("UPDATE seen_pfx SET lastseen=NOW() WHERE pfx=#{prefix}")
	@sql_q += 1
end


def db_pfx_special?(pfx, plen)
	prefix = @sql_ld.quote(pfx.to_s + "/" + plen.to_s)
	row = @sql_ld.select_one("SELECT `desc` FROM special_pfx "+
		"WHERE `pfx`=#{prefix}")
	@sql_q += 1
	if row != nil
		return row[0]
	else
		return false
	end
end

def db_pfx_add_special(pfx, desc)
	prefix = @sql_ld.quote(pfx)
	description = @sql_ld.quote(desc)
	@sql_ld.do("INSERT INTO special_pfx (`pfx`, `desc`) VALUES " +
		"(#{prefix}, #{description})")
	@sql_q += 1
end

def pfx_check_bogus(prefix, plen)
	case prefix
		when /^10\./
			return "RFC1918"
		when /^192\.168\./
			return "RFC1918"
		when /^172\.16\./
			return "RFC1918"
		when /^172\.17\./
			return "RFC1918"
		when /^172\.18\./
			return "RFC1918"
		when /^172\.19\./
			return "RFC1918"
		when /^172\.20\./
			return "RFC1918"
		when /^172\.21\./
			return "RFC1918"
		when /^172\.22\./
			return "RFC1918"
		when /^172\.23\./
			return "RFC1918"
		when /^172\.24\./
			return "RFC1918"
		when /^172\.25\./
			return "RFC1918"
		when /^172\.26\./
			return "RFC1918"
		when /^172\.27\./
			return "RFC1918"
		when /^172\.28\./
			return "RFC1918"
		when /^172\.29\./
			return "RFC1918"
		when /^172\.30\./
			return "RFC1918"
		when /^172\.31\./
			return "RFC1918"
		when /^169\.254\./
			return "ZEROCONF"
		when /^127\./
			return "LOCALNET"
		when /^0\./
			return "BOGON"
		when /^1\./
			return "BOGON"
		when /^2\./
			return "BOGON"
		when /^5\./
			return "BOGON"
		when /^7\./
			return "BOGON"
		when /^23\./
			return "BOGON"
		when /^27\./
			return "BOGON"
		when /^31\./
			return "BOGON"
		when /^36\./
			return "BOGON"
		when /^37\./
			return "BOGON"
		when /^39\./
			return "BOGON"
		when /^42\./
			return "BOGON"
		when /^49\./
			return "BOGON"
		when /^50\./
			return "BOGON"
		when /^100\./
			return "BOGON"
		when /^101\./
			return "BOGON"
		when /^102\./
			return "BOGON"
		when /^103\./
			return "BOGON"
		when /^104\./
			return "BOGON"
		when /^105\./
			return "BOGON"
		when /^106\./
			return "BOGON"
		when /^107\./
			return "BOGON"
		when /^108\./
			return "BOGON"
		when /^109\./
			return "BOGON"
		when /^110\./
			return "BOGON"
		when /^111\./
			return "BOGON"
		when /^112\./
			return "BOGON"
		when /^113\./
			return "BOGON"
		when /^173\./
			return "BOGON"
		when /^174\./
			return "BOGON"
		when /^175\./
			return "BOGON"
		when /^176\./
			return "BOGON"
		when /^177\./
			return "BOGON"
		when /^178\./
			return "BOGON"
		when /^179\./
			return "BOGON"
		when /^180\./
			return "BOGON"
		when /^181\./
			return "BOGON"
		when /^182\./
			return "BOGON"
		when /^183\./
			return "BOGON"
		when /^184\./
			return "BOGON"
		when /^185\./
			return "BOGON"
		when /^192\.0\.2/
			return "BOGON"
		when /^197\./
			return "BOGON"
		when /^198\.18\./
			return "BOGON"
		when /^198\.19\./
			return "BOGON"
		when /^223\./
			return "BOGON"
		when /^224\./
			return "BOGON"
		when /^225\./
			return "BOGON"
		when /^226\./
			return "BOGON"
		when /^227\./
			return "BOGON"
		when /^228\./
			return "BOGON"
		when /^229\./
			return "BOGON"
		when /^230\./
			return "BOGON"
		when /^231\./
			return "BOGON"
		when /^232\./
			return "BOGON"
		when /^233\./
			return "BOGON"
		when /^234\./
			return "BOGON"
		when /^235\./
			return "BOGON"
		when /^236\./
			return "BOGON"
		when /^237\./
			return "BOGON"
		when /^238\./
			return "BOGON"
		when /^239\./
			return "BOGON"
		when /^240\./
			return "BOGON"
		when /^241\./
			return "BOGON"
		when /^242\./
			return "BOGON"
		when /^243\./
			return "BOGON"
		when /^244\./
			return "BOGON"
		when /^245\./
			return "BOGON"
		when /^246\./
			return "BOGON"
		when /^247\./
			return "BOGON"
		when /^248\./
			return "BOGON"
		when /^249\./
			return "BOGON"
		when /^250\./
			return "BOGON"
		when /^251\./
			return "BOGON"
		when /^252\./
			return "BOGON"
		when /^253\./
			return "BOGON"
		when /^254\./
			return "BOGON"
		when /^255\./
			return "BOGON"
	end
	return nil
end
