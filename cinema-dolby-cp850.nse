
local nmap = require "nmap"
local stdnse = require "stdnse"
local nsedebug = require "nsedebug"


description = [[
Detects socket fingerprint of Dolby CP850 sound processor device and flags if found.
Reads the active macro preset/name plus fader and mute levels using read-only queries.

The CP850 listens on the same TCP port as the CP750 (61408) but speaks a
different API: commands carry no "cp750." prefix, and it answers
sys.macro_preset / sys.macro_name, which the CP750 ignores. The CP950
shares this API (per the Bitfocus Companion dolby-cinemaprocessor module),
but this script was verified against a CP850 only.

WARNING: the CP850 command stack is fragile. It tolerates a single,
unhurried connection; rapid successive connections wedged a live unit
(port 61408 refusing connections until reboot, audio playback unaffected).
This script therefore uses ONE connection for all queries with pauses
between them. Do not run it in a loop against a CP850.
]]

--------------------------------------------------------------------
---
-- @usage
-- nmap -sS -p 80,111,61408 --script=cinema-dolby-cp850 <target>
-- @output
-- PORT      STATE  SERVICE REASON
-- 80/tcp    open   http    syn-ack ttl 64
-- 111/tcp   closed rpcbind reset ttl 64
-- 61408/tcp open   unknown syn-ack ttl 64
-- | cinema-dolby-cp850:
-- |   classification: sound-processor
-- |   vendor: Dolby
-- |   productName: CP850
-- |   macroPreset: 3
-- |   macroName: Non-Sync
-- |   faderLevel: 3.7
-- |_  muteStatus: Unmuted
--

author = "Juan Marin"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "cinema", "safe", "intrusive" }

-- port 61408 must be open. The CP850 also serves its web UI on port 80
-- (the CP750 does not) and, unlike the CP750, it does not listen on
-- port 111. Checking this first tells CP850 and CP750 apart before any
-- query is sent.
portrule = function(host, port)
	if port.number ~= 61408 then
		return false
	end

	stdnse.debug("port is " .. port.state .. ", protocol is " .. port.protocol)
	if port.state ~= "open" or port.protocol ~= "tcp" then
		return false
	end

	local http80 = { number = 80, protocol = "tcp" }
	local http_open = nmap.get_port_state(host, http80)
	local p111 = { number = 111, protocol = "tcp" }
	local p111_open = nmap.get_port_state(host, p111)

	local res = false
	if http_open ~= nil and http_open.state == 'open' and
		(p111_open == nil or p111_open.state ~= 'open') then
		res = true
	end
	return res
end


-------------------------------------------------------------------------------------------------------------

local function all_trim(s)
	if s == nil then
		return ''
	end
	local res = s:match("^%s*(.-)%s*$")
	res = res:gsub("\x00", "")
	return res
end

------------------------------------------------------------------------------

-- Queries the processor over a SINGLE connection with pauses between
-- commands (see WARNING above). Returns a table of raw replies keyed by
-- command, or nil if the unit did not answer as a CP850.
local function cp850_query_all(host)
	stdnse.debug("cp850_query_all " .. host.ip)
	local socket, try, catch
	local replies = {}

	socket = nmap.new_socket()
	socket:set_timeout(4000)
	catch = function()
		stdnse.debug('Socket exception')
		socket:close()
		return nil
	end
	try = nmap.new_try(catch)
	try(socket:connect(host, 61408))
	stdnse.sleep(0.5)

	local cmds = { "sys.macro_preset ?", "sys.macro_name ?", "sys.fader ?", "sys.mute ?" }
	for _, cmd in ipairs(cmds) do
		try(socket:send(cmd .. "\r\n"))
		stdnse.sleep(0.5)
		local status, result = socket:receive_bytes(1024)
		stdnse.debug(cmd .. " - status: " .. nsedebug.tostr(status))
		if status == false or status == nil or status == 'nil' then
			socket:close()
			return nil
		end
		replies[cmd] = all_trim(result)
	end
	socket:close()
	return replies
end

------------------------------------------------------------------------------

-- Now lets query the processor for macro, fader and mute status
action = function(host, port)
	--
	local output = stdnse.output_table()
	-- required variables are
	--- classification, vendor, productName, serialNumber, softwareVersion
	output.classification = 'sound-processor'
	output.vendor = 'Dolby'

	local replies = cp850_query_all(host)
	if replies == nil then
		return nil
	end

	-- sys.macro_preset is the discriminator: only CP850/CP950 answer it.
	-- A CP750 stays silent, so anything else means "not a CP850".
	local preset = replies["sys.macro_preset ?"]:match("^sys%.macro_preset%s+(%S+)")
	if preset == nil then
		return nil
	end

	output.productName = "CP850"
	output.macroPreset = preset

	local macro_name = replies["sys.macro_name ?"]:match("^sys%.macro_name%s+(.+)$")
	if macro_name ~= nil then
		output.macroName = macro_name
	end

	local level = replies["sys.fader ?"]:match("^sys%.fader%s+(%d+)")
	if level ~= nil then
		output.faderLevel = string.format("%.1f", tonumber(level) / 10)
	end

	local mute = replies["sys.mute ?"]:match("^sys%.mute%s+(%d+)")
	if mute ~= nil then
		if mute == "0" then
			output.muteStatus = "Unmuted"
		else
			output.muteStatus = "Muted"
		end
	end

	return output
end
