local nmap = require "nmap"
local stdnse = require "stdnse"
local nsedebug = require "nsedebug"
local http = require "http"


description = [[
Detects socket fingerprint of RLY-8 automation-io device and flags if found.
Will attempt to pull out software and firmware version of system
]]

--------------------------------------------------------------------
---
-- @usage
-- sudo nmap -sS -n -p 21,22,80,5000 --script cinema-KMTronic-8portWebRelay <target>
-- @output
-- PORT     STATE  SERVICE
-- PORT     STATE    SERVICE REASON
-- 21/tcp   filtered ftp     no-response
-- 22/tcp   filtered ssh     no-response
-- 80/tcp   open     http    syn-ack ttl 97
-- | cinema-KMTronic-8portWebRelay:
-- |   classification: automation-io
-- |   vendor: KMTronix
-- |   productName: KMTronicWebRelay8
-- |_  serialNumber: na
-- 5000/tcp filtered upnp    no-response

author = "James Gardiner"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "cinema", "safe", "intrusive" }


----------------------------------------------------------------------------------------------------

local function all_trim(s)
	if s == nil then
		return ''
	end

	local res = s:match("^%s*(.-)%s*$")
	res = res:gsub("\x00", "")
	return res
end

--

function TableConcat(t1, t2)
	for i = 1, #t2 do
		t1[#t1 + 1] = t2[i]
	end
	return t1
end

function Split(s, delimiter)
	result = {};
	for match in (s .. delimiter):gmatch("(.-)" .. delimiter) do
		table.insert(result, match);
	end
	return result;
end

local function KMtronic_request(host)
	local is_KMtronic = false
	local path = '/'
	stdnse.debug("--KMtronic_request " .. path)

	local result = http.get(host, 80, path, nil)
	-- stdnse.pretty_printer(result)
	if (result['status'] ~= 200 or result['content-length'] == 0) then
		return false, 'http request Failed'
	end
	-- check the title of the HTML page is, <title>KMtronic Relays Control Web Server</title>
	local http_title = all_trim(string.match(result['body'], '<title>(.-)</title>'))
	if http_title == 'KMtronic Relays Control Web Server' then
		is_KMtronic = true
	end
	local split0 = Split(result['body'], '<div align="left">')
	local split1 = Split(all_trim(split0[1]), '</div>')
	local version = split1[0]

	return is_KMtronic, 'OK', version
end

----------------------------------------------------------------------------------------------
-- if port 80 is open, we try and query the system Doby Player
portrule = function(host, port)
	if port.number ~= 80 then
		return false
	end

	stdnse.debug("port is " .. port.state .. ", protocol is " .. port.protocol)
	if port.state ~= "open" or port.protocol ~= "tcp" then
		return false
	end

	-- if port 80 open and all other closed
	local ftp = { number = 21, protocol = "tcp" }
	local ftp_open = nmap.get_port_state(host, ftp)
	local ssh = { number = 22, protocol = "tcp" }
	local ssh_open = nmap.get_port_state(host, ssh)
	local p5000 = { number = 5000, protocol = "tcp" }
	local p5000_open = nmap.get_port_state(host, p5000)

	local res = false
	if ftp_open.state ~= 'open' and
		ssh_open.state ~= 'open' and
		p5000_open.state ~= 'open' then
		res = true
	end

	-- if we don;t get a suitable response from prot 80, don;t report anything.
	local rly_status, rly_res, version = KMtronic_request(host.ip)
	return rly_status
end

----------------------------------------------------------------------------------------------
-- Now lets try and query the player for some useful information
action = function(host, port)
	--
	local output = stdnse.output_table()
	-- required variables are
	--- classification, vendor, productName, serialNumber, softwareVersion
	output.classification = 'automation-io'
	output.vendor = 'KMTronix'

	local rly_status, rly_res, version = KMtronic_request(host)
	if rly_status ~= true then
		-- output.error = rly_res
		-- a common port 80 only device, so ignore output if we don;t get what we want.
		return true
	end

	output.productName = "KMTronicWebRelay8"
	output.serialNumber = 'na'
	output.version = version

	return output
end
