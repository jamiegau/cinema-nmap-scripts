local nmap = require "nmap"
local stdnse = require "stdnse"
local nsedebug = require "nsedebug"


description = [[
Detects socket fingerprint of digitall dCine e-cinema device and flags if found.
Will attempt to pull out software and firmware version of system
]]

--------------------------------------------------------------------
---
-- @usage
-- nmap -sS -p 21,22,80,4242,5900 --script=cinema-digitall-dcine <target>
-- @output
-- PORT      STATE  SERVICE REASON
-- PORT     STATE  SERVICE
-- 21/tcp   open   ftp
-- 22/tcp   closed ssh
-- 80/tcp   open   http
-- 4242/tcp open   vrml-multi-use
-- | cinema-digitall-dcine:
-- |   classification: e-cinema
-- |   vendor: digitAll
-- |   productName: dCine
-- |   serialNumber: 08156
-- |   version: 13.4 Mar  9 2018 16:55:57
-- |_  owner: Centre Cinemas
-- 5900/tcp open   vnc

-- Nmap done: 1 IP address (1 host up) scanned in 1.32 seconds
--

author = "James Gardiner"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "cinema", "safe", "intrusive" }

-- if port 2000 is open, we try and query the system Doby Player
portrule = function(host, port)
	if port.number ~= 4242 then
		return false
	end

	stdnse.debug("port is " .. port.state .. ", protocol is " .. port.protocol)
	if port.state ~= "open" or port.protocol ~= "tcp" then
		return false
	end

	-- if port 80 and all these following ports are open, we can assume its a Dolby player
	local ftp = { number = 21, protocol = "tcp" }
	local ftp_open = nmap.get_port_state(host, ftp)
	local ssh = { number = 22, protocol = "tcp" }
	local ssh_open = nmap.get_port_state(host, ssh)
	local http80 = { number = 80, protocol = "tcp" }
	local http80_open = nmap.get_port_state(host, http80)
	local vnc = { number = 5900, protocol = "tcp" }
	local vnc_open = nmap.get_port_state(host, vnc)


	local res = false
	if ftp_open.state == 'open' and
		ssh_open.state ~= 'open' and
		http80_open.state == 'open' and
		vnc_open.state == 'open' then
		res = true
	end
	return res
end


-------------------------------------------------------------------------------------------------------------

local function Split(s, delimiter)
	local result = {};
	for match in (s .. delimiter):gmatch("(.-)" .. delimiter) do
		table.insert(result, match);
	end
	return result;
end

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

local function dcine_request_data(host)
	stdnse.debug("dcine_request_data " .. host.ip)
	local socket, try, catch

	local serialNumber_string = "##4\nInit\n"
	stdnse.debug("Get version cmd: " .. serialNumber_string)

	socket = nmap.new_socket()
	socket:set_timeout(1000)
	catch = function()
		stdnse.debug('Socket exception')
		socket:close()
		return false, 'Socket exception, melformed message.', ''
	end
	try = nmap.new_try(catch)
	try(socket:connect(host, 4242))

	try(socket:send(serialNumber_string))

	local status, result = socket:receive_bytes(2024)
	stdnse.debug("result status (did I get a result): " .. nsedebug.tostr(status))
	stdnse.debug("---------------------------------")
	if status == false or status == nil or status == 'nil' then
		return false, 'Socket exception: ' .. result
	end

	data_str = all_trim(result)

	return true, 'OK', data_str
end

-----------------------------------------------------------------------------
--
local function hex_to_char(x)
	return string.char(tonumber(x, 16))
end

local function unescape(url)
	url = url:gsub("%%(%x%x)", hex_to_char)
	return url:gsub("+", " ")
end

local function getDcineConfig(key, data_str)
	stdnse.debug("getDcineConfig " .. key)
	local res = "na"
	local lines = {}
	for s in data_str:gmatch("[^\r\n]+") do
		table.insert(lines, s)
	end
	for i, line in ipairs(lines) do
		if string.find(line, key) then
			local line_array = Split(line, '=')
			-- stdnse.debug("line_array = " .. nsedebug.tostr(line_array))
			res = all_trim(line_array[2])
			break
		end
	end
	if key == "sVersion" or key == "sBuild" or key == "sOwner" then
		res = unescape(res)
	end
	return res
end

------------------------------------------------------------------------------

-- Now lets try and query the player for some useful information
action = function(host, port)
	--
	local output = stdnse.output_table()
	-- required variables are
	--- classification, vendor, productName, serialNumber, softwareVersion
	output.classification = 'e-cinema'
	output.vendor = 'digitAll'

	local v_status, v_res, data_str = dcine_request_data(host)
	if v_status ~= true then
		output.error = v_res
		return output
	end

	local productName = getDcineConfig("sApplication", data_str)
	local serialNumber = getDcineConfig("sLicense", data_str)
	local version_p1 = getDcineConfig("sVersion", data_str)
	local version_p2 = getDcineConfig("sBuild", data_str)
	local owner = getDcineConfig("sOwner", data_str)

	output.productName = productName
	output.serialNumber = serialNumber
	output.version = version_p1 .. " " .. version_p2
	output.owner = owner

	return output
end
