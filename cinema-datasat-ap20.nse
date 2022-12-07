local nmap = require "nmap"
local stdnse = require "stdnse"
local nsedebug = require "nsedebug"


description = [[
Detects socket fingerprint of Dolby CP750 sound processor device and flags if found.
Will attempt to pull out software and firmware version of system
]]

--------------------------------------------------------------------
---
-- @usage
-- nmap -sS -p 21,22,23,14500 --script=cinema-datasat-ap20 <target>
-- @output
-- PORT      STATE  SERVICE REASON
-- 21/tcp    closed ftp     reset ttl 255
-- 22/tcp    closed ssh     reset ttl 255
-- 14500/tcp    closed http    reset ttl 255
-- | cinema-datasat-ap20:
-- |   classification: sound-processor
-- |   vendor: DataSat
-- |   productName: AP20
-- |   serialNumber: blarr
-- |_  version: aNumber
-- MAC Address: 00:D0:46:08:EC:31 (**)
--

author = "James Gardiner"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "cinema", "safe", "intrusive" }

-- if port 14500 is open, we try and query the system Doby Player
portrule = function(host, port)
	if port.number ~= 14500 then
		return false
	end

	stdnse.debug("port is " .. port.state .. ", protocol is " .. port.protocol)
	if port.state ~= "open" or port.protocol ~= "tcp" then
		return false
	end

	local ftp = { number = 21, protocol = "tcp" }
	local ftp_open = nmap.get_port_state(host, ftp)
	local ssh = { number = 22, protocol = "tcp" }
	local ssh_open = nmap.get_port_state(host, ssh)
	local telnet = { number = 23, protocol = "tcp" }
	local telnet_open = nmap.get_port_state(host, telnet)
	local p14500 = { number = 14500, protocol = "tcp" }
	local p14500_open = nmap.get_port_state(host, p14500)


	local res = false
	if ftp_open.state == 'open' and
		ssh_open.state == 'open' and
		telnet_open.state == 'open' and
		p14500_open.state == 'open' then
		res = true
	end
	return res
end


-------------------------------------------------------------------------------------------------------------

local function Split(s, delimiter, limit)
	local counter = 1
	local result = {};
	for match in (s .. delimiter):gmatch("(.-)" .. delimiter) do
		table.insert(result, match);
		if counter == limit then

			break
		end
		counter = counter + 1
	end
	return result;
end

-- Split a string into a table using a delimiter and a limit
string.split = function(str, pat, limit)
	local t = {}
	local fpat = "(.-)" .. pat
	local last_end = 1
	local s, e, cap = str:find(fpat, 1)
	while s do
		if s ~= 1 or cap ~= "" then
			table.insert(t, cap)
		end

		last_end = e + 1
		s, e, cap = str:find(fpat, last_end)

		if limit ~= nil and limit <= #t then
			break
		end
	end

	if last_end <= #str then
		cap = str:sub(last_end)
		table.insert(t, cap)
	end

	return t
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

-------------------------------------------------------------------------------------------------------------

local function ap20_request_version(host)
	stdnse.debug("ap20_request_version " .. host.ip)
	local socket, try, catch

	local system_string = "@SYSTEM\r\n"
	stdnse.debug("Get version cmd: " .. all_trim(system_string))

	socket = nmap.new_socket()
	socket:set_timeout(500)
	catch = function()
		stdnse.debug('Socket exception')
		socket:close()
		return false, 'Socket exception, melformed message.', ''
	end
	try = nmap.new_try(catch)
	try(socket:connect(host, 14500))

	try(socket:send(system_string))

	local status, result = socket:receive_bytes(1024)
	stdnse.debug("result - status: " .. nsedebug.tostr(status))
	if status == false or status == nil or status == 'nil' then
		return false, 'Socket exception: ' .. result
	end

	-- stdnse.debug("result:\n" .. nsedebug.tostr(result))

	local lines_array = string.split(all_trim(result), '\n', 4)
	-- stdnse.debug("lines_array: " .. nsedebug.tostr(lines_array))
	-- stdnse.debug("lines_array[1]: " .. nsedebug.tostr(lines_array[1]))
	-- stdnse.debug("test: " .. nsedebug.tostr(string.split(all_trim(lines_array[1]), ' ', 1)))

	local version_str = all_trim(string.split(all_trim(lines_array[1]), ' ', 1)[2])
	stdnse.debug("version_str: " .. nsedebug.tostr(version_str))

	local version_date_str = all_trim(string.split(all_trim(lines_array[2]), ' ', 1)[2])
	stdnse.debug("version_date_str: " .. nsedebug.tostr(version_date_str))

	return true, 'OK', version_str .. " " .. version_date_str
end

local function ap20_request_serialNumber(host)
	stdnse.debug("ap20_request_serialNumber for " .. host.ip)
	local socket, try, catch

	local serial_cmd_str_string = "@SERIALNO\r\n"
	stdnse.debug("Get serial_cmd_str_string: " .. all_trim(serial_cmd_str_string))

	socket = nmap.new_socket()
	socket:set_timeout(500)
	catch = function()
		stdnse.debug('Socket exception')
		socket:close()
		return false, 'Socket exception, melformed message.', ''
	end
	try = nmap.new_try(catch)
	try(socket:connect(host, 14500))

	try(socket:send(serial_cmd_str_string))

	local status, result = socket:receive_bytes(1024)
	stdnse.debug("result - status: " .. nsedebug.tostr(status))
	if status == false or status == nil or status == 'nil' then
		return false, 'Socket exception: ' .. result
	end

	stdnse.debug("result:\n" .. nsedebug.tostr(result))

	local lines_array = string.split(all_trim(result), '\n', 5)
	stdnse.debug("lines_array: " .. nsedebug.tostr(lines_array))
	local serial_str = all_trim(string.split(all_trim(lines_array[1]), ' ', 1)[2])
	stdnse.debug("serial_str: " .. nsedebug.tostr(serial_str))

	return true, 'OK', serial_str
end

------------------------------------------------------------------------------

-- Now lets try and query the player for some useful information
action = function(host, port)
	--
	local output = stdnse.output_table()
	-- required variables are
	--- classification, vendor, productName, serialNumber, softwareVersion
	output.classification = 'sound-processor'
	output.vendor = 'DataSat'

	local v_status, v_res, version = ap20_request_version(host)
	if v_status ~= true then
		output.error = v_res
		return output
	end

	local sn_status, sn_res, serialNumber = ap20_request_serialNumber(host)
	if sn_status ~= true then
		output.error = sn_res
		return output
	end

	output.productName = "AP20"
	output.serialNumber = serialNumber
	output.version = version

	return output
end
