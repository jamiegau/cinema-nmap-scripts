local nmap = require "nmap"
local stdnse = require "stdnse"
local nsedebug = require "nsedebug"


description = [[
Detects socket fingerprint of Edge Jenior IO automation-io device and flags if found.
Will attempt to pull out software and firmware version of system
]]

--------------------------------------------------------------------
---
-- @usage
-- nmap -sS -p 21,22,80,111,61408 --script=cinema-dolby-cp750 <target>
-- @output
-- PORT      STATE  SERVICE REASON
--

author = "James Gardiner"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "cinema", "safe", "intrusive" }

-- if port 2000 is open, we try and query the system Doby Player
portrule = function(host, port)
	if port.number ~= 1125 then
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
	local http_open = nmap.get_port_state(host, http80)


	local res = false
	if ftp_open.state == 'open' and
		ssh_open.state ~= 'open' and
		http_open.state ~= 'open' then
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

local function jenior_io_request_version(host)
	stdnse.debug("jenior_io_request_version " .. host.ip)
	local result, socket, try, catch

	local version_string = "\r\n"
	stdnse.debug("Get version cmd: " .. version_string)

	socket = nmap.new_socket()
	socket:set_timeout(500)
	catch = function()
		stdnse.debug('Socket exception')
		socket:close()
		return false, 'Socket exception, melformed message.', ''
	end
	try = nmap.new_try(catch)
	try(socket:connect(host, 61408))

	try(socket:send(version_string))

	local status, result = socket:receive_bytes(1024)
	stdnse.debug("result - status: " .. nsedebug.tostr(status))
	if status == false or status == nil or status == 'nil' then
		return false, 'Socket exception: ' .. result
	end
	local version_array = Split(all_trim(result), ' ')
	local version = version_array[2]
	stdnse.debug("result - data: " .. version)
	version = version:gsub("\x00", "")
	version = all_trim(version)

	return true, 'OK', version
end

-----------------------------------------------------------------------------
-- serialNumber
local function jenior_io_request_serialNumber(host)
	stdnse.debug("jenior_io_request_serialNumber " .. host.ip)
	local result, socket, try, catch

	local serialNumber_string = "\r\n"
	stdnse.debug("Get version cmd: " .. serialNumber_string)

	socket = nmap.new_socket()
	socket:set_timeout(500)
	catch = function()
		stdnse.debug('Socket exception')
		socket:close()
		return false, 'Socket exception, melformed message.', ''
	end
	try = nmap.new_try(catch)
	try(socket:connect(host, 61408))

	try(socket:send(serialNumber_string))

	local status, result = socket:receive_bytes(1024)
	stdnse.debug("result - status: " .. nsedebug.tostr(status))
	if status == false or status == nil or status == 'nil' then
		return false, 'Socket exception: ' .. result
	end

	local serialNumber_array = Split(all_trim(result), ' ')
	local serialNumber = serialNumber_array[2]
	stdnse.debug("result - data: " .. serialNumber)
	serialNumber = serialNumber:gsub("\x00", "")
	serialNumber = all_trim(serialNumber)

	return true, 'OK', serialNumber
end

------------------------------------------------------------------------------

-- Now lets try and query the player for some useful information
action = function(host, port)
	--
	local output = stdnse.output_table()
	-- required variables are
	--- classification, vendor, productName, serialNumber, softwareVersion
	output.classification = 'automation-io'
	output.vendor = 'Edge'

	local v_status, v_res, version = jenior_io_request_version(host)
	if v_status ~= true then
		output.error = v_res
		return output
	end

	local sn_status, sn_res, serialNumber = jenior_io_request_serialNumber(host)
	if sn_status ~= true then
		output.error = sn_res
		return output
	end

	output.productName = "Senior-IO"
	output.serialNumber = serialNumber
	output.version = version

	return output
end
