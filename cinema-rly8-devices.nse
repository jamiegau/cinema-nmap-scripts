local nmap = require "nmap"
local stdnse = require "stdnse"
local nsedebug = require "nsedebug"
local json = require "json"


description = [[
Detects socket fingerprint of RLY-8 automation-io device and flags if found.
Will attempt to pull out software and firmware version of system
]]

--------------------------------------------------------------------
---
-- @usage
-- nmap -sS -p 21,22,80,2000 --script=cinema-rly8-devices <target>
-- @output
-- PORT     STATE  SERVICE
-- 21/tcp   closed ftp
-- 22/tcp   closed ssh
-- 80/tcp   closed http
-- 2000/tcp open   cisco-sccp
-- | cinema-rly8-devices:
-- |   classification: automation-io
-- |   vendor: RLY-8
-- |   productName: RLY-8
-- |   serialNumber: na
-- |_  version: V1.0U

author = "James Gardiner"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "cinema", "safe", "intrusive" }

-- if port 2000 is open, we try and query the system Doby Player
portrule = function(host, port)
	if port.number ~= 2000 then
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
	if ftp_open.state ~= 'open' and
		ssh_open.state ~= 'open' and
		http_open.state ~= 'open' then
		res = true
	end
	return res
end

----------------------------------------------------------------------------------------------------
local function PrintHex(data)
	if data == nil then
		return ''
	end
	local res = ''
	for i = 1, #data do
		local char = string.sub(data, i, i)
		local pinrt_char
		if char:match '[^ -~\n\t]' then
			pinrt_char = ' '
		else
			pinrt_char = char
		end
		local char_as_hex = pinrt_char .. string.format("%02x", string.byte(char)) .. ' '
		-- print('loop ' .. i .. ', char ' .. char .. ', char_as_hex ' .. char_as_hex)
		res = res .. char_as_hex
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

--

function TableConcat(t1, t2)
	for i = 1, #t2 do
		t1[#t1 + 1] = t2[i]
	end
	return t1
end

local function rly8_request(host)
	stdnse.debug("rly8_request " .. host.ip)
	local result, socket, try, catch

	local version_string = "{\"get\":\"version\"}\r\n"
	stdnse.debug("Get version cmd: " .. version_string)

	socket = nmap.new_socket()
	socket:set_timeout(500)
	catch = function()
		stdnse.debug('Socket exception')
		socket:close()
		return false, 'Socket exception, melformed message.', ''
	end
	try = nmap.new_try(catch)
	try(socket:connect(host, 2000))

	try(socket:send(version_string))

	local status, result = socket:receive_bytes(1024)
	stdnse.debug("result - status: " .. nsedebug.tostr(status))
	if status == false or status == nil or status == 'nil' then
		return false, 'Socket exception: ' .. result
	else
		result = all_trim(result)
		stdnse.debug("result - data: " .. result)
		stdnse.debug("result - hex : " .. PrintHex(result))
	end

	local json_status, as_table = json.parse(result)
	stdnse.debug('json_status = ' .. nsedebug.tostr(json_status))
	stdnse.debug('as_table = ' .. nsedebug.tostr(as_table))

	local version = as_table.version

	version = version:gsub("\x00", "")
	version = all_trim(version)

	----------

	return true, 'OK', version
end

-- Now lets try and query the player for some useful information
action = function(host, port)
	-- -- test code
	-- local json_str = '{"version":"V1.0U"}'
	-- local json_table, json_table2 = json.parse(json_str)
	-- stdnse.debug('json_table = ' .. nsedebug.tostr(json_table))
	-- stdnse.debug('json_table2 = ' .. nsedebug.tostr(json_table2))
	--
	local output = stdnse.output_table()
	-- required variables are
	--- classification, vendor, productName, serialNumber, softwareVersion
	output.classification = 'automation-io'
	output.vendor = 'RLY-8'

	local rly_status, rly_res, version = rly8_request(host)
	if rly_status ~= true then
		output.error = rly_res
		return output
	end

	output.productName = "RLY-8"
	output.serialNumber = "na"
	output.version = version

	return output
end
