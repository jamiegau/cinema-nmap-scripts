local nmap = require "nmap"
local stdnse = require "stdnse"
local http = require "http"
local nsedebug = require "nsedebug"

description = [[
Detects socket fingerprint of QSC-USL cinema devices and flags if found.
Will attempt to pull out software and firmware version of system
]]

--------------------------------------------------------------------
---
-- @usage
-- nmap -sS -p21,22,80,10001 --script=cinema-qsc-usl-devices <target>
-- @output
-- PORT      STATE    SERVICE
-- 21/tcp    filtered ftp
-- 22/tcp    filtered ssh
-- 80/tcp    open     http
-- | cinema-qsc-usl-devices:
-- |   classification: sound-processor
-- |   vendor: QSC-USL
-- |   productName: JSD-60
-- |   serialNumber: 3458
-- |   version: E,141205,141218,141014
-- |   PCBversion: E
-- |   bootloaderVersion: 141205
-- |   picVersion: 141218
-- |   dspVersion: 141014
-- |   hostname: JSD60-FORBES-C1
-- |   theaterName: Forbes Services Club
-- |   theaterNumber: 1
-- |   dcs: IMS2000
-- |   automation: JNIOR
-- |   comments:
-- |_  projector: NC1100L-A
-- 10001/tcp open     scp-config

author = "James Gardiner"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "cinema", "safe", "intrusive" }

-- if port 80 and port  21, 22, 10001 states match a device fingerprint..
portrule = function(host, port)
	if port.number ~= 80 then
		return false
	end

	if port.state ~= "open" or port.protocol ~= "tcp" then
		return false
	end

	-- if port 80 and all these following ports are open, we can assume its a Dolby player
	local ftp = { number = 21, protocol = "tcp" }
	local ftp_open = nmap.get_port_state(host, ftp)
	local ssh = { number = 22, protocol = "tcp" }
	local ssh_open = nmap.get_port_state(host, ssh)
	local usl = { number = 10001, protocol = "tcp" }
	local usl_open = nmap.get_port_state(host, usl)

	local res = false
	if ftp_open.state ~= 'open' and
		ssh_open.state ~= 'open' and
		usl_open.state == 'open' then
		res = true
	end
	return res
end

-------------------------------------------------------------------------------------------------------------

local function all_trim(s)
	if s == nil then
		return ''
	end
	return s:match("^%s*(.-)%s*$")
end

function TableConcat(t1, t2)
	for i = 1, #t2 do
		t1[#t1 + 1] = t2[i]
	end
	return t1
end

local function socket_command(host, cmd)
	local port = { number = 10001, protocol = 'tcp' }
	local socket = nmap.new_socket()
	socket:set_timeout(500)

	local catch = function()
		print('Catch on connection')
		socket:close()
	end

	local try = nmap.new_try(catch)

	try(socket:connect(host.ip, port.number))

	-- print('Send command [' .. all_trim(cmd) .. ']')
	try(socket:send(cmd))

	local response = try(socket:receive_lines(1))
	socket:close()

	response = all_trim(response)
	return response
end

local function split(str, sep)
	local result = {}
	local regex = ("([^%s]+)"):format(sep)
	for each in str:gmatch(regex) do
		table.insert(result, each)
	end
	return result
end

local function getHttpUrl(host, urlPath)
	local http_port = { number = 80, protocol = 'tcp' }
	local get_res = http.get(host, http_port, urlPath)
	-- stdnse.debug("http GET = " .. nsedebug.tostr(get_res))

	local res, body
	if get_res.status == 404 then
		res = false
	else
		res = true
		body = get_res.body
	end
	return res, body
end

local function magiclines(s)
	if s:sub(-1) ~= "\n" then s = s .. "\n" end
	return s:gmatch("(.-)\n")
end

local function oldJsd100_search(search_str, body)
	local res
	for line in magiclines(body) do
		if string.find(line, '<tr><td>' .. search_str .. '</td><td>') then
			local line_array = Split(line, '</td><td>')
			stdnse.debug("line_array = " .. nsedebug.tostr(line_array))
			res = line_array[1]
		end
	end
	return res
end

-- Now lets try and query the player for some useful information
action = function(host, port)
	local productName = 'na'
	local serialNumber = 'na'
	local classification = 'na'
	local version = nil
	local PCBversion = nil
	local bootloaderVersion = nil
	local picVersion = nil
	local dspVersion = nil
	local hostname = nil
	local theaterName = nil
	local theaterNumber = nil
	local dcs = nil
	local automation = nil
	local comments = nil
	local projector = nil

	local lineOneTable, lineTwoTable

	local output = stdnse.output_table()
	--
	-- Fetch the http://host/ConfigFlash.html
	local get_status, configFlash_body
	local get_status2, configFlash_body2
	local get_status3, page_body3

	get_status, configFlash_body = getHttpUrl(host, '/ConfigFlash.html')
	stdnse.debug("get_status = " .. nsedebug.tostr(get_status))
	if get_status == false then
		get_status2, configFlash_body = getHttpUrl(host, '/debug/ConfigFlash.html')
		stdnse.debug("get_status2 = " .. nsedebug.tostr(get_status2))
		if get_status2 == false then
			--
			-- could be an old IRC-28C with older firmware that does not suppore ConfigFlash.html
			get_status3, page_body3 = getHttpUrl(host, '/')
			stdnse.debug("get_status3 = " .. nsedebug.tostr(get_status3))
			if get_status3 == true then
				-- looks like a IRC-28C or older JSD100
				local page_title = all_trim(string.match(page_body3, '<title>(.-)</title>'))
				stdnse.debug("page_title = " .. nsedebug.tostr(page_title))
				if page_title == 'USL Caption Encoder' then
					-- special case, a older firmware IRC-28C
					stdnse.debug('special case, a older firmware IRC-28C')
					local h1 = all_trim(string.match(page_body3, '<h1>(.-)</h1>'))
					productName = 'IRC-28C'
					version = split(h1, ' ')[4]
					classification = 'accessibility'
				end
				if string.find(page_title, 'JSD-100') then
					-- special case, a older firmware JSD-100
					stdnse.debug('special case, a older firmware JSD-100')
					local h1 = all_trim(string.match(page_body3, '<h1>(.-)</h1>'))
					productName = 'OLD-JSD-100'
				end
			else
				return false
			end
		end
	end

	if configFlash_body ~= nil then
		-- stdnse.pretty_printer(configFlash_body)
		local configFlash = string.match(configFlash_body, '<pre>(.-)</pre>')
		configFlash = all_trim(configFlash)
		configFlash = configFlash:gsub("\x0D", "")
		-- before we plit into lines, check if its a IRC by looking for 'irc.sys.ip'
		local irc_start, irc_end = string.find(configFlash, 'irc.sys.ip')
		if irc_start ~= nil then
			productName = "IRC-28C"
		end
		--
		local configFlash_table = split(configFlash, "\n")
		-- stdnse.pretty_printer(configFlash_table)
		lineOneTable = split(configFlash_table[1], ' ')
		lineTwoTable = split(configFlash_table[2], ' ')
		-- print('--------------------- lineOneTable -----------------')
		-- stdnse.pretty_printer(lineOneTable)
		if lineOneTable[3] == "JSD-60" or
			lineOneTable[3] == "JSD-100" then
			classification = 'sound-processor'
			productName = lineOneTable[3]
		elseif lineOneTable[3] == "CM-8E" then
			classification = 'sound-device'
		elseif lineOneTable[3] == "LSS-200" then
			classification = 'quality-assurance'
			productName = lineOneTable[3]
			serialNumber = 'to implement'
			version = 'to implement'
		elseif productName == "IRC-28C" then
			-- productName = "IRC-28C"
			classification = 'accessibility'
		end
	end



	if productName == 'JSD-60' then
		serialNumber = all_trim(socket_command(host, 'jsd60.sys.serial_number\r\n'))
		theaterName = socket_command(host, 'jsd60.sys.theater_name\r\n')
		theaterNumber = socket_command(host, 'jsd60.sys.theater_number\r\n')
		dcs = socket_command(host, 'jsd60.sys.dcs\r\n')
		automation = socket_command(host, 'jsd60.sys.automation\r\n')
		comments = socket_command(host, 'jsd60.sys.comments\r\n')
		projector = socket_command(host, 'jsd60.sys.projector\r\n')
		version = socket_command(host, 'jsd60.sys.ver\r\n')
		hostname = socket_command(host, 'jsd60.sys.host\r\n')

		local verTable = split(version, '\t')
		PCBversion = verTable[1]
		bootloaderVersion = verTable[2]
		picVersion = verTable[3]
		dspVersion = verTable[4]
		version = PCBversion .. ',' .. bootloaderVersion .. ',' .. picVersion .. ',' .. dspVersion

	elseif productName == 'JSD-100' then
		serialNumber = all_trim(socket_command(host, 'jsd100.sys.serial_number\r\n'))
		theaterName = socket_command(host, 'jsd100.sys.theater_name\r\n')
		theaterNumber = socket_command(host, 'jsd100.sys.theater_number\r\n')
		dcs = socket_command(host, 'jsd100.sys.dcs\r\n')
		automation = socket_command(host, 'jsd100.sys.automation\r\n')
		comments = socket_command(host, 'jsd100.sys.comments\r\n')
		projector = socket_command(host, 'jsd100.sys.projector\r\n')
		version = socket_command(host, 'jsd100.sys.ver\r\n')
		hostname = socket_command(host, 'jsd100.sys.host\r\n')

		local verTable = split(version, '\t')
		PCBversion = verTable[1]
		bootloaderVersion = verTable[2]
		picVersion = verTable[3]
		dspVersion = verTable[4]
		version = PCBversion .. ',' .. bootloaderVersion .. ',' .. picVersion .. ',' .. dspVersion
	elseif productName == 'OLD-JSD-100' then
		productName = 'JSD-100'
		serialNumber = 'na'
		theaterName = oldJsd100_search('Theater Name', get_status3)
		theaterNumber = oldJsd100_search('Theater Number', get_status3)
		dcs = oldJsd100_search('Digital Server', get_status3)
		automation = oldJsd100_search('Automation', get_status3)
		comments = oldJsd100_search('Comments', get_status3)
		projector = oldJsd100_search('Projector', get_status3)
		version = oldJsd100_search('Model Number', get_status3)
		hostname = oldJsd100_search('Host Name', get_status3)
	elseif productName == 'CM-8E' then
		serialNumber = all_trim(socket_command(host, 'cm8.sys.serial_number\r\n'))
		theaterName = socket_command(host, 'cm8.sys.theater_name\r\n')
		theaterNumber = socket_command(host, 'cm8.sys.theater_number\r\n')
		theaterName = socket_command(host, 'cm8.sys.theater_name\r\n')
		dcs = socket_command(host, 'cm8.sys.dcs\r\n')
		automation = socket_command(host, 'cm8.sys.automation\r\n')
		comments = socket_command(host, 'cm8.sys.comments\r\n')
		projector = socket_command(host, 'cm8.sys.projector\r\n')
		hostname = socket_command(host, 'cm8.sys.host\r\n')
		version = lineTwoTable[5]
	elseif productName == 'IRC-28C' then
		--
		comments = socket_command(host, 'irc.sys.comments\r\n')
		hostname = socket_command(host, 'irc.sys.host\r\n')
		theaterName = socket_command(host, 'irc.sys.theater_name\r\n')
		theaterNumber = socket_command(host, 'irc.sys.theater_number\r\n')
		dcs = socket_command(host, 'irc.sys.dcs_ip\r\n')
	end

	-- required variables are
	--- classification, vendor, productName, serialNumber, softwareVersion
	output.classification = classification
	output.vendor = 'QSC-USL'
	-- local productName
	output.productName = productName
	output.serialNumber = serialNumber
	output.version = version

	if PCBversion then
		output.PCBversion = PCBversion
	end
	if bootloaderVersion then
		output.bootloaderVersion = bootloaderVersion
	end
	if picVersion then
		output.picVersion = picVersion
	end
	if dspVersion then
		output.dspVersion = dspVersion
	end

	if hostname then
		output.hostname = hostname
	end
	if theaterName then
		output.theaterName = theaterName
	end
	if theaterNumber then
		output.theaterNumber = theaterNumber
	end
	if dcs then
		output.dcs = dcs
	end
	if automation then
		output.automation = automation
	end
	if comments then
		output.comments = comments
	end
	if projector then
		output.projector = projector
	end

	return output
end
