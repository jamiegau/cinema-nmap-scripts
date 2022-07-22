local nmap = require "nmap"
local stdnse = require "stdnse"
local nsedebug = require "nsedebug"


description = [[
Detects socket fingerprint of INTEG Jnior automation-io device and flags if found.
Will attempt to pull out software and firmware version of system
]]

--------------------------------------------------------------------
---
-- @usage
-- nmap -sS -p 21,22,80,9200 --script=cinema-integ-jnior --script-args 'username=jnior,password=jnior' <target>
-- @output
-- PORT     STATE    SERVICE
-- 21/tcp   open     ftp
-- 22/tcp   filtered ssh
-- 80/tcp   open     http
-- | cinema-integ-jnior:
-- |   classification: automation-io
-- |   vendor: Integ
-- |   productName: jr410
-- |   serialNumber: 616090227
-- |   version: v1.5.0
-- |_  hostname: jr616090227
-- 9200/tcp open     wap-wsp

author = "James Gardiner"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "safe", "intrusive" }

-- if port 80 and port  21, 22, 9200 are open, we try and query the system Doby Player
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
	local jnior = { number = 9200, protocol = "tcp" }
	local jnior_open = nmap.get_port_state(host, jnior)

	local res = false
	if ftp_open.state == 'open' and
		ssh_open.state ~= 'open' and
		jnior_open.state == 'open' then
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

----------------------------------------------------------------------------------------------------------
local crctab = {
	0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
	0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
	0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
	0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
	0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
	0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
	0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
	0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
	0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
	0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
	0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
	0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
	0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
	0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
	0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
	0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
	0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
	0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
	0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
	0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
	0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
	0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
	0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
	0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
	0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
	0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
	0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
	0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
	0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
	0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
	0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
	0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
}

-------------------------------------------------------------------------------------------------------------
local XMODEMCRC16Lookup = {
	0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
	0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
	0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
	0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
	0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
	0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
	0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
	0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
	0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
	0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
	0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
	0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
	0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
	0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
	0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
	0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
	0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
	0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
	0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
	0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
	0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
	0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
	0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
	0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
	0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
	0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
	0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
	0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
	0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
	0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
	0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
	0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
}

local function crc16(bytes)
	local crc = 0
	for i = 1, #bytes do
		local b = string.byte(bytes, i, i)
		-- crc = ((crc << 8) & 0xffff) ~ XMODEMCRC16Lookup[(((crc >> 8) ~ b) & 0xff) + 1]
		crc = ((crc << 8) & 0xffff) ~ crctab[(((crc >> 8) ~ b) & 0xff) + 1]
	end
	print('crc16: ' .. crc .. ' ' .. tonumber(crc))
	return tonumber(crc)
end

--------------------------------------------------------------------------------------------------
local crypt_crc = {
	0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
	0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
	0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
	0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
	0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
	0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
	0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
	0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
	0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
	0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
	0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
	0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
	0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
	0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
	0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
	0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
	0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
	0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
	0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
	0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
	0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
	0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
	0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
	0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
	0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
	0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
	0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
	0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
	0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
	0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
	0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
	0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0
}

local crc = function(data)
	local sum = 0
	for i = 1, #data do
		-- sum = (crypt_crc[(sum >> 8) + 1] ~ data:byte(i) ~ (sum << 8)) & 0xFFFF
		sum = (crctab[(sum >> 8) + 1] ~ data:byte(i) ~ (sum << 8)) & 0xFFFF
	end
	return sum
end
------------------------------------------------------------------------------------------------------


local function crc16modbus(msg)
	local res, tmp
	res = 0xFFFF
	for i = 1, #msg do
		tmp = msg:byte(i)
		tmp = bit.bxor(tmp, res)
		tmp = bit.band(tmp, 0xFF)
		res = bit.rshift(res, 8)
		res = bit.bxor(res, crctab[tmp + 1])
	end
	return res
end

-----------------------------------------------------------------------------------------------------------
local function int_to_bytes(num, endian, signed)
	if num < 0 and not signed then num = -num print "warning, dropping sign from number converting to unsigned" end
	local res = {}
	local n = math.ceil(select(2, math.frexp(num)) / 8) -- number of bytes to be used.
	if signed and num < 0 then
		num = num + 2 ^ n
	end
	for k = n, 1, -1 do -- 256 = 2^8 bits per char.
		local mul = 2 ^ (8 * (k - 1))
		res[k] = math.floor(num / mul)
		num = num - res[k] * mul
	end
	assert(num == 0)
	if endian == "big" then
		local t = {}
		for k = 1, n do
			t[k] = res[n - k + 1]
		end
		res = t
	end
	return string.char(unpack(res))
end

function Int16ToBytes(num, endian)
	if num < 0 then
		num = num & 0xFFFF
	end

	highByte = (num & 0xFF00) >> 8
	lowByte  = num & 0xFF

	if endian == "little" then
		lowByte, highByte = highByte, lowByte
	end

	return string.char(highByte, lowByte)
end

-------------------------------------------------------------------------------------------------------------

local function all_trim(s)
	if s == nil then
		return ''
	end
	return s:match("^%s*(.-)%s*$")
end

--

function TableConcat(t1, t2)
	for i = 1, #t2 do
		t1[#t1 + 1] = t2[i]
	end
	return t1
end

local function jnior_request_login(host, username, password)
	stdnse.debug("jnior_request_login " .. host.ip, username, password)
	local result, socket, try, catch

	-- local login_string = "\x01\x00\x0d\x60\xb7\x7e\x05" .. username .. "\x05" .. password
	local login_string = "\x7e\x05" .. username .. "\x05" .. password
	stdnse.debug('login_string = ' .. PrintHex(login_string))
	local jnior_len = string.len(login_string)
	-- stdnse.debug('jnior_len: ' .. jnior_len)
	-- stdnse.debug('jnior_len: ' .. string.format("%02x", jnior_len) .. ', len: ' .. string.len(string.format("%x", jnior_len)))
	local pad_len = ''
	if string.len(string.format("%x", jnior_len)) < 3 then
		pad_len = '\x00'
	end

	-- local jnior_crc = crc(login_string)
	-- local crc_as_bytes = Int16ToBytes(jnior_crc)
	-- override the attempt at making CRC
	crc_as_bytes = '\xff\xff'
	-- stdnse.debug('crc: ' .. string.format("%x", jnior_crc))
	-- stdnse.debug('crc: ' .. PrintHex(crc_as_bytes))



	local jnior_str = '\x01' .. pad_len .. string.char(jnior_len) .. crc_as_bytes .. login_string

	stdnse.debug("should be     : " .. PrintHex("\x01\x00\x0d\x60\xb7\x7e\x05" .. username .. "\x05" .. password))
	stdnse.debug("binary message: " .. PrintHex(jnior_str))

	socket = nmap.new_socket()
	socket:set_timeout(500)
	catch = function()
		-- print('Socket exception')
		socket:close()
		return false, 'Socket exception, melformed message.'
	end
	try = nmap.new_try(catch)
	try(socket:connect(host, 9200))

	try(socket:send(jnior_str))

	local status, result = socket:receive_bytes(1024)
	stdnse.debug("result - status: " .. nsedebug.tostr(status))
	stdnse.debug("result - data: " .. PrintHex(result))
	if status == false then
		return false, 'Socket exception: ' .. result
	end

	local success_login = "\x01\x00\x02\xf0\x20\x7d\x80"
	local login_res = string.sub(result, 1, 7)
	stdnse.debug(PrintHex(success_login) .. ' == ' .. PrintHex(login_res))

	if success_login == login_res then
		stdnse.debug('login worked')
	else
		return false, 'Login failed'
	end

	local product = string.sub(result, 15, 19)
	local version = string.sub(result, 21, 32)
	version = version:gsub("\x00", "")
	version = all_trim(version)

	-------------------------------------------------------------------------------------------------
	-- version variable fetch
	-- "\x01\x00\x13\xff\xff\x0b\x00\x01\x00\xde\x0d\x24\x53\x65\x72\x69\x61\x6c\x4e\x75\x6d\x62\x65\x72"
	local version_cmd = '\x0b\x00\x01\x00\xde\x0d\x24\x53\x65\x72\x69\x61\x6c\x4e\x75\x6d\x62\x65\x72'
	local version_len = string.len(version_cmd)

	local v_pad_len = ''
	if string.len(string.format("%x", version_len)) < 3 then
		v_pad_len = '\x00'
	end

	local v_read = "\x01" .. v_pad_len .. string.char(version_len) .. crc_as_bytes .. version_cmd
	stdnse.debug("VerInfoReq: " .. PrintHex(v_read))
	try(socket:send(v_read))
	local status2, result2 = socket:receive_bytes(1024)
	stdnse.debug("result2 - status: " .. nsedebug.tostr(status2))
	stdnse.debug("result2 - data: " .. PrintHex(result2))
	if status2 == false then
		return false, 'Socket exception: ' .. result
	end
	if status2 == "nil" then
		return false, 'Socket exception: ' .. result
	end
	local serial = string.sub(result2, 12, -1) -- to end of string..
	-------------------------------------------------------------------------------------------------
	-- Hostname variable fetch
	--
	-- cmd len crc requestRegVar len DevicePath
	-- "\x01 \x00\x13 \xbe\x61 \x0b\x00\x01\x00\xde \x0d \x24\x53\x65\x72\x69\x61\x6c\x4e\x75\x6d\x62\x65\x72"
	local hostname_cmd = '\x0b\x00\x01\x00\xde\x11IpConfig/Hostname'
	-- local hostname_cmd = '\x0b\x00\x01\x00\xde\x0bDevice/Desc'

	local hostname_len = string.len(hostname_cmd)

	local hn_pad_len = ''
	if string.len(string.format("%x", hostname_len)) < 3 then
		hn_pad_len = '\x00'
	end

	local hn_read = "\x01" .. hn_pad_len .. string.char(hostname_len) .. crc_as_bytes .. hostname_cmd
	stdnse.debug("HnInfoReq: " .. PrintHex(hn_read))
	try(socket:send(hn_read))
	local status3, result3 = socket:receive_bytes(1024)
	stdnse.debug("result3 - status: " .. nsedebug.tostr(status3))
	stdnse.debug("resul32 - data: " .. PrintHex(result3))
	if status3 == false then
		return false, 'Socket exception: ' .. result3
	end
	if status3 == "nil" then
		return false, 'Socket exception: ' .. result3
	end
	local hostname = string.sub(result3, 12, -1)
	-----------

	return true, 'OK', product, version, serial, hostname
end

-- Now lets try and query the player for some useful information
action = function(host, port)
	-- get command line username and password
	-- arguments, username, password, getcerts
	local username = stdnse.get_script_args('username')
	if username == nil then
		username = 'jnior'
	end
	local password = stdnse.get_script_args('password')
	if password == nil then
		password = 'jnior'
	end
	--
	--
	local output = stdnse.output_table()
	-- required variables are
	--- classification, vendor, productName, serialNumber, softwareVersion
	output.classification = 'automation-io'
	output.vendor = 'Integ'

	local v_res, desc, product, version, serial, hostname = jnior_request_login(host, username, password)
	if desc ~= "OK" then
		output.error = desc
		return output
	end

	output.productName = product
	output.serialNumber = serial
	output.version = version
	output.hostname = hostname

	return output
end
