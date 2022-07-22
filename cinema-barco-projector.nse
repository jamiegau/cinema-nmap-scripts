local nmap = require "nmap"
local stdnse = require "stdnse"
local snmp = require "snmp"

description = [[
Detects socket fingerprint of Barco DCI cinema projector and flags if found.
Will attempt to pull out software and firmware version of system

Sockets required for scan, 21,22,80,1173,43680,43728
Port 43680 - S1
Port 43728 - S2

NOTE: not tested against Series4 projectors, very different API/socket implementation.

Tool uses SNMP, OID for query data.
]]

--------------------------------------------------------------------
---
-- @usage
-- nmap -sS -p21,22,80,1173,43680,43728 --script=cinema-barco-projector --script-args 'getcerts=true' <target>
-- @output
-- PORT      STATE SERVICE
-- 21/tcp    open  ftp
-- 22/tcp    open  ssh
-- 80/tcp    open  http
-- | cinema-barco-projector:
-- |   classification: dci-projector
-- |   vendor: Barco
-- |   productName: DP2K-20C
-- |   serialNumber: 1190136617
-- |   version: 4.5.454
-- |   tiPackageVersion: 4.5.454
-- |   tiSerialNumber: 01d96e261a000085
-- |   enigmaVersion: P1.8(24)
-- |   enigmaSerialNumber: 860e1b4a0c06359d
-- |   lampSerialNumber: E914Wq158
-- |   lampArticleNumber: R9855937 OSRAM(R) XBO 4000W/DHP OFR
-- |   location: ChinetownC1
-- |   projectorCert: -----BEGIN CERTIFICATE-----
-- | MIIEzTCCA7WgAwIBAgIDAYVwMA0GCSqGSIb3DQEBCwUAMIGZMSkwJwYDVQQLEyBD
-- | QS02LkRMUC1DaW5lbWEuVGV4YXNJbnN0cnVtZW50czEkMCIGA1UEChMbRExQLUNp
-- | bmVtYS5UZXhhc0luc3RydW1lbnRzMR8wHQYDVQQDExYuVGV4YXNJbnN0cnVtZW50
-- | cy5DQS42MSUwIwYDVQQuExxyNjNkNFdGdmhkc1dLMjBweTRaamV0a0lBZEk9MB4X
-- | DTE4MDIyNDE1MDM0NFoXDTQxMDIyNjAwMDAwMFowgaQxJDAiBgNVBAsTG0RMUC1D
-- | aW5lbWEuVGV4YXNJbnN0cnVtZW50czEkMCIGA1UEChMbRExQLUNpbmVtYS5UZXhh
-- | c0luc3RydW1lbnRzMS8wLQYDVQQDEyZQUi5ETFAtQ2luZW1hLlNlcmllczIuMDFE
-- | OTZFMjYxQTAwMDA4NTElMCMGA1UELhMcOW40QW0xa1pzYnZxV2VDOHlWRXp3Tk0z
-- | b1pBPTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMwcjQx7YFeNR9Hb
-- | +MISPpPCJnG16CpiBAe4Sa+zBA/OXqyR50SSdVZkG736ZR7l1zXSLc+17i+wPW1k
-- | 98pj6bDzGiu8Y91oJAWfMCUXZXloWCRMoyWT/5J7VFBVxZ5etxKIA+KTA/hqgW8e
-- | THAPG6DqeSUIGgxMRP3wl2A24U/QZjsft3D8v6QB36ngErJwkg+IGmUgglE0z+D4
-- | V6HKHTlz0TqitjXBM5dUlY7F4DKt1PIn+XMzJ4/EI3mFMr7N8tUS0NLLx6syvGqN
-- | flQh8eJelheqy3aFPRvDDpQ5JHtc7P0k90uswrWMQDdh2Zsr3HCIS2PLgL8rdGk+
-- | 973cBNcCAwEAAaOCAQ8wggELMIHOBgNVHSMEgcYwgcOAFK+t3eFhb4XbFittKcuG
-- | Y3rZCAHSoYGnpIGkMIGhMSQwIgYDVQQKExtETFAtQ2luZW1hLlRleGFzSW5zdHJ1
-- | bWVudHMxLDAqBgNVBAsTI1Jvb3QtQ0EuRExQLUNpbmVtYS5UZXhhc0luc3RydW1l
-- | bnRzMSQwIgYDVQQDExsuVGV4YXNJbnN0cnVtZW50cy5Sb290LUNBLjAxJTAjBgNV
-- | BC4THGZmQW1JdVdSenVuTVgrKzJuQmNnTDFpeXdHST2CAQcwHQYDVR0OBBYEFPZ+
-- | AJtZGbG76lngvMlRM8DTN6GQMAwGA1UdEwEB/wQCMAAwCwYDVR0PBAQDAgSwMA0G
-- | CSqGSIb3DQEBCwUAA4IBAQCogIHREIdVpdQq5ULV+YBDc4XqEezm59pfol96NfjH
-- | MmPai9Hwg4x1QpneumkWdrJMxwRM8ok6FfIGcjrHyi+ZG6adeB3wZClgvDPso3ls
-- | ny+/r0xQ+ZpBTJe2MwmdkwCCsrmWONpAp//sXdcxZylYQGxtVNDvj6Y7PJ/HkLpH
-- | Pzk+QMm++AAOkMzl6qXSLkQWPPnKGPyEeLKSs7SBSY0P9EDSJZRefbe8MrL6ncTC
-- | Xg5RXDTlYWqGK19rulnbSuwbMKWk+0gEOFypOt122X1kmAMVrxagmbx6X1DJOBVH
-- | mD2KHaPFUoj9FTzNcJxdpBtIP+V+Y70kK+7D8nwi/RLe
-- | -----END CERTIFICATE----7
-- | -----END CERTIFICATE---
-- |   linkDecryptorCert: -----BEGIN CERTIFICATE-----
-- | MIIEzTCCA7WgAwIBAgIDAIt/MA0GCSqGSIb3DQEBCwUAMIGZMSkwJwYDVQQLEyBD
-- | QS02LkRMUC1DaW5lbWEuVGV4YXNJbnN0cnVtZW50czEkMCIGA1UEChMbRExQLUNp
-- | bmVtYS5UZXhhc0luc3RydW1lbnRzMR8wHQYDVQQDExYuVGV4YXNJbnN0cnVtZW50
-- | cy5DQS42MSUwIwYDVQQuExxyNjNkNFdGdmhkc1dLMjBweTRaamV0a0lBZEk9MB4X
-- | DTEzMDkwNjAxMDIwOVoXDTQxMDIyNjAwMDAwMFowgaQxJDAiBgNVBAsTG0RMUC1D
-- | aW5lbWEuVGV4YXNJbnN0cnVtZW50czEkMCIGA1UEChMbRExQLUNpbmVtYS5UZXhh
-- | c0luc3RydW1lbnRzMS8wLQYDVQQDEyZMRC5ETFAtQ2luZW1hLlNlcmllczIuODYw
-- | RTFCNEEwQzA2MzU5RDElMCMGA1UELhMcT1lFUEJXL3NYQkZQMVpLYlAyWHNLdFBx
-- | TkJvPTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANaAstK2m9YwsFLk
-- | Ii3uqX6eN8eULnVFuzAxmzkeO+2cN6WbSAzmM4Wu0mCzdJssHxnxUCbYhkJ71efb
-- | 8a4Hvj6SsmHSKet+v3xVuxYYqeMkvVJa1SWyAYxL27ZMcO1Qr6BMqCigfDLJYXFo
-- | 6AxQRI9E2FfHl8I0ejW1X0Rgy5GIbio4wGOvekfciK/WRf7M+4zQvriBCZhZKpAm
-- | 9nIt8wAdWX1OORuyGFfZTFfN/UeYoGFczLuMU/BbsH3JeSWKblPIyFQo2HChBp9J
-- | efoZwwomRcTDd9ucUKnFwqAfpc0GgUPF1y9lG16OTRYQWCuLmXjeqfTT7ejI3d7K
-- | wY2CWNMCAwEAAaOCAQ8wggELMIHOBgNVHSMEgcYwgcOAFK+t3eFhb4XbFittKcuG
-- | Y3rZCAHSoYGnpIGkMIGhMSQwIgYDVQQKExtETFAtQ2luZW1hLlRleGFzSW5zdHJ1
-- | bWVudHMxLDAqBgNVBAsTI1Jvb3QtQ0EuRExQLUNpbmVtYS5UZXhhc0luc3RydW1l
-- | bnRzMSQwIgYDVQQDExsuVGV4YXNJbnN0cnVtZW50cy5Sb290LUNBLjAxJTAjBgNV
-- | BC4THGZmQW1JdVdSenVuTVgrKzJuQmNnTDFpeXdHST2CAQcwHQYDVR0OBBYEFDmB
-- | DwVv7FwRT9WSmz9l7CrT6jQaMAwGA1UdEwEB/wQCMAAwCwYDVR0PBAQDAgSwMA0G
-- | CSqGSIb3DQEBCwUAA4IBAQClp2XLcC9WS0BegmPkPewS8ADQBVFtXpc6RSTVWzlC
-- | 7I2njwVYg8m7lKGvSJN7vO3CABi5qhK5VB0dGy5YjxLDjdEcpRy5EFyq9jUXJFJ5
-- | Fxew5C9cskgGa6xyjiGnaeYALbMkapFLw7rcGp7f+P6myFIVb/iw4ApdovV35aqn
-- | u2edWrY22EUXN4fc99EoTNP+hBlSZiXIdt0MVEnQ44kYX/rLpfPJ/H4u7RGOTUJM
-- | fvi2Ce9mook9Sjah98DJ7Z4cPYr0ZnlqNWTDsSM9McuIqUhYUpGwHHk05FDs4RRq
-- | dEvTzLD3QBuc+uCD4/Mebc3Q8nt3gIvEgI85pvyq+Rm7
-- |_-----END CERTIFICATE---
-- 1173/tcp  open  d-cinema-rrp
-- 43680/tcp open  unknown
-- 43728/tcp open  unknown

author = "James Gardiner"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "safe", "intrusive" }

-- if port 80 and port  21, 22, 1173, 43680, 43728 are the right state, we try and query the target
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
	local dci = { number = 1173, protocol = "tcp" }
	local dci_open = nmap.get_port_state(host, dci)
	local barcoS1 = { number = 43680, protocol = "tcp" }
	local barcoS1_open = nmap.get_port_state(host, barcoS1)
	local barcoS2 = { number = 43680, protocol = "tcp" }
	local barcoS2_open = nmap.get_port_state(host, barcoS2)


	local res = false
	if ftp_open.state == 'open' and
		ssh_open.state == 'open' and
		dci_open.state == 'open' and
		(barcoS1_open.state == 'open' or barcoS2_open.state == 'open') then
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

local function hexencode(str)
	return (str:gsub(".", function(char) return string.format("%02x", char:byte()) end))
end

function get_snmp_IOD_value(host, port, iod)
	local res = ''

	local snmpHelper = snmp.Helper:new(host, port)
	snmpHelper:connect()

	local status, retvar = snmpHelper:get({ reqId = 28428 }, iod)
	if status == false then
		res = 'na'
	else
		res = all_trim(retvar[1][1])
	end

	return res
end

-- Now lets try and query the player for some useful information
action = function(host, port)
	local getcerts = stdnse.get_script_args('getcerts')
	if getcerts == 'y' or getcerts == 'yes' or getcerts == 'true' then
		getcerts = true
	else
		getcerts = false
	end

	local snmp_port = { number = 161, protocol = "udp" }
	local output = stdnse.output_table()
	-- required variables are
	--- classification, vendor, productName, serialNumber, version
	output.classification = 'dci-projector'
	output.vendor = 'Barco'
	--
	-- productName / .1.3.6.1.2.1.1.1.0
	output.productName = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.2.1.1.1.0')
	--
	-- serialNumber .1.3.6.1.4.1.12612.220.11.2.2.1.0
	output.serialNumber = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.12612.220.11.2.2.1.0')
	--
	-- tiPackageVersion - .1.3.6.1.4.1.12612.220.11.1.2.12.0
	local tiPackageVersion = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.12612.220.11.1.2.12.0')
	-- tiSerialNumber - .1.3.6.1.4.1.12612.220.11.1.2.16.0
	local tiSerialNumber = hexencode(get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.12612.220.11.1.2.16.0'))
	output.version = tiPackageVersion
	output.tiPackageVersion = tiPackageVersion
	output.tiSerialNumber = tiSerialNumber

	-- enigmaVersion .1.3.6.1.4.1.12612.220.11.1.2.18.0
	output.enigmaVersion = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.12612.220.11.1.2.18.0')

	-- enigmaSerialNumber .1.3.6.1.4.1.12612.220.11.1.2.19.0
	output.enigmaSerialNumber = hexencode(get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.12612.220.11.1.2.19.0'))

	-- lampSerialNumber .1.3.6.1.4.1.12612.220.11.2.2.4.1.0
	output.lampSerialNumber = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.12612.220.11.2.2.4.1.0')

	-- lampArticleNumber .1.3.6.1.4.1.12612.220.11.2.2.4.2.0
	output.lampArticleNumber = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.12612.220.11.2.2.4.2.0')

	-- location .1.3.6.1.2.1.1.6.0
	output.location = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.2.1.1.6.0')

	if getcerts then
		-- Proj Cert .1.3.6.1.4.1.12612.220.11.1.2.17.1.3.1
		local projectorCert = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.12612.220.11.1.2.17.1.3.1')
		projectorCert = projectorCert:gsub("\x0D", "")
		output.projectorCert = projectorCert


		-- Link Decryptor Cert .1.3.6.1.4.1.12612.220.11.1.2.17.1.3.2
		local linkDecryptorCert = get_snmp_IOD_value(host, snmp_port, '.1.3.6.1.4.1.12612.220.11.1.2.17.1.3.2')
		linkDecryptorCert = linkDecryptorCert:gsub("\x0D", "")
		output.linkDecryptorCert = linkDecryptorCert
	end

	return output
end
