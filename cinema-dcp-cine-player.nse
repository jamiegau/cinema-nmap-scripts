local stdnse = require 'stdnse'
local http = require 'http'
local json = require 'json'

description = [[
Identifies D-Cine dcp-cine-player 4.2.20+ using its anonymous discovery API.
One read-only GET on TCP 8080 (or an explicitly configured web port), with no
login, credentials, redirects, operational queries or endpoint probing.
Reports running service version, licence-issued serial and installation UUID.
Public recipient certificate metadata is separate from the product serial.
The dci-player classification is the toolkit's DCP/TMS integration category;
it does not establish DCI certification, an active licence or certificate trust.
]]
author = 'James Gardiner'
license = 'Same as Nmap--See https://nmap.org/book/man-legal.html'
categories = {'cinema', 'safe', 'discovery'}

-- @usage
-- nmap -n -p8080 --script=cinema-dcp-cine-player TARGET
-- @args cinema-dcp-cine-player.port Web/API port override (default 8080).
-- @args cinema-dcp-cine-player.scheme http or https (default http; https on port 443).
-- @args cinema-dcp-cine-player.getcerts Include the public leaf PEM (default false; legacy getcerts accepted).
-- @output
-- | cinema-dcp-cine-player:
-- |   classification: dci-player
-- |   vendor: D-Cine
-- |   productName: dcp-cine-player
-- |   version: 4.2.20
-- |   serialNumber: 260014
-- |_  deviceId: urn:uuid:c81d38db-8d1b-4db6-afa2-2e7ee6f2118e

local PATH = '/api/player/v1/discovery'
local BODY_LIMIT = 131072

local function argument(name)
  return stdnse.get_script_args('cinema-dcp-cine-player.' .. name)
end

local function api_port()
  local value = argument('port')
  if value == nil then return 8080 end
  if type(value) ~= 'string' and type(value) ~= 'number' then return nil end
  local number = tonumber(value)
  if number and number % 1 == 0 and number >= 1 and number <= 65535 then return number end
end

portrule = function(host, port)
  local scheme = argument('scheme')
  return (scheme == nil or scheme == 'http' or scheme == 'https')
    and port.protocol == 'tcp' and port.state == 'open' and port.number == api_port()
end

local function scalar(value, limit)
  if type(value) ~= 'string' or #value > (limit or 256) or value:find('%c') then return nil end
  value = value:match('^%s*(.-)%s*$')
  if value == '' then return nil end
  return value
end

local function device_id(value)
  value = scalar(value, 45)
  if not value then return nil end
  local uuid = value:lower():gsub('^urn:uuid:', '')
  if uuid:match('^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$') then
    return value
  end
end

local function public_pem(value)
  if type(value) == 'string' and #value <= 65536
      and value:match('^-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----%s*$') then
    return value
  end
end

action = function(host, port)
  if not portrule(host, port) then return nil end
  local scheme = argument('scheme') or (port.number == 443 and 'https' or 'http')
  local ok, response = pcall(http.get, host, port, PATH, {
    scheme=scheme, timeout=3000, max_body_size=BODY_LIMIT, truncated_ok=false,
    redirect_ok=false, bypass_cache=true, no_cache=true,
    header={Accept='application/json', ['Accept-Encoding']='identity'},
  })
  if not ok or type(response) ~= 'table' or response.status ~= 200 or response.truncated
      or type(response.body) ~= 'string' or #response.body > BODY_LIMIT then return nil end
  local content_type = response.header and response.header['content-type']
  if type(content_type) ~= 'string'
      or content_type:lower():match('^%s*([^;%s]+)') ~= 'application/json' then return nil end
  local parsed, data = json.parse(response.body)
  if not parsed or type(data) ~= 'table' or data.schema ~= 'd-cine.player-api.discovery.v1'
      or data.product ~= 'dcp-cine-player' then return nil end

  local output = stdnse.output_table()
  output.classification, output.vendor, output.productName = 'dci-player', 'D-Cine', 'dcp-cine-player'
  output.version = scalar(data.version)
  output.mainSoftwareVersion = output.version
  output.serialNumber = scalar(data.serial_number, 50)
  output.deviceId = device_id(data.device_id)
  local cert = data.recipient_certificate
  if type(cert) == 'table' then
    local fingerprint = scalar(cert.fingerprint_sha256, 64)
    if fingerprint and #fingerprint == 64 and fingerprint:match('^%x+$') then
      output.recipientCertificateFingerprintSHA256 = fingerprint:lower()
    end
    output.recipientCertificateSerialNumber = scalar(cert.certificate_serial_number, 100)
    output.recipientCertificateNotBefore = scalar(cert.not_before_utc, 64)
    output.recipientCertificateNotAfter = scalar(cert.not_after_utc, 64)
    local getcerts = argument('getcerts')
    if getcerts == nil then getcerts = stdnse.get_script_args('getcerts') end
    if getcerts == true or getcerts == 'true' or getcerts == 'yes' or getcerts == 'y' then
      local pem = public_pem(cert.pem)
      if pem then output.CertInfo = {{title='Recipient leaf', cert=pem}} end
    end
  end
  return output
end
