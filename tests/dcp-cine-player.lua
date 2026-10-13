-- Passive discovery contracts. All network operations are mocked.
local root = assert(arg[1])
local args, response, data, requests
local host = {ip='127.0.0.1'}
local port = {number=8080, protocol='tcp', state='open'}
package.preload.stdnse = function() return {
  get_script_args=function(key) return args[key] end,
  output_table=function() return {} end,
} end
package.preload.http = function() return {get=function(h, p, path, options)
  assert(h == host and path == '/api/player/v1/discovery')
  assert(options.timeout == 3000 and options.max_body_size == 131072 and options.truncated_ok == false)
  assert(options.redirect_ok == false and options.no_cache and options.bypass_cache)
  assert(options.auth == nil and options.cookies == nil)
  assert(options.header.Authorization == nil and options.header.Accept == 'application/json')
  requests[#requests + 1] = {port=p.number, scheme=options.scheme}
  return response
end} end
package.preload.json = function() return {parse=function(body)
  return body ~= 'malformed', data
end} end
local env = setmetatable({}, {__index=_G})
assert(loadfile(root .. '/cinema-dcp-cine-player.nse', 't', env))()
local function reset()
  args, requests = {}, {}
  response = {status=200, header={['content-type']='application/json; charset=utf-8'}, body='json'}
  data = {schema='d-cine.player-api.discovery.v1', product='dcp-cine-player', version='4.2.20',
          serial_number='PRODUCT-123', device_id='urn:uuid:c81d38db-8d1b-4db6-afa2-2e7ee6f2118e',
          recipient_certificate={certificate_serial_number='CERT-456', fingerprint_sha256=string.rep('a',64),
                                pem='-----BEGIN CERTIFICATE-----\nVEVTVA==\n-----END CERTIFICATE-----\n'}}
end
local count = 0
local function test(name, fn)
  reset(); fn(); count=count+1; print('PASS: ' .. name)
end
test('DCP-Cine selects only open TCP 8080 by default', function()
  assert(env.portrule(host, port))
  for _, p in ipairs({{number=80, protocol='tcp', state='open'}, {number=8080, protocol='udp', state='open'},
                     {number=8080, protocol='tcp', state='closed'}}) do
    assert(not env.portrule(host, p))
  end
end)
test('DCP-Cine permits explicit web ports and HTTPS without probing other endpoints', function()
  args['cinema-dcp-cine-player.port']='8443'
  args['cinema-dcp-cine-player.scheme']='https'
  assert(not env.portrule(host, port))
  local p = {number=8443, protocol='tcp', state='open'}
  assert(env.action(host,p))
  assert(#requests == 1 and requests[1].scheme == 'https')
end)
test('DCP-Cine validates port and transport overrides', function()
  for _, value in ipairs({'0', '65536', '-1', '1.2', 'bad', true, {}}) do
    args['cinema-dcp-cine-player.port']=value
    assert(not env.portrule(host, port))
  end
  args['cinema-dcp-cine-player.port']=nil
  args['cinema-dcp-cine-player.scheme']='ftp'
  assert(env.action(host,port) == nil and #requests == 0)
end)
test('DCP-Cine defaults to HTTPS on explicitly selected port 443', function()
  args['cinema-dcp-cine-player.port']='443'
  assert(env.action(host,{number=443, protocol='tcp', state='open'}))
  assert(requests[1].scheme == 'https' and #requests == 1)
end)
test('DCP-Cine reports product identity and keeps certificate serial separate', function()
  local out = env.action(host,port)
  assert(out.vendor == 'D-Cine' and out.productName == 'dcp-cine-player' and out.classification == 'dci-player')
  assert(out.version == '4.2.20' and out.mainSoftwareVersion == '4.2.20')
  assert(out.serialNumber == 'PRODUCT-123' and out.recipientCertificateSerialNumber == 'CERT-456')
  assert(out.deviceId == data.device_id and out.CertInfo == nil and #requests == 1)
end)
test('DCP-Cine unknown registration never substitutes certificate serial', function()
  data.serial_number=nil
  assert(env.action(host,port).serialNumber == nil)
  data.device_id, data.recipient_certificate = nil, nil
  local out = env.action(host,port)
  assert(out and out.deviceId == nil and out.recipientCertificateSerialNumber == nil)
end)
test('DCP-Cine ignores invalid optional values and unadvertised private metadata', function()
  data.version, data.serial_number, data.device_id = {}, 'bad\nserial', '/etc/private'
  data.private_key='PRIVATE'; data.licence_token='SECRET'
  data.recipient_certificate.fingerprint_sha256='bad'
  local out = env.action(host,port)
  assert(out and out.version == nil and out.serialNumber == nil and out.deviceId == nil)
  assert(out.recipientCertificateFingerprintSHA256 == nil and out.private_key == nil and out.licence_token == nil)
end)
test('DCP-Cine certificate output is opt-in and public leaf only', function()
  args.getcerts='true'
  assert(env.action(host,port).CertInfo[1].cert == data.recipient_certificate.pem)
  data.recipient_certificate.pem=data.recipient_certificate.pem .. '-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----'
  assert(env.action(host,port).CertInfo == nil)
  data.recipient_certificate.pem=string.rep('x',65537)
  assert(env.action(host,port).CertInfo == nil)
end)
test('DCP-Cine requires exact schema and product rather than a generic web response', function()
  data.product='other-player'; assert(env.action(host,port) == nil)
  data.product='dcp-cine-player'; data.schema='wrong'; assert(env.action(host,port) == nil)
  data={}; assert(env.action(host,port) == nil)
end)
test('DCP-Cine rejects redirects, failures, wrong content type, malformed and oversized replies', function()
  for _, status in ipairs({301,302,401,403,404,500}) do
    response.status=status; assert(env.action(host,port) == nil)
  end
  response.status=200; response.header['content-type']='text/html'; assert(env.action(host,port) == nil)
  response.header['content-type']='application/json'; response.body='malformed'; assert(env.action(host,port) == nil)
  response.body=string.rep('x',131073); assert(env.action(host,port) == nil)
  response.body='json'; response.truncated=true; assert(env.action(host,port) == nil)
end)
print('DCP-Cine offline tests passed: ' .. count)
