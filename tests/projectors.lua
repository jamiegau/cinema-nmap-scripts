-- Offline projector contracts. All HTTP and SNMP operations are mocked.
local root = assert(arg[1])
local state
local host = { ip = '10.70.7.12' }
local port = { number = 80, protocol = 'tcp', state = 'open' }
local function reset()
    state = { ports = {}, args = {}, requests = {}, closes = 0, snmp = {},
        values = { modelname = 'SP2K-9S', serialnumber = '2590502364',
            firmwareversion = '1.9.12', familyname = 'SP2KS' } }
end
package.preload.nmap = function() return {
    get_port_state = function(_, p) return state.ports[p.number] end
} end
package.preload.stdnse = function() return {
    output_table = function() return {} end,
    get_script_args = function(k) return state.args[k] end
} end
package.preload.url = function() return { parse = function() return state.redirect end } end
package.preload.json = function() return { parse = function(body)
    if body == 'bad-json' then return false, 'invalid JSON' end
    return true, { result = state.values[body] }
end } end
package.preload.http = function() return { get = function(_, p, path, options)
    assert(path:match('^/rest/system/[%a]+$'), 'identity GETs only')
    assert(options.redirect_ok == false and options.timeout == 3000 and options.max_body_size == 4096)
    table.insert(state.requests, { port = p.number, path = path, auth = options.auth })
    if p.number == 80 and state.redirect then
        return { status = 302, header = { location = 'mock-redirect' } }
    end
    return { status = state.status or 200, body = state.bad_json and 'bad-json' or path:match('([^/]+)$'),
        truncated = state.truncated }
end } end
package.preload.snmp = function() return { Helper = { new = function()
    return {
        socket = { close = function() state.closes = state.closes + 1 end },
        connect = function() return not state.connect_failure end,
        get = function(_, _, oid)
            if state.snmp_failure then return false, 'timeout' end
            return true, {{state.snmp[oid] or false}}
        end
    }
end } } end
local function load_script(name)
    local env = setmetatable({}, { __index = _G })
    assert(loadfile(root .. '/' .. name, 't', env))()
    return env
end
local barco = load_script('cinema-barco-projector.nse')
local nec = load_script('cinema-nec-projector.nse')
local count = 0
local function test(name, fn)
    reset(); fn(); count = count + 1; print('PASS: ' .. name)
end
test('Barco S4 does not require legacy ports or a full port scan', function()
    assert(barco.portrule(host, port))
    local out = barco.action(host, port)
    assert(out.vendor == 'Barco' and out.classification == 'dci-projector')
    assert(out.productName == 'SP2K-9S' and out.serialNumber == '2590502364' and out.version == '1.9.12')
    assert(#state.requests == 4 and state.closes == 0)
    for _, req in ipairs(state.requests) do assert(req.auth == nil) end
end)
test('Barco S4 upgrades only same-host identity request to HTTPS', function()
    state.redirect = { scheme = 'https', host = host.ip, path = '/rest/system/modelname' }
    assert(barco.action(host, port).productName == 'SP2K-9S')
    assert(#state.requests == 5)
    for i = 2, 5 do assert(state.requests[i].port == 443) end
end)
test('redirect cannot move credentials to another host, path or port', function()
    for _, redirect in ipairs({
        {scheme='https',host='other.example',path='/rest/system/modelname'},
        {scheme='https',host=host.ip,path='/rest/system/reboot'},
        {scheme='https',host=host.ip,path='/rest/system/modelname',port=8443},
        {scheme='http',host=host.ip,path='/rest/system/modelname'}
    }) do
        state.requests = {}; state.redirect = redirect
        assert(barco.action(host, port) == nil and #state.requests == 1)
    end
end)
test('HTTPS-only scan works and dual-port scan does not duplicate output', function()
    local https = {number=443,protocol='tcp',state='open'}
    assert(barco.portrule(host, https))
    assert(barco.action(host, https).productName == 'SP2K-9S')
    state.ports[80] = {state='open'}
    assert(not barco.portrule(host, https))
end)
test('SP4K models are supported', function()
    state.values.modelname = 'SP4K-25C'
    assert(barco.action(host, port).productName == 'SP4K-25C')
end)
test('other models and invalid result types are not identified as Barco', function()
    for _, model in ipairs({'NEC NC900C', 'SP2K', 'unknown', false, 123, {}}) do
        state.values.modelname = model
        assert(barco.action(host, port) == nil)
    end
end)
test('HTTP errors, malformed JSON and oversized replies are ignored', function()
    for _, status in ipairs({401,404,503}) do
        state.status = status; assert(barco.action(host, port) == nil)
    end
    state.status = 200; state.bad_json = true; assert(barco.action(host, port) == nil)
    state.bad_json = false; state.truncated = true; assert(barco.action(host, port) == nil)
end)
test('missing optional fields are omitted rather than fabricated', function()
    state.values.serialnumber = false; state.values.firmwareversion = ''
    local out = barco.action(host, port)
    assert(out.productName == 'SP2K-9S' and out.serialNumber == nil and out.version == nil)
end)
test('only explicitly supplied namespaced credentials are used', function()
    state.args['cinema-barco-projector.username'] = 'operator'
    state.args['cinema-barco-projector.password'] = 'test-only'
    barco.action(host, port)
    assert(state.requests[1].auth.username == 'operator')
end)
test('legacy Barco S2 fingerprint includes actual port 43728', function()
    state.status = 404
    for _, p in ipairs({21,22,1173,43728}) do state.ports[p] = {state='open'} end
    state.snmp['.1.3.6.1.2.1.1.1.0'] = 'DP2K-20C'
    state.snmp['.1.3.6.1.4.1.12612.220.11.2.2.1.0'] = '1190136617'
    local out = barco.action(host, port)
    assert(out.productName == 'DP2K-20C' and out.serialNumber == '1190136617')
    assert(state.closes > 0)
end)
test('NEC missing ports do not crash and matching ports alone prove nothing', function()
    assert(not nec.portrule(host, port))
    state.ports[43728] = {state='open'}
    assert(nec.portrule(host, port))
    assert(nec.action(host, port) == nil and state.closes == 1)
end)
test('NEC requires model from its private MIB', function()
    state.snmp['.1.3.6.1.4.1.119.2.3.123.1.13.0'] = 'NC900C'
    local out = nec.action(host, port)
    assert(out.vendor == 'NEC' and out.productName == 'NC900C')
end)
test('SNMP timeout and connect failure cannot label an unknown unit NEC', function()
    state.snmp_failure = true; assert(nec.action(host, port) == nil)
    state.connect_failure = true; assert(nec.action(host, port) == nil)
    assert(state.closes == 2)
end)
print(count .. ' projector offline tests passed')
