-- Offline candidate-selection checks; real XML/HTTP is tested by cp950-loopback.py.
local root = assert(arg[1])
local ports, override
package.preload.nmap = function() return {
    get_port_state=function(_, port) return ports[port.number] end
} end
package.preload.stdnse = function() return {
    get_script_args=function() return override end
} end
package.preload.http = function() return {} end
package.preload.slaxml = function() return {} end
local env=setmetatable({}, {__index=_G})
assert(loadfile(root .. '/cinema-dolby-cp950.nse','t',env))()
local function port(n, state, protocol)
    return {number=n, state=state or 'open', protocol=protocol or 'tcp'}
end
local count=0
local function test(name, fn)
    ports={}; override=nil; fn(); count=count+1; print('PASS: '..name)
end
test('CP950 selects documented SOAP port', function()
    assert(env.portrule({},port(9090)))
end)
test('older Catcher scans use control port as candidate without probing it', function()
    assert(env.portrule({},port(61408)))
end)
test('dual-port scans run SOAP identity once', function()
    ports[9090]=port(9090)
    assert(env.portrule({},port(9090)) and not env.portrule({},port(61408)))
end)
test('explicitly closed or filtered SOAP port is not retried', function()
    for _, state in ipairs({'closed','filtered'}) do
        ports[9090]=port(9090,state)
        assert(not env.portrule({},port(61408)))
    end
end)
test('irrelevant ports, UDP and closed ports are skipped', function()
    for _, p in ipairs({port(80),port(9090,'closed'),port(9090,'open','udp')}) do
        assert(not env.portrule({},p))
    end
end)
test('namespaced SOAP port override is validated', function()
    override='19090'; assert(env.portrule({},port(19090)))
    assert(not env.portrule({},port(9090)))
    for _, value in ipairs({'bad','0','65536','1.5'}) do
        override=value; assert(not env.portrule({},port(61408)))
    end
end)
print(('%d CP950 offline tests passed'):format(count))
