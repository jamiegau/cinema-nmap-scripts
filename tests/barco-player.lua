-- Port selection only; TLS/SOAP/session behaviour uses the loopback simulator.
local root = assert(arg[1])
local override
package.preload.nmap = function() return {} end
package.preload.stdnse = function() return {get_script_args=function() return override end} end
package.preload.slaxml = function() return {} end
local env = setmetatable({}, {__index=_G})
assert(loadfile(root .. '/cinema-barco-player.nse', 't', env))()
local function port(number, state, protocol)
  return {number=number, state=state or 'open', protocol=protocol or 'tcp'}
end
assert(env.portrule({}, port(43758)))
for _, p in ipairs({port(80), port(443), port(43728), port(43758, 'closed'), port(43758, 'open', 'udp')}) do
  assert(not env.portrule({}, p))
end
override = '19090'
assert(env.portrule({}, port(19090)))
assert(not env.portrule({}, port(43758)))
for _, value in ipairs({'0', '65536', '-1', '1.2', 'bad', true, {}}) do
  override = value
  assert(not env.portrule({}, port(43758)))
end
print('PASS: Barco ICMP selects only the open TLS API port and validates overrides')
