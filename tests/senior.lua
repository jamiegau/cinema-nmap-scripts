-- Captured get.ip fields from Senior 1.1.3; newline variants are synthetic.
local root = assert(arg[1])
local fixture = 'Version 1.1.3\nIP Adr 010.120.246.031\nSubnet 255.255.255.000\nRouter 010.120.246.254\ncommand.ack\n'
local args, chunks, fail, calls, now, advance
local function reset()
  args={}; chunks={fixture}; fail=nil; now=0; advance=0
  calls={connect=0, send=0, close=0, read=0, sleep=0, socket=0}
end
package.preload.nmap = function() return {
  clock_ms=function() return now end,
  new_socket=function()
    calls.socket=calls.socket+1
    return {
      set_timeout=function(_, ms) assert(ms > 0 and ms <= 3000) end,
      connect=function(_, host, port, protocol)
        calls.connect=calls.connect+1; calls.port=port
        assert(host.ip=='10.120.246.31' and protocol=='tcp')
        return fail ~= 'connect'
      end,
      send=function(_, message)
        calls.send=calls.send+1; assert(message=='get.ip\n')
        return fail ~= 'send'
      end,
      receive_bytes=function(_, n)
        assert(n==1); calls.read=calls.read+1; now=now+advance
        if fail=='exception' then error('simulated socket error') end
        local chunk=table.remove(chunks,1)
        return chunk ~= nil, chunk or 'TIMEOUT'
      end,
      close=function() calls.close=calls.close+1 end,
    }
  end,
} end
package.preload.stdnse = function() return {
  get_script_args=function(key) return args[key] end,
  output_table=function() return {} end,
  sleep=function(seconds) assert(seconds==0.25); calls.sleep=calls.sleep+1 end,
  debug1=function() end,
} end
local env=setmetatable({}, {__index=_G})
assert(loadfile(root..'/cinema-edge-senior-io.nse','t',env))()
local function host() return {ip='10.120.246.31', registry={}} end
local function check_result(result)
  assert(result and result.vendor=='Edge' and result.productName=='Senior-IO')
  assert(result.classification=='automation-io' and result.version=='1.1.3')
  assert(result.serialNumber==nil)
  assert(calls.connect==1 and calls.send==1 and calls.close==1)
end
local count=0
local function test(name, fn)
  reset(); fn(); count=count+1; print('PASS: '..name)
end
test('Senior port rule needs only open TCP 1125, not FTP/SSH/HTTP', function()
  assert(env.portrule(host(),{number=1125,protocol='tcp',state='open'}))
  for _, port in ipairs({{number=61408,protocol='tcp',state='open'},
    {number=1125,protocol='udp',state='open'}, {number=1125,protocol='tcp',state='closed'}}) do
    assert(not env.portrule(host(),port))
  end
  assert(not env.hostrule(host()))
end)
test('direct mode enables host rule and disables port rule', function()
  args['cinema-edge-senior-io.direct']='true'
  assert(env.hostrule(host()))
  assert(not env.portrule(host(),{number=1125,protocol='tcp',state='open'}))
end)
test('validated explicit port override', function()
  args['cinema-edge-senior-io.direct']='true'
  for _, bad in ipairs({'0','65536','1.5','bad'}) do
    args['cinema-edge-senior-io.port']=bad
    assert(not env.hostrule(host())); assert(env.action(host())==nil)
  end
  assert(calls.socket==0)
  args['cinema-edge-senior-io.port']='11125'
  check_result(env.action(host())); assert(calls.port==11125)
end)
test('captured response yields identity with one query on 1125', function()
  check_result(env.action(host())); assert(calls.port==1125)
end)
test('fragmented reply assembled without additional commands', function()
  chunks={}; for i=1,#fixture do chunks[#chunks+1]=fixture:sub(i,i) end
  check_result(env.action(host()))
end)
test('CRLF response supported', function()
  chunks={fixture:gsub('\n','\r\n')}; check_result(env.action(host()))
end)
test('ack without final newline supported', function()
  chunks={fixture:sub(1,-2)}; check_result(env.action(host()))
end)
test('generic version/IP data and incomplete or malformed replies rejected', function()
  local bad={fixture:gsub('command.ack','command.nak'),fixture:gsub('IP Adr','Address'),
    fixture:gsub('010.120.246.031','999.120.246.031'),fixture:gsub('Version 1.1.3','Version unknown'),
    'command.ack\n','Version 1.1.3\ncommand.ack\n',fixture..'extra\n'}
  for _, reply in ipairs(bad) do
    reset(); chunks={reply}; assert(env.action(host())==nil)
    assert(calls.connect==1 and calls.send==1 and calls.close==1)
  end
end)
test('connection failure closes socket and never sends/retries', function()
  fail='connect'; assert(env.action(host())==nil)
  assert(calls.connect==1 and calls.send==0 and calls.close==1)
end)
test('send failure closes socket without reads/retries', function()
  fail='send'; assert(env.action(host())==nil)
  assert(calls.send==1 and calls.read==0 and calls.close==1)
end)
test('read timeout and exception close without retries', function()
  for _, failure in ipairs({'timeout','exception'}) do
    reset(); fail=failure; chunks={}; assert(env.action(host())==nil)
    assert(calls.connect==1 and calls.send==1 and calls.close==1)
  end
end)
test('response byte limit enforced', function()
  chunks={string.rep('x',4097)}; assert(env.action(host())==nil)
  assert(calls.read==1 and calls.close==1)
end)
test('slow trickle cannot extend total read deadline', function()
  chunks={'V','e','r','s','i','o','n'}; advance=1000
  assert(env.action(host())==nil); assert(calls.read==3 and calls.close==1)
end)
test('same host cannot reconnect after success or failure', function()
  for _, failure in ipairs({'none','connect'}) do
    reset(); fail=failure; local h=host()
    env.action(h); assert(env.action(h)==nil)
    assert(calls.connect==1 and calls.close==1)
  end
end)
print(('%d Senior offline tests passed'):format(count))
