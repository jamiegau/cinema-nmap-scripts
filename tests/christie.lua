-- Synthetic protocol fixtures based on the cited Christie manuals, NOT live captures.
local root = assert(arg[1])
local state
local host, port = {ip='127.0.0.1'}, {number=5000,protocol='tcp',state='open'}
local function reset()
    state = {sent={}, closes=0, connects=0, reads=0, now=0, replies={
        PNG={'(PNG!71 001 000 001)'},
        ['SST+SERI']={'(SST+SERI!000 001 "IMB-123" "IMB Serial Number")' ..
            '(SST+SERI!001 001 "123456789" "Projector S/N")' ..
            '(SST+SERI!"---END---")'},
        ['SST+SYST']={'(SST+SYST!000 001 "CP4420-RGB" "Projector Model")' ..
            '(SST+SYST!"---END---")'}
    }}
end
package.preload.nmap = function() return {
    clock_ms = function() state.now=state.now+1; return state.now end,
    new_socket = function() return {
        set_timeout=function(_, n) assert(n>0 and n<=2500) end,
        connect=function() state.connects=state.connects+1; return not state.connect_fail end,
        close=function() state.closes=state.closes+1 end,
        send=function(_, wire)
            local cmd=wire:match('^%((.-)%?%)\r\n$')
            assert(cmd == 'PNG' or cmd == 'SST+CONF' or cmd == 'SST+SERI' or cmd == 'SST+SYST', 'read-only allowlist')
            state.sent[#state.sent+1]=cmd
            state.current=cmd; state.index=0
            return not state.send_fail
        end,
        receive_bytes=function(_, n)
            assert(n==1); state.reads=state.reads+1
            if state.throw then error('synthetic socket error') end
            state.index=state.index+1
            local data=(state.replies[state.current] or {})[state.index]
            if not data then return false, 'TIMEOUT' end
            return true, data
        end
    } end
} end
package.preload.stdnse = function() return {
    output_table=function() return {} end, debug1=function() end,
    get_script_args=function() return state.port_override end
} end
local env=setmetatable({}, {__index=_G})
assert(loadfile(root .. '/cinema-christie-projector.nse', 't', env))()
local count=0
local function test(name, fn)
    reset(); fn(); count=count+1; print('PASS: ' .. name)
end
local function run()
    local out=env.action(host,port)
    assert(state.connects==1 and state.closes==1, 'exactly one connection and cleanup')
    return out
end
test('only open TCP 5000 is probed', function()
    assert(env.portrule(host,port))
    for _, p in ipairs({{number=5000,protocol='udp',state='open'},
        {number=5000,protocol='tcp',state='closed'}, {number=80,protocol='tcp',state='open'}}) do
        assert(not env.portrule(host,p))
    end
end)
test('explicit alternate port is validated and replaces the default', function()
    state.port_override='15000'
    assert(env.portrule(host,{number=15000,protocol='tcp',state='open'}))
    assert(not env.portrule(host,port))
    for _, value in ipairs({'bad', '0', '65536', '1.5'}) do
        state.port_override=value; assert(not env.portrule(host,port))
    end
end)
test('CineLife+ fields and main CPU version, not IMB serial', function()
    local out=run()
    assert(out.classification=='dci-projector' and out.vendor=='Christie')
    assert(out.productName=='CP4420-RGB' and out.serialNumber=='123456789' and out.version=='1.0.1')
    assert(#state.sent==3)
end)
test('CineLife uses documented type 60', function()
    state.replies.PNG={'(PNG!60 001 000 234)'}
    assert(run().version=='1.0.234')
end)
test('Solaria uses configuration group and legacy severity zero', function()
    state.replies.PNG={'(PNG!046 004 008 001)'}
    state.replies['SST+CONF']={'(SST+CONF!000 000 "Solaria One+" "Projector Model")' ..
        '(SST+CONF!001 000 "SN-001" "Projector Serial Number")(SST+CONF!"---END---")'}
    local out=run()
    assert(out.productName=='Solaria One+' and out.serialNumber=='SN-001' and out.version=='4.8.1')
    assert(#state.sent==2)
end)
test('older CP2000 type has basic identity without assuming SST', function()
    state.replies.PNG={'(PNG!041 001 002)'}
    local out=run()
    assert(out.productName=='CP2000-ZX' and out.version=='1.2' and #state.sent==1)
end)
test('board, non-cinema, unknown and malformed identities rejected', function()
    for _, reply in ipairs({'(PNG!40 001 002)', '(PNG!48 001 002)', '(PNG!49 001 002)',
        '(PNG!99 001 002 003)', '(PNG!71 001 002)', '(PNG!71 1.2.3)',
        '(PNG!71 001 002 003 garbage)', '(PNG?71 001 002 003)', '<html>Christie</html>'}) do
        reset(); state.replies.PNG={reply}; assert(run()==nil and #state.sent==1)
    end
end)
test('fragmented replies, echo, multiple frames and parenthesis in labels', function()
    state.replies.PNG={'(PNG?)\r\n(PN', 'G!71 001 ', '000 001)'}
    state.replies['SST+SERI']={'(SST+SERI!000 001 "discard" "IMB (serial)")',
        '(SST+SERI!001 001 "123456789" "Projector S/N")', '(SST+SERI!"---END---")'}
    assert(run().serialNumber=='123456789')
end)
test('missing optional data does not fabricate a model or serial', function()
    state.replies['SST+SERI']={'(SST+SERI!000 001 "IMB-123" "IMB Serial Number")(SST+SERI!"---END---")'}
    state.replies['SST+SYST']={'(SST+SYST!000 001 "On" "Power State")(SST+SYST!"---END---")'}
    local out=run(); assert(out.vendor=='Christie' and out.productName==nil and out.serialNumber==nil)
end)
test('error status and unknown placeholder values ignored', function()
    for _, value in ipairs({'Unknown','N/A','Not Specified','Communication Fault'}) do
        reset()
        state.replies['SST+SERI']={'(SST+SERI!001 001 "'..value..'" "Projector S/N")(SST+SERI!"---END---")'}
        state.replies['SST+SYST']={'(SST+SYST!000 003 "CP4420-RGB" "Projector Model")(SST+SYST!"---END---")'}
        local out=run(); assert(not out.serialNumber and not out.productName)
    end
end)
test('permission denial preserves identity and does not log in', function()
    state.replies['SST+SERI']={'(ERR 005 "Not authorized")'}
    local out=run(); assert(out.vendor=='Christie' and #state.sent==2)
end)
test('unterminated group preserves complete rows and permits next group', function()
    state.replies['SST+SERI']={'(SST+SERI!001 001 "123456789" "Projector S/N")'}
    local out=run(); assert(out.serialNumber=='123456789' and out.productName=='CP4420-RGB' and #state.sent==3)
end)
test('truncated frames cannot provide fields', function()
    state.replies['SST+SERI']={'(SST+SERI!001 001 "123456789" "Projector S/N"'}
    assert(not run().serialNumber)
end)
test('oversized replies are bounded', function()
    state.replies.PNG={string.rep('x',17000)..'(PNG!71 001 000 001)'}
    assert(run()==nil and state.reads==1)
end)
test('slow replies are bounded by wall clock deadline', function()
    state.replies.PNG=setmetatable({}, {__index=function() state.now=state.now+1000; return 'x' end})
    assert(run()==nil and state.reads<=3)
end)
test('connect, send, timeout and thrown errors close the socket', function()
    for _, key in ipairs({'connect_fail','send_fail','throw'}) do
        reset(); state[key]=true; assert(run()==nil)
    end
    reset(); state.replies.PNG={}; assert(run()==nil)
end)
print(('Christie offline tests: %d passed (no hardware tested)'):format(count))
