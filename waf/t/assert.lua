-- waf/t/assert.lua
-- 极简断言 + 测试框架：print 结果，run.lua 汇总后按失败数决定退出码。

local M = { passed = 0, failed = 0 }

function M.test(name, fn)
    local ok, err = pcall(fn)
    if ok then
        M.passed = M.passed + 1
        print("[PASS] " .. name)
    else
        M.failed = M.failed + 1
        print("[FAIL] " .. name .. " :: " .. tostring(err))
    end
end

function M.eq(a, b, msg)
    if a ~= b then
        error((msg or "eq") .. ": expected " .. tostring(b) .. ", got " .. tostring(a))
    end
end

function M.ok(v, msg)
    if not v then error((msg or "true") .. ": got " .. tostring(v)) end
end

function M.no(v, msg)
    if v then error((msg or "false") .. ": got truthy (" .. tostring(v) .. ")") end
end

function M.isnil(v, msg)
    if v ~= nil then error((msg or "nil") .. ": got " .. tostring(v)) end
end

function M.notnil(v, msg)
    if v == nil then error((msg or "notnil") .. ": got nil") end
end

function M.match(s, pat, msg)
    if not tostring(s):match(pat) then
        error((msg or "match") .. ": '" .. tostring(s) .. "' !~ " .. pat)
    end
end

function M.no_exit(fn, msg)
    -- 期望函数正常返回（未触发 ngx.exit）
    local ok, err = pcall(fn)
    if not ok then
        error((msg or "no_exit") .. ": unexpected error " .. tostring(err))
    end
end

function M.exits(fn, code, msg)
    -- 期望函数触发 ngx.exit(code)
    local ok, err = pcall(fn)
    if ok then
        error((msg or "exits") .. ": expected exit(" .. tostring(code) .. "), no exit")
    end
    if ngx.exit_code ~= code then
        error((msg or "exits") .. ": expected exit(" .. tostring(code) ..
              "), got exit(" .. tostring(ngx.exit_code) .. ") err=" .. tostring(err))
    end
end

function M.summary()
    print(string.format("\n==== %d passed, %d failed ====", M.passed, M.failed))
    return M.failed == 0
end

return M
