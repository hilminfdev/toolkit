--[[
    Delta Toolkit  (Remote Spy + Explorer + Function Dumper)
    Target: Delta executor (mobile / PC), Luau.

    Tabs
      Remotes   : logs FireServer / InvokeServer calls, generates replay code,
                  Block / Ignore / Replay per remote.
      Explorer  : Dex-style tree of the DataModel, search, property dump,
                  script decompile, jump to the script's functions.
      Functions : scans getgc() for Lua functions, filter by name / script /
                  constant, dumps info + constants + upvalues, Trace calls.

    Needs executor functions (checked at start, missing ones just disable a feature):
      hookmetamethod, getnamecallmethod, checkcaller, newcclosure, getgc,
      debug.getconstants / getupvalues / getprotos / getinfo, decompile,
      hookfunction, setclipboard, writefile
]]

local genv = (getgenv and getgenv()) or _G
if genv.DeltaToolkit and genv.DeltaToolkit.Gui and genv.DeltaToolkit.Gui.Parent then
    genv.DeltaToolkit.Gui.Enabled = true
    return
end

----------------------------------------------------------------------
-- Services / executor function fallbacks
----------------------------------------------------------------------
local Players = game:GetService("Players")
local UIS = game:GetService("UserInputService")
local LocalPlayer = Players.LocalPlayer

local hookmm      = hookmetamethod
local getnc       = getnamecallmethod
local checkcall   = checkcaller or function() return false end
local newcc       = newcclosure or function(f) return f end
local hookfn      = hookfunction or replaceclosure
local setclip     = setclipboard or toclipboard or (Clipboard and Clipboard.set)
local dgetinfo    = (debug and debug.getinfo) or getinfo
local dconsts     = (debug and debug.getconstants) or getconstants
local dupvals     = (debug and debug.getupvalues) or getupvalues
local dprotos     = (debug and debug.getprotos) or getprotos
local decomp      = decompile
local isLua       = islclosure or function(f) return not iscclosure(f) end
local isExecFn    = isexecutorclosure or checkclosure or is_synapse_function or function() return false end
local getCallScr  = getcallingscript

local function safeToString(v)
    local ok, s = pcall(tostring, v)
    return ok and s or "<?>"
end

----------------------------------------------------------------------
-- Serializer (values -> Lua source)
----------------------------------------------------------------------
local KEYWORDS = {}
for w in ("and break do else elseif end false for function if in local nil not or repeat return then true until while continue"):gmatch("%a+") do
    KEYWORDS[w] = true
end

local function isIdent(s)
    return type(s) == "string" and s:match("^[%a_][%w_]*$") ~= nil and not KEYWORDS[s]
end

local function q(s)
    return string.format("%q", s)
end

local function num(n)
    if n ~= n then return "0/0" end
    if n == math.huge then return "math.huge" end
    if n == -math.huge then return "-math.huge" end
    if n % 1 == 0 and math.abs(n) < 1e15 then return string.format("%d", n) end
    return string.format("%.14g", n)
end

local function isService(inst)
    local ok, s = pcall(game.GetService, game, inst.ClassName)
    return ok and s == inst
end

local function getPath(inst)
    if typeof(inst) ~= "Instance" then return safeToString(inst) end
    if inst == game then return "game" end

    local chain, cur, base = {}, inst, nil
    while cur and cur ~= game do
        if LocalPlayer and cur == LocalPlayer then
            base = 'game:GetService("Players").LocalPlayer'
            break
        end
        table.insert(chain, 1, cur)
        cur = cur.Parent
    end
    if not base then
        if cur ~= game then
            return "nil --[[ " .. inst.Name .. " (not parented to game) ]]"
        end
        base = "game"
    end

    local out = base
    for i, p in ipairs(chain) do
        if base == "game" and i == 1 and isService(p) then
            out = out .. ":GetService(" .. q(p.ClassName) .. ")"
        elseif isIdent(p.Name) then
            out = out .. "." .. p.Name
        else
            out = out .. "[" .. q(p.Name) .. "]"
        end
    end
    return out
end

local serialize
local function join(t, f)
    local r = {}
    for i, v in ipairs(t) do r[i] = f(v) end
    return table.concat(r, ", ")
end

function serialize(v, depth, seen, ind)
    depth = depth or 0
    seen = seen or {}
    ind = ind or ""
    local t = typeof(v)

    if t == "string" then return q(v)
    elseif t == "number" then return num(v)
    elseif t == "boolean" or t == "nil" then return tostring(v)
    elseif t == "Instance" then return getPath(v)
    elseif t == "Vector3" then return "Vector3.new(" .. num(v.X) .. ", " .. num(v.Y) .. ", " .. num(v.Z) .. ")"
    elseif t == "Vector2" then return "Vector2.new(" .. num(v.X) .. ", " .. num(v.Y) .. ")"
    elseif t == "CFrame" then return "CFrame.new(" .. join({ v:GetComponents() }, num) .. ")"
    elseif t == "Color3" then return "Color3.new(" .. num(v.R) .. ", " .. num(v.G) .. ", " .. num(v.B) .. ")"
    elseif t == "UDim2" then return "UDim2.new(" .. num(v.X.Scale) .. ", " .. num(v.X.Offset) .. ", " .. num(v.Y.Scale) .. ", " .. num(v.Y.Offset) .. ")"
    elseif t == "UDim" then return "UDim.new(" .. num(v.Scale) .. ", " .. num(v.Offset) .. ")"
    elseif t == "BrickColor" then return "BrickColor.new(" .. q(v.Name) .. ")"
    elseif t == "NumberRange" then return "NumberRange.new(" .. num(v.Min) .. ", " .. num(v.Max) .. ")"
    elseif t == "Ray" then return "Ray.new(" .. serialize(v.Origin) .. ", " .. serialize(v.Direction) .. ")"
    elseif t == "EnumItem" or t == "Enum" then return tostring(v)
    elseif t == "function" then
        local name = "?"
        if dgetinfo then
            local ok, info = pcall(dgetinfo, v)
            if ok and info and info.name and info.name ~= "" then name = info.name end
        end
        return "function() end --[[ " .. name .. " ]]"
    elseif t == "table" then
        if seen[v] then return "{} --[[ cyclic ]]" end
        if depth >= 8 then return "{} --[[ max depth ]]" end
        seen[v] = true
        local inner = ind .. "    "
        local parts, n = {}, #v
        for i = 1, n do
            if #parts >= 200 then parts[#parts + 1] = inner .. "--[[ truncated ]]"; break end
            parts[#parts + 1] = inner .. serialize(v[i], depth + 1, seen, inner)
        end
        local extra = 0
        for k, val in next, v do
            if not (type(k) == "number" and k >= 1 and k <= n and k % 1 == 0) then
                extra = extra + 1
                if extra > 200 then parts[#parts + 1] = inner .. "--[[ truncated ]]"; break end
                local ks = isIdent(k) and k or ("[" .. serialize(k, depth + 1, seen, inner) .. "]")
                parts[#parts + 1] = inner .. ks .. " = " .. serialize(val, depth + 1, seen, inner)
            end
        end
        seen[v] = nil
        if #parts == 0 then return "{}" end
        return "{\n" .. table.concat(parts, ",\n") .. "\n" .. ind .. "}"
    end
    return "nil --[[ " .. t .. ": " .. safeToString(v) .. " ]]"
end

local function ser(v, depth)
    local ok, r = pcall(serialize, v, depth)
    return ok and r or ("nil --[[ serialize error: " .. safeToString(r) .. " ]]")
end

----------------------------------------------------------------------
-- GUI skeleton
----------------------------------------------------------------------
local C = {
    bg     = Color3.fromRGB(24, 24, 30),
    bar    = Color3.fromRGB(34, 34, 44),
    panel  = Color3.fromRGB(18, 18, 22),
    btn    = Color3.fromRGB(52, 52, 68),
    sel    = Color3.fromRGB(70, 90, 160),
    accent = Color3.fromRGB(90, 120, 220),
    text   = Color3.fromRGB(225, 225, 235),
    dim    = Color3.fromRGB(150, 150, 165),
    red    = Color3.fromRGB(190, 70, 70),
}

local function mk(class, props, parent)
    local o = Instance.new(class)
    for k, v in pairs(props) do o[k] = v end
    o.Parent = parent
    return o
end

local function corner(o, r)
    mk("UICorner", { CornerRadius = UDim.new(0, r or 4) }, o)
end

local gui = mk("ScreenGui", {
    Name = "DeltaToolkit", ResetOnSpawn = false, IgnoreGuiInset = true,
    ZIndexBehavior = Enum.ZIndexBehavior.Sibling, DisplayOrder = 999999,
})
do
    local ok = false
    if gethui then ok = pcall(function() gui.Parent = gethui() end) end
    if not ok then ok = pcall(function() gui.Parent = game:GetService("CoreGui") end) end
    if not ok then gui.Parent = LocalPlayer:WaitForChild("PlayerGui") end
end

local WIN_W, WIN_H = 640, 330
local win = mk("Frame", {
    BackgroundColor3 = C.bg, BorderSizePixel = 0,
    Size = UDim2.fromOffset(WIN_W, WIN_H),
    Position = UDim2.new(0.5, -WIN_W / 2, 0.5, -WIN_H / 2),
    ClipsDescendants = true,
}, gui)
corner(win, 6)

local titleBar = mk("Frame", { BackgroundColor3 = C.bar, BorderSizePixel = 0, Size = UDim2.new(1, 0, 0, 26) }, win)
mk("TextLabel", {
    BackgroundTransparency = 1, Position = UDim2.fromOffset(8, 0), Size = UDim2.new(1, -70, 1, 0),
    Text = "Delta Toolkit", TextColor3 = C.text, Font = Enum.Font.GothamBold, TextSize = 13,
    TextXAlignment = Enum.TextXAlignment.Left,
}, titleBar)

local function smallBtn(text, xFromRight, color, cb)
    local b = mk("TextButton", {
        BackgroundColor3 = color, Text = text, TextColor3 = C.text, Font = Enum.Font.GothamBold, TextSize = 13,
        Size = UDim2.fromOffset(24, 18), Position = UDim2.new(1, xFromRight, 0, 4), AutoButtonColor = true,
    }, titleBar)
    corner(b, 4)
    b.MouseButton1Click:Connect(cb)
    return b
end

local body = mk("Frame", { BackgroundTransparency = 1, Position = UDim2.fromOffset(0, 26), Size = UDim2.new(1, 0, 1, -26) }, win)
local minimized = false
smallBtn("-", -56, C.btn, function()
    minimized = not minimized
    body.Visible = not minimized
    win.Size = minimized and UDim2.fromOffset(WIN_W, 26) or UDim2.fromOffset(WIN_W, WIN_H)
end)
smallBtn("X", -28, C.red, function() gui.Enabled = false end)

-- dragging (mouse + touch)
do
    local dragging, dragStart, startPos
    titleBar.InputBegan:Connect(function(i)
        if i.UserInputType == Enum.UserInputType.MouseButton1 or i.UserInputType == Enum.UserInputType.Touch then
            dragging, dragStart, startPos = true, i.Position, win.Position
            i.Changed:Connect(function()
                if i.UserInputState == Enum.UserInputState.End then dragging = false end
            end)
        end
    end)
    UIS.InputChanged:Connect(function(i)
        if dragging and (i.UserInputType == Enum.UserInputType.MouseMovement or i.UserInputType == Enum.UserInputType.Touch) then
            local d = i.Position - dragStart
            win.Position = UDim2.new(startPos.X.Scale, startPos.X.Offset + d.X, startPos.Y.Scale, startPos.Y.Offset + d.Y)
        end
    end)
end

-- tabs
local tabBar = mk("Frame", { BackgroundTransparency = 1, Size = UDim2.new(1, -8, 0, 24), Position = UDim2.fromOffset(4, 2) }, body)
mk("UIListLayout", { FillDirection = Enum.FillDirection.Horizontal, Padding = UDim.new(0, 4) }, tabBar)

local LEFT_W = 300
local pagesHolder = mk("Frame", {
    BackgroundTransparency = 1, Position = UDim2.fromOffset(4, 30), Size = UDim2.new(0, LEFT_W, 1, -34),
}, body)

local rightPane = mk("Frame", {
    BackgroundTransparency = 1, Position = UDim2.fromOffset(LEFT_W + 10, 30), Size = UDim2.new(1, -(LEFT_W + 14), 1, -34),
}, body)

-- generic UI helpers
local function makeToolbar(parent, y)
    local f = mk("Frame", { BackgroundTransparency = 1, Position = UDim2.fromOffset(0, y), Size = UDim2.new(1, 0, 0, 22) }, parent)
    mk("UIListLayout", {
        FillDirection = Enum.FillDirection.Horizontal, Padding = UDim.new(0, 4), SortOrder = Enum.SortOrder.LayoutOrder,
    }, f)
    return f
end

local function tbBtn(toolbar, text, cb)
    local b = mk("TextButton", {
        BackgroundColor3 = C.btn, Text = text, TextColor3 = C.text, Font = Enum.Font.Gotham, TextSize = 12,
        AutomaticSize = Enum.AutomaticSize.X, Size = UDim2.new(0, 0, 1, 0), AutoButtonColor = true,
    }, toolbar)
    mk("UIPadding", { PaddingLeft = UDim.new(0, 8), PaddingRight = UDim.new(0, 8) }, b)
    corner(b, 4)
    b.MouseButton1Click:Connect(function() cb(b) end)
    return b
end

local function makeInput(parent, y, placeholder)
    local tb = mk("TextBox", {
        BackgroundColor3 = C.panel, BorderSizePixel = 0, Position = UDim2.fromOffset(0, y), Size = UDim2.new(1, 0, 0, 22),
        Text = "", PlaceholderText = placeholder, PlaceholderColor3 = C.dim, TextColor3 = C.text,
        Font = Enum.Font.Gotham, TextSize = 12, ClearTextOnFocus = false, TextXAlignment = Enum.TextXAlignment.Left,
    }, parent)
    mk("UIPadding", { PaddingLeft = UDim.new(0, 6) }, tb)
    corner(tb, 4)
    return tb
end

local function makeList(parent, y)
    local sf = mk("ScrollingFrame", {
        BackgroundColor3 = C.panel, BorderSizePixel = 0, Position = UDim2.fromOffset(0, y), Size = UDim2.new(1, 0, 1, -y),
        ScrollBarThickness = 4, CanvasSize = UDim2.new(), AutomaticCanvasSize = Enum.AutomaticSize.Y,
        ScrollingDirection = Enum.ScrollingDirection.Y,
    }, parent)
    mk("UIListLayout", { SortOrder = Enum.SortOrder.LayoutOrder }, sf)
    corner(sf, 4)
    return sf
end

local function clearList(list)
    for _, c in ipairs(list:GetChildren()) do
        if not c:IsA("UIListLayout") then c:Destroy() end
    end
end

-- output pane (shared)
local outFull, outTag = "", "dump"
local outBar = makeToolbar(rightPane, 0)
local outScroll = mk("ScrollingFrame", {
    BackgroundColor3 = C.panel, BorderSizePixel = 0, Position = UDim2.fromOffset(0, 26), Size = UDim2.new(1, 0, 1, -26),
    ScrollBarThickness = 5, CanvasSize = UDim2.new(), AutomaticCanvasSize = Enum.AutomaticSize.Y,
    ScrollingDirection = Enum.ScrollingDirection.Y,
}, rightPane)
corner(outScroll, 4)
local outLabel = mk("TextLabel", {
    BackgroundTransparency = 1, Size = UDim2.new(1, -8, 0, 0), Position = UDim2.fromOffset(4, 2),
    AutomaticSize = Enum.AutomaticSize.Y, Text = "", TextColor3 = C.text, Font = Enum.Font.Code, TextSize = 12,
    TextXAlignment = Enum.TextXAlignment.Left, TextYAlignment = Enum.TextYAlignment.Top, TextWrapped = true,
    TextSelectable = true,
}, outScroll)

local SHOW_LIMIT = 14000
local function refreshOut()
    if #outFull > SHOW_LIMIT then
        outLabel.Text = outFull:sub(1, SHOW_LIMIT) .. "\n\n-- [display truncated, Copy / Save has the full text: " .. #outFull .. " chars]"
    else
        outLabel.Text = outFull
    end
end

local function setOut(text, tag)
    outFull = tostring(text)
    outTag = tag or "dump"
    refreshOut()
    outScroll.CanvasPosition = Vector2.zero
end

local function appendOut(line)
    outFull = outFull .. line .. "\n"
    if #outFull > 100000 then outFull = outFull:sub(-80000) end
    refreshOut()
end

local function flash(btn, text)
    local old = btn.Text
    btn.Text = text
    task.delay(1, function() if btn.Parent then btn.Text = old end end)
end

tbBtn(outBar, "Copy", function(b)
    if setclip then setclip(outFull); flash(b, "Copied") else flash(b, "No clip") end
end)
tbBtn(outBar, "Save", function(b)
    if not writefile then return flash(b, "No fs") end
    pcall(function() if makefolder and isfolder and not isfolder("DeltaToolkit") then makefolder("DeltaToolkit") end end)
    local name = ("DeltaToolkit/%s_%d.txt"):format(outTag:gsub("[^%w_]", "_"), os.time())
    local ok = pcall(writefile, name, outFull)
    flash(b, ok and "Saved" or "Failed")
end)
tbBtn(outBar, "Clear", function() setOut("") end)

-- pages & tabs
local pages, tabButtons = {}, {}
local function showTab(name)
    for n, p in pairs(pages) do p.Visible = (n == name) end
    for n, b in pairs(tabButtons) do b.BackgroundColor3 = (n == name) and C.accent or C.btn end
end

local function newPage(name)
    local p = mk("Frame", { BackgroundTransparency = 1, Size = UDim2.fromScale(1, 1), Visible = false }, pagesHolder)
    pages[name] = p
    local b = mk("TextButton", {
        BackgroundColor3 = C.btn, Text = name, TextColor3 = C.text, Font = Enum.Font.GothamBold, TextSize = 12,
        Size = UDim2.fromOffset(90, 22), AutoButtonColor = true,
    }, tabBar)
    corner(b, 4)
    b.MouseButton1Click:Connect(function() showTab(name) end)
    tabButtons[name] = b
    return p
end

local function addRow(list, text, order, cb)
    local b = mk("TextButton", {
        BackgroundColor3 = C.panel, BorderSizePixel = 0, Size = UDim2.new(1, -4, 0, 20), LayoutOrder = order or 0,
        Text = text, TextColor3 = C.text, Font = Enum.Font.Code, TextSize = 12, TextXAlignment = Enum.TextXAlignment.Left,
        TextTruncate = Enum.TextTruncate.AtEnd, AutoButtonColor = false,
    }, list)
    mk("UIPadding", { PaddingLeft = UDim.new(0, 4) }, b)
    b.MouseButton1Click:Connect(function() cb(b) end)
    return b
end

----------------------------------------------------------------------
-- TAB 1: Remote Spy
----------------------------------------------------------------------
local remotePage = newPage("Remotes")
local remoteBar = makeToolbar(remotePage, 0)
local remoteList = makeList(remotePage, 26)

local remoteLogs, remoteCounter = {}, 0
local blocked, ignored = {}, {}
local selectedLog, selectedLogRow
local paused = false

local function genRemoteCode(e)
    local args = {}
    for i = 1, e.args.n do
        args[i] = "    " .. ser(e.args[i], 1):gsub("\n", "\n    ")
    end
    local lines = {
        "-- " .. e.class .. ": " .. e.name .. "  |  " .. e.method .. "  |  " .. e.time,
    }
    if e.script then lines[#lines + 1] = "-- calling script: " .. e.script end
    lines[#lines + 1] = "local remote = " .. e.path
    if e.args.n == 0 then
        lines[#lines + 1] = "remote:" .. e.method .. "()"
    else
        lines[#lines + 1] = "local args = {\n" .. table.concat(args, ",\n") .. "\n}"
        lines[#lines + 1] = ("remote:%s(unpack(args, 1, %d))"):format(e.method, e.args.n)
    end
    return table.concat(lines, "\n")
end

local function handleRemote(remote, method, args, callingScript)
    if paused or ignored[remote] then return end
    local ok = pcall(function()
        local cls = remote.ClassName
        if cls ~= "RemoteEvent" and cls ~= "RemoteFunction" and cls ~= "UnreliableRemoteEvent" then return end
        remoteCounter = remoteCounter + 1
        local e = {
            remote = remote, class = cls, name = remote.Name, method = method, args = args,
            path = getPath(remote), time = os.date("%H:%M:%S"), id = remoteCounter,
            script = callingScript and getPath(callingScript) or nil,
        }
        table.insert(remoteLogs, e)
        e.row = addRow(remoteList, ("#%d %s:%s (%d)"):format(e.id, e.name, method, args.n), -e.id, function(row)
            if selectedLogRow then selectedLogRow.BackgroundColor3 = C.panel end
            selectedLog, selectedLogRow = e, row
            row.BackgroundColor3 = C.sel
            setOut(genRemoteCode(e), "remote_" .. e.name)
        end)
        if #remoteLogs > 200 then
            local old = table.remove(remoteLogs, 1)
            if old.row then old.row:Destroy() end
        end
    end)
    return ok
end

tbBtn(remoteBar, "Pause", function(b)
    paused = not paused
    b.Text = paused and "Resume" or "Pause"
end)
tbBtn(remoteBar, "Clear", function()
    clearList(remoteList)
    table.clear(remoteLogs)
    selectedLog, selectedLogRow = nil, nil
end)
tbBtn(remoteBar, "Block", function(b)
    if not selectedLog then return flash(b, "Select") end
    local r = selectedLog.remote
    blocked[r] = not blocked[r] or nil
    flash(b, blocked[r] and "Blocked" or "Unblocked")
end)
tbBtn(remoteBar, "Ignore", function(b)
    if not selectedLog then return flash(b, "Select") end
    ignored[selectedLog.remote] = true
    flash(b, "Ignored")
end)
tbBtn(remoteBar, "Replay", function(b)
    if not selectedLog then return flash(b, "Select") end
    local e = selectedLog
    task.spawn(function()
        local ok, res
        if e.method:lower() == "fireserver" then
            ok, res = pcall(function() return e.remote:FireServer(unpack(e.args, 1, e.args.n)) end)
        else
            ok, res = pcall(function() return e.remote:InvokeServer(unpack(e.args, 1, e.args.n)) end)
        end
        appendOut(("\n-- replay %s: %s"):format(ok and "ok" or "error", ser(res, 5)))
    end)
end)

local REMOTE_METHODS = { FireServer = true, InvokeServer = true, fireServer = true, invokeServer = true }
local hookOk = false
if hookmm and getnc then
    local oldNamecall
    hookOk = pcall(function()
        oldNamecall = hookmm(game, "__namecall", newcc(function(self, ...)
            local method = getnc()
            if REMOTE_METHODS[method] and typeof(self) == "Instance" and not checkcall() then
                local args = table.pack(...)
                local cs
                if getCallScr then
                    local okc, res = pcall(getCallScr)
                    if okc then cs = res end
                end
                task.defer(handleRemote, self, method, args, cs)
                if blocked[self] then return end
            end
            return oldNamecall(self, ...)
        end))
    end)
end

----------------------------------------------------------------------
-- TAB 3 helpers first (Functions) so Explorer can call scan
----------------------------------------------------------------------
local funcPage = newPage("Functions")
local funcBar = makeToolbar(funcPage, 0)
local funcInput = makeInput(funcPage, 26, "filter: name / script / constant")
local funcList = makeList(funcPage, 52)

local funcResults, selectedFn, selectedFnRow = {}, nil, nil
local scanning = false

local function describeFn(e)
    local lines = {
        "-- Function dump",
        "name        : " .. (e.name ~= "" and e.name or "anonymous"),
        "source      : " .. e.src,
        "linedefined : " .. tostring(e.line),
        "numparams   : " .. tostring(e.info.numparams),
        "is_vararg   : " .. tostring(e.info.is_vararg),
        "nups        : " .. tostring(e.info.nups),
        "script      : " .. (e.script and getPath(e.script) or "?"),
        "",
    }
    if dconsts then
        local ok, consts = pcall(dconsts, e.fn)
        lines[#lines + 1] = "-- constants"
        if ok and type(consts) == "table" then
            local shown = 0
            for i, v in pairs(consts) do
                shown = shown + 1
                if shown > 300 then lines[#lines + 1] = "  ... truncated"; break end
                lines[#lines + 1] = ("  [%s] = %s"):format(tostring(i), ser(v, 6))
            end
        else
            lines[#lines + 1] = "  unavailable"
        end
        lines[#lines + 1] = ""
    end
    if dupvals then
        local ok, ups = pcall(dupvals, e.fn)
        lines[#lines + 1] = "-- upvalues"
        if ok and type(ups) == "table" then
            local shown = 0
            for i, v in pairs(ups) do
                shown = shown + 1
                if shown > 100 then lines[#lines + 1] = "  ... truncated"; break end
                lines[#lines + 1] = ("  [%s] (%s) = %s"):format(tostring(i), typeof(v), ser(v, 5))
            end
        else
            lines[#lines + 1] = "  unavailable"
        end
        lines[#lines + 1] = ""
    end
    if dprotos then
        local ok, protos = pcall(dprotos, e.fn)
        if ok and type(protos) == "table" then
            lines[#lines + 1] = "-- protos: " .. #protos
        end
    end
    return table.concat(lines, "\n")
end

local function scanFunctions(filter, scriptFilter)
    if scanning then return end
    if not getgc then return setOut("-- getgc is not supported by this executor") end
    scanning = true
    clearList(funcList)
    table.clear(funcResults)
    selectedFn, selectedFnRow = nil, nil
    filter = (filter or ""):lower()
    setOut("-- scanning...")

    task.spawn(function()
        local ok, err = pcall(function()
            local gc = getgc(true)
            local found = 0
            for i = 1, #gc do
                if i % 3000 == 0 then task.wait() end
                local f = gc[i]
                if type(f) == "function" and isLua(f) and not isExecFn(f) then
                    local info = dgetinfo and dgetinfo(f) or {}
                    local name = info.name or ""
                    local src = info.short_src or info.source or "?"
                    local scr
                    local okEnv, env = pcall(getfenv, f)
                    if okEnv and type(env) == "table" then
                        local okS, s = pcall(function() return env.script end)
                        if okS and typeof(s) == "Instance" then scr = s end
                    end

                    local match = true
                    if scriptFilter then
                        match = (scr == scriptFilter)
                    elseif filter ~= "" then
                        match = name:lower():find(filter, 1, true) ~= nil
                            or src:lower():find(filter, 1, true) ~= nil
                            or (scr ~= nil and scr.Name:lower():find(filter, 1, true) ~= nil)
                        if not match and dconsts then
                            local okC, consts = pcall(dconsts, f)
                            if okC and type(consts) == "table" then
                                for _, c in pairs(consts) do
                                    if type(c) == "string" and c:lower():find(filter, 1, true) then
                                        match = true
                                        break
                                    end
                                end
                            end
                        end
                    end

                    if match then
                        found = found + 1
                        if found > 400 then break end
                        local e = { fn = f, name = name, src = src, line = info.linedefined or 0, info = info, script = scr }
                        funcResults[#funcResults + 1] = e
                        local label = ("%s  [%s]:%s"):format(name ~= "" and name or "anonymous", scr and scr.Name or src, tostring(e.line))
                        e.row = addRow(funcList, label, found, function(row)
                            if selectedFnRow then selectedFnRow.BackgroundColor3 = C.panel end
                            selectedFn, selectedFnRow = e, row
                            row.BackgroundColor3 = C.sel
                            setOut(describeFn(e), "func_" .. (name ~= "" and name or "anon"))
                        end)
                    end
                end
            end
            setOut(("-- scan done: %d function(s)%s"):format(found, found > 400 and " (capped at 400, narrow the filter)" or ""))
        end)
        if not ok then setOut("-- scan error: " .. safeToString(err)) end
        scanning = false
    end)
end

tbBtn(funcBar, "Scan", function() scanFunctions(funcInput.Text) end)
tbBtn(funcBar, "Trace", function(b)
    if not selectedFn then return flash(b, "Select") end
    if not hookfn then return flash(b, "No hook") end
    local e = selectedFn
    if e.traced then return flash(b, "Already") end
    local old
    local okHook = pcall(function()
        old = hookfn(e.fn, function(...)
            local n = select("#", ...)
            local a = {}
            for i = 1, n do a[i] = ser((select(i, ...)), 6):gsub("%s*\n%s*", " ") end
            pcall(appendOut, ("[call] %s(%s)"):format(e.name ~= "" and e.name or "anonymous", table.concat(a, ", ")))
            return old(...)
        end)
    end)
    e.traced = okHook
    setOut(okHook and ("-- tracing " .. (e.name ~= "" and e.name or "anonymous") .. ", calls appear below\n") or "-- hookfunction failed on this closure", "trace")
end)
tbBtn(funcBar, "Clear", function()
    clearList(funcList)
    table.clear(funcResults)
    selectedFn, selectedFnRow = nil, nil
end)

----------------------------------------------------------------------
-- TAB 2: Explorer (Dex-like)
----------------------------------------------------------------------
local explorerPage = newPage("Explorer")
local expBar = makeToolbar(explorerPage, 0)
local expSearch = makeInput(explorerPage, 26, "search name / class (empty = tree)")
local expList = makeList(explorerPage, 52)

local expanded = {}
local selectedInst, selectedInstRow
local MAX_ROWS = 700

local PROPS = {
    "Name", "ClassName", "Parent", "Archivable", "Position", "Size", "CFrame", "Anchored", "CanCollide", "Transparency",
    "Material", "Color", "BrickColor", "Text", "Visible", "Enabled", "Disabled", "Value", "RunContext", "Health", "MaxHealth",
    "WalkSpeed", "JumpPower", "JumpHeight", "Image", "SoundId", "Volume", "Playing", "TimePosition", "PlaybackSpeed",
    "Adornee", "Part0", "Part1", "PrimaryPart", "CameraType", "FieldOfView", "ClickDetector", "MaxActivationDistance",
    "ActionText", "ObjectText", "HoldDuration", "RequiresLineOfSight", "Brightness", "Range", "TeamColor", "UserId",
}

local function describeInst(inst)
    local lines = {
        "-- " .. inst.ClassName .. ": " .. inst.Name,
        "path     : " .. getPath(inst),
        "children : " .. #inst:GetChildren(),
        "",
        "-- properties",
    }
    for _, p in ipairs(PROPS) do
        local ok, v = pcall(function() return inst[p] end)
        if ok and p ~= "ClassName" and p ~= "Name" then
            lines[#lines + 1] = ("  %s = %s"):format(p, ser(v, 6))
        end
    end
    local okA, attrs = pcall(function() return inst:GetAttributes() end)
    if okA and next(attrs) then
        lines[#lines + 1] = ""
        lines[#lines + 1] = "-- attributes"
        for k, v in pairs(attrs) do
            lines[#lines + 1] = ("  %s = %s"):format(k, ser(v, 6))
        end
    end
    return table.concat(lines, "\n")
end

local function selectInst(inst, row)
    if selectedInstRow then selectedInstRow.BackgroundColor3 = C.panel end
    selectedInst, selectedInstRow = inst, row
    if row then row.BackgroundColor3 = C.sel end
    setOut(describeInst(inst), "inst_" .. inst.Name)
end

local refreshTree
local function addTreeRow(inst, depth, order)
    local holder = mk("Frame", { BackgroundTransparency = 1, Size = UDim2.new(1, -4, 0, 20), LayoutOrder = order }, expList)
    local hasKids = #inst:GetChildren() > 0
    local indent = depth * 12
    if hasKids then
        local arrow = mk("TextButton", {
            BackgroundTransparency = 1, Position = UDim2.fromOffset(indent, 0), Size = UDim2.fromOffset(18, 20),
            Text = expanded[inst] and "v" or ">", TextColor3 = C.dim, Font = Enum.Font.Code, TextSize = 12,
        }, holder)
        arrow.MouseButton1Click:Connect(function()
            expanded[inst] = not expanded[inst] or nil
            refreshTree()
        end)
    end
    local nameBtn = mk("TextButton", {
        BackgroundColor3 = (inst == selectedInst) and C.sel or C.panel, BorderSizePixel = 0,
        Position = UDim2.fromOffset(indent + 18, 0), Size = UDim2.new(1, -(indent + 18), 1, 0),
        Text = inst.Name .. "  <" .. inst.ClassName .. ">", TextColor3 = C.text, Font = Enum.Font.Code, TextSize = 12,
        TextXAlignment = Enum.TextXAlignment.Left, TextTruncate = Enum.TextTruncate.AtEnd, AutoButtonColor = false,
    }, holder)
    if inst == selectedInst then selectedInstRow = nameBtn end
    nameBtn.MouseButton1Click:Connect(function() selectInst(inst, nameBtn) end)
end

function refreshTree()
    local keepScroll = expList.CanvasPosition
    clearList(expList)
    selectedInstRow = nil
    local count = 0
    local query = expSearch.Text:lower()

    if query ~= "" then
        for _, d in ipairs(game:GetDescendants()) do
            if count >= 300 then break end
            if d.Name:lower():find(query, 1, true) or d.ClassName:lower():find(query, 1, true) then
                count = count + 1
                addTreeRow(d, 0, count)
            end
        end
    else
        local function walk(inst, depth)
            for _, c in ipairs(inst:GetChildren()) do
                if count >= MAX_ROWS then return end
                count = count + 1
                addTreeRow(c, depth, count)
                if expanded[c] then walk(c, depth + 1) end
            end
        end
        walk(game, 0)
    end
    expList.CanvasPosition = keepScroll
end

expSearch.FocusLost:Connect(function() refreshTree() end)

tbBtn(expBar, "Refresh", refreshTree)
tbBtn(expBar, "Path", function(b)
    if not selectedInst then return flash(b, "Select") end
    local p = getPath(selectedInst)
    if setclip then setclip(p) end
    setOut(p, "path")
    flash(b, "Copied")
end)
tbBtn(expBar, "Source", function(b)
    if not selectedInst then return flash(b, "Select") end
    if not decomp then return setOut("-- decompile is not supported by this executor") end
    if not selectedInst:IsA("LuaSourceContainer") then return flash(b, "No script") end
    local inst = selectedInst
    setOut("-- decompiling " .. inst.Name .. " ...")
    task.spawn(function()
        local ok, res = pcall(decomp, inst)
        setOut(ok and res or ("-- decompile failed: " .. safeToString(res)), "src_" .. inst.Name)
    end)
end)
tbBtn(expBar, "Funcs", function(b)
    if not selectedInst then return flash(b, "Select") end
    if not selectedInst:IsA("LuaSourceContainer") then return flash(b, "No script") end
    showTab("Functions")
    scanFunctions("", selectedInst)
end)
tbBtn(expBar, "Fold", function()
    table.clear(expanded)
    refreshTree()
end)

----------------------------------------------------------------------
-- Start
----------------------------------------------------------------------
local function yn(v) return v and "yes" or "NO " end
setOut(table.concat({
    "-- Delta Toolkit loaded",
    "executor : " .. ((identifyexecutor and select(1, identifyexecutor())) or "unknown"),
    "",
    "-- support",
    "  remote hook (hookmetamethod) : " .. yn(hookOk),
    "  getgc                        : " .. yn(getgc),
    "  debug.getconstants/upvalues  : " .. yn(dconsts and dupvals),
    "  decompile                    : " .. yn(decomp),
    "  hookfunction (Trace)         : " .. yn(hookfn),
    "  setclipboard                 : " .. yn(setclip),
    "  writefile (Save)             : " .. yn(writefile),
}, "\n"), "info")

showTab("Remotes")
refreshTree()

genv.DeltaToolkit = { Gui = gui }
