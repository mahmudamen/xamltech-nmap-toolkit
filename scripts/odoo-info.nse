local http = require "http"
local json = require "json"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Detects an Odoo ERP web server and performs read-only exposure checks.

Checks (all unauthenticated, read-only, no credentials are sent):
  * /web/webclient/version_info  -> Odoo version and series
  * /web/database/list           -> is the database list public? (list_db)
  * /web/database/manager        -> is the database manager page reachable?

Nothing is created, modified or deleted. Database names are NOT printed unless
you opt in with the script argument odoo-info.showdbs=true.

Part of the XamlTech Nmap Toolkit (https://xamltech.com).
]]

---
-- @usage
-- nmap -p 8069 --script ./scripts/odoo-info.nse <target>
-- nmap -p 443  --script ./scripts/odoo-info.nse --script-args odoo-info.showdbs=true <target>
--
-- @output
-- PORT     STATE SERVICE
-- 8069/tcp open  http
-- | odoo-info:
-- |   version: 17.0
-- |   series: 17.0
-- |   transport: http
-- |   database_listing: exposed (3 database(s))
-- |_  database_manager: exposed (/web/database/manager is reachable)
--
-- @args odoo-info.showdbs  Print database names when the list is public (default: false).

author = "Mahmoud Mohamed Amin <https://xamltech.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "discovery", "safe" }

portrule = function(host, port)
  if shortport.http(host, port) then return true end
  return shortport.port_or_service({ 8069, 8071, 8072 }, { "unknown" })(host, port)
end

local RPC_BODY = '{"jsonrpc":"2.0","method":"call","params":{},"id":%d}'
local JSON_HEADERS = { ["Content-Type"] = "application/json" }

--- POST an empty JSON-RPC call and return the decoded table (or nil)
local function rpc(host, port, path, id)
  local resp = http.post(host, port, path, { header = JSON_HEADERS, no_cache = true },
    nil, string.format(RPC_BODY, id))
  if not resp or resp.status ~= 200 or not resp.body then return nil, resp end
  local ok, data = json.parse(resp.body)
  if not ok or type(data) ~= "table" then return nil, resp end
  return data, resp
end

action = function(host, port)
  local out = stdnse.output_table()
  local found = false

  -- 1. version ------------------------------------------------------------
  local data = rpc(host, port, "/web/webclient/version_info", 1)
  if data and type(data.result) == "table" and data.result.server_version then
    found = true
    out.version = tostring(data.result.server_version)
    if data.result.server_serie then out.series = tostring(data.result.server_serie) end
  else
    -- fall back to a login-page fingerprint
    local resp = http.get(host, port, "/web/login", { no_cache = true })
    if resp and resp.status == 200 and resp.body
        and (resp.body:find("/web/static/", 1, true) or resp.body:lower():find("odoo", 1, true)) then
      found = true
      out.version = "unknown (login page fingerprint)"
    end
  end
  if not found then return nil end -- not Odoo: stay silent

  out.transport = (port.version and port.version.service_tunnel == "ssl") and "https" or "http"

  -- 2. database listing ------------------------------------------------------
  local dbs = rpc(host, port, "/web/database/list", 2)
  if dbs and type(dbs.result) == "table" then
    local n = #dbs.result
    out.database_listing = string.format("exposed (%d database(s))", n)
    if stdnse.get_script_args("odoo-info.showdbs") == "true" and n > 0 then
      local names = {}
      for _, name in ipairs(dbs.result) do names[#names + 1] = tostring(name) end
      out.databases = table.concat(names, ", ")
    end
  elseif dbs and dbs.error then
    out.database_listing = "disabled"
  else
    out.database_listing = "not available"
  end

  -- 3. database manager page ---------------------------------------------------
  local mgr = http.get(host, port, "/web/database/manager", { no_cache = true })
  if mgr and mgr.status == 200 and mgr.body
      and (mgr.body:find("o_database_list", 1, true) or mgr.body:find("Master Password", 1, true)
        or mgr.body:find("Database Manager", 1, true)) then
    out.database_manager = "exposed (/web/database/manager is reachable)"
  else
    out.database_manager = "not exposed"
  end

  return out
end
