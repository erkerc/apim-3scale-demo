--###################
local loggerclass = {}
loggerclass.new = function()

local concat                = table.concat
local tcp                   = ngx.socket.tcp
local udp                   = ngx.socket.udp
local timer_at              = ngx.timer.at
local ngx_log               = ngx.log
local ngx_sleep             = ngx.sleep
local type                  = type
local pairs                 = pairs
local tostring              = tostring
local debug                 = ngx.config.debug

local DEBUG                 = ngx.DEBUG
local CRIT                  = ngx.CRIT

local MAX_PORT              = 65535


-- table.new(narr, nrec)
local succ, new_tab = pcall(require, "table.new")
if not succ then
    new_tab = function () return {} end
end

local _M = new_tab(0, 5)cd 

local is_exiting

if not ngx.config or not ngx.config.ngx_lua_version
    or ngx.config.ngx_lua_version < 9003 then

    is_exiting = function() return false end

    ngx_log(CRIT, "We strongly recommend you to update your ngx_lua module to "
            .. "0.9.3 or above. lua-resty-logger-socket will lose some log "
            .. "messages when Nginx reloads if it works with ngx_lua module "
            .. "below 0.9.3")
else
    is_exiting = ngx.worker.exiting
end


_M._VERSION = '0.03'

-- user config
local flush_limit           = 4096         -- 4KB
local drop_limit            = 1048576      -- 1MB
local timeout               = 1000         -- 1 sec
local host
local port
local ssl                   = false
local ssl_verify            = true
local sni_host
local path
local max_buffer_reuse      = 10000        -- reuse buffer for at most 10000
                                           -- times
local periodic_flush        = nil
local need_periodic_flush   = nil
local sock_type             = 'tcp'

-- internal variables
local buffer_size           = 0
-- 2nd level buffer, it stores logs ready to be sent out
local send_buffer           = ""
-- 1st level buffer, it stores incoming logs
local log_buffer_data       = new_tab(20000, 0)
-- number of log lines in current 1st level buffer, starts from 0
local log_buffer_index      = 0

local last_error

local connecting
local connected
local exiting
local retry_connect         = 0
local retry_send            = 0
local max_retry_times       = 3
local retry_interval        = 100         -- 0.1s
local pool_size             = 10
local flushing
local logger_initted
local counter               = 0
local ssl_session

local function _write_error(msg)
    last_error = msg
end

local function _do_connect()
    local ok, err, sock

    if not connected then
        if (sock_type == 'udp') then
            sock, err = udp()
        else
            sock, err = tcp()
        end

        if not sock then
            _write_error(err)
            return nil, err
        end

        sock:settimeout(timeout)
    end

    -- "host"/"port" and "path" have already been checked in init()
    if host and port then
        if (sock_type == 'udp') then
            ok, err = sock:setpeername(host, port)
        else
            ok, err = sock:connect(host, port)
        end
    elseif path then
        ok, err = sock:connect("unix:" .. path)
    end

    if not ok then
        return nil, err
    end

    return sock
end

local function _do_handshake(sock)
    if not ssl then
        return sock
    end

    local session, err = sock:sslhandshake(ssl_session, sni_host or host, ssl_verify)
    if not session then
        return nil, err
    end

    ssl_session = session
    return sock
end

local function _connect()
    local err, sock

    if connecting then
        if debug then
            ngx_log(DEBUG, "previous connection not finished")
        end
        return nil, "previous connection not finished"
    end

    connected = false
    connecting = true

    retry_connect = 0

    while retry_connect <= max_retry_times do
        sock, err = _do_connect()

        if sock then
            sock, err = _do_handshake(sock)
            if sock then
                connected = true
                break
            end
        end

        if debug then
            ngx_log(DEBUG, "reconnect to the log server: ", err)
        end

        -- ngx.sleep time is in seconds
        if not exiting then
            ngx_sleep(retry_interval / 1000)
        end

        retry_connect = retry_connect + 1
    end

    connecting = false
    if not connected then
        return nil, "try to connect to the log server failed after "
                    .. max_retry_times .. " retries: " .. err
    end

    return sock
end

local function _prepare_stream_buffer()
    local packet = concat(log_buffer_data, "", 1, log_buffer_index)
    send_buffer = send_buffer .. packet

    log_buffer_index = 0
    counter = counter + 1
    if counter > max_buffer_reuse then
        log_buffer_data = new_tab(20000, 0)
        counter = 0
        if debug then
            ngx_log(DEBUG, "log buffer reuse limit (" .. max_buffer_reuse
                    .. ") reached, create a new \"log_buffer_data\"")
        end
    end
end

local function _do_flush()
    local ok, err, sock, bytes
    local packet = send_buffer

    sock, err = _connect()
    if not sock then
        return nil, err
    end

    bytes, err = sock:send(packet)
    if not bytes then
        -- "sock:send" always closes current connection on error
        return nil, err
    end

    if debug then
        ngx.update_time()
        ngx_log(DEBUG, ngx.now(), ":log flush:" .. bytes .. ":" .. packet)
    end

    if (sock_type ~= 'udp') then
        ok, err = sock:setkeepalive(0, pool_size)
        if not ok then
            return nil, err
        end
    end

    return bytes
end

local function _need_flush()
    if buffer_size > 0 then
        return true
    end

    return false
end

local function _flush_lock()
    if not flushing then
        if debug then
            ngx_log(DEBUG, "flush lock acquired")
        end
        flushing = true
        return true
    end
    return false
end

local function _flush_unlock()
    if debug then
        ngx_log(DEBUG, "flush lock released")
    end
    flushing = false
end

local function _flush()
    local err

    -- pre check
    if not _flush_lock() then
        if debug then
            ngx_log(DEBUG, "previous flush not finished")
        end
        -- do this later
        return true
    end

    if not _need_flush() then
        if debug then
            ngx_log(DEBUG, "no need to flush:", log_buffer_index)
        end
        _flush_unlock()
        return true
    end

    -- start flushing
    retry_send = 0
    if debug then
        ngx_log(DEBUG, "start flushing")
    end

    local bytes
    while retry_send <= max_retry_times do
        if log_buffer_index > 0 then
            _prepare_stream_buffer()
        end

        bytes, err = _do_flush()

        if bytes then
            break
        end

        if debug then
            ngx_log(DEBUG, "resend log messages to the log server: ", err)
        end

        -- ngx.sleep time is in seconds
        if not exiting then
            ngx_sleep(retry_interval / 1000)
        end

        retry_send = retry_send + 1
    end

    _flush_unlock()

    if not bytes then
        local err_msg = "try to send log messages to the log server "
                        .. "failed after " .. max_retry_times .. " retries: "
                        .. err
        _write_error(err_msg)
        return nil, err_msg
    else
        if debug then
            ngx_log(DEBUG, "send " .. bytes .. " bytes")
        end
    end

    buffer_size = buffer_size - #send_buffer
    send_buffer = ""

    return bytes
end

local function _periodic_flush(premature)
    if premature then
        exiting = true
    end

    if need_periodic_flush or exiting then
        -- no regular flush happened after periodic flush timer had been set
        if debug then
            ngx_log(DEBUG, "performing periodic flush")
        end
        _flush()
    else
        if debug then
            ngx_log(DEBUG, "no need to perform periodic flush: regular flush "
                    .. "happened before")
        end
        need_periodic_flush = true
    end

    timer_at(periodic_flush, _periodic_flush)
end

local function _flush_buffer()
    local ok, err = timer_at(0, _flush)

    need_periodic_flush = false

    if not ok then
        _write_error(err)
        return nil, err
    end
end

local function _write_buffer(msg, len)
    log_buffer_index = log_buffer_index + 1
    log_buffer_data[log_buffer_index] = msg

    buffer_size = buffer_size + len


    return buffer_size
end

function _M.init(user_config)
    if (type(user_config) ~= "table") then
        return nil, "user_config must be a table"
    end

    for k, v in pairs(user_config) do
        if k == "host" then
            if type(v) ~= "string" then
                return nil, '"host" must be a string'
            end
            host = v
        elseif k == "port" then
            if type(v) ~= "number" then
                return nil, '"port" must be a number'
            end
            if v < 0 or v > MAX_PORT then
                return nil, ('"port" out of range 0~%s'):format(MAX_PORT)
            end
            port = v
        elseif k == "path" then
            if type(v) ~= "string" then
                return nil, '"path" must be a string'
            end
            path = v
        elseif k == "sock_type" then
            if type(v) ~= "string" then
                return nil, '"sock_type" must be a string'
            end
            if v ~= "tcp" and v ~= "udp" then
                return nil, '"sock_type" must be "tcp" or "udp"'
            end
            sock_type = v
        elseif k == "flush_limit" then
            if type(v) ~= "number" or v < 0 then
                return nil, 'invalid "flush_limit"'
            end
            flush_limit = v
        elseif k == "drop_limit" then
            if type(v) ~= "number" or v < 0 then
                return nil, 'invalid "drop_limit"'
            end
            drop_limit = v
        elseif k == "timeout" then
            if type(v) ~= "number" or v < 0 then
                return nil, 'invalid "timeout"'
            end
            timeout = v
        elseif k == "max_retry_times" then
            if type(v) ~= "number" or v < 0 then
                return nil, 'invalid "max_retry_times"'
            end
            max_retry_times = v
        elseif k == "retry_interval" then
            if type(v) ~= "number" or v < 0 then
                return nil, 'invalid "retry_interval"'
            end
            -- ngx.sleep time is in seconds
            retry_interval = v
        elseif k == "pool_size" then
            if type(v) ~= "number" or v < 0 then
                return nil, 'invalid "pool_size"'
            end
            pool_size = v
        elseif k == "max_buffer_reuse" then
            if type(v) ~= "number" or v < 0 then
                return nil, 'invalid "max_buffer_reuse"'
            end
            max_buffer_reuse = v
        elseif k == "periodic_flush" then
            if type(v) ~= "number" or v < 0 then
                return nil, 'invalid "periodic_flush"'
            end
            periodic_flush = v
        elseif k == "ssl" then
            if type(v) ~= "boolean" then
                return nil, '"ssl" must be a boolean value'
            end
            ssl = v
        elseif k == "ssl_verify" then
            if type(v) ~= "boolean" then
                return nil, '"ssl_verify" must be a boolean value'
            end
            ssl_verify = v
        elseif k == "sni_host" then
            if type(v) ~= "string" then
                return nil, '"sni_host" must be a string'
            end
            sni_host = v
        end
    end

    if not (host and port) and not path then
        return nil, "no logging server configured. \"host\"/\"port\" or "
                .. "\"path\" is required."
    end


    if (flush_limit >= drop_limit) then
        return nil, "\"flush_limit\" should be < \"drop_limit\""
    end

    flushing = false
    exiting = false
    connecting = false

    connected = false
    retry_connect = 0
    retry_send = 0

    logger_initted = true

    if periodic_flush then
        if debug then
            ngx_log(DEBUG, "periodic flush enabled for every "
                    .. periodic_flush .. " seconds")
        end
        need_periodic_flush = true
        timer_at(periodic_flush, _periodic_flush)
    end

    return logger_initted
end

function _M.log(msg)
    if not logger_initted then
        return nil, "not initialized"
    end

    local bytes

    if type(msg) ~= "string" then
        msg = tostring(msg)
    end

    local msg_len = #msg

    if (debug) then
        ngx.update_time()
        ngx_log(DEBUG, ngx.now(), ":log message length: " .. msg_len)
    end

    -- response of "_flush_buffer" is not checked, because it writes
    -- error buffer
    if (is_exiting()) then
        exiting = true
        _write_buffer(msg, msg_len)
        _flush_buffer()
        if (debug) then
            ngx_log(DEBUG, "Nginx worker is exiting")
        end
        bytes = 0
    elseif (msg_len + buffer_size < flush_limit) then
        _write_buffer(msg, msg_len)
        bytes = msg_len
    elseif (msg_len + buffer_size <= drop_limit) then
        _write_buffer(msg, msg_len)
        _flush_buffer()
        bytes = msg_len
    else
        _flush_buffer()
        if (debug) then
            ngx_log(DEBUG, "logger buffer is full, this log message will be "
                    .. "dropped")
        end
        bytes = 0
        --- this log message doesn't fit in buffer, drop it
    end

    if last_error then
        local err = last_error
        last_error = nil
        return bytes, err
    end

    return bytes
end

function _M.initted()
    return logger_initted
end

_M.flush = _flush

return _M
end

--###################
local apicast = require('apicast').new()
local logger = loggerclass.new()
--local logger = {}
local cjson = require('cjson')

local setmetatable = setmetatable

local _M = require('apicast.policy').new('thy-custom-policy-logging', '0.1')

local mt = { __index = _M }

function _M.new()
  return setmetatable({}, mt)
end

local host
local port
local proto
local flush_limit
local drop_limit

function _M:init()
  host = os.getenv('SYSLOG_HOST')
  port = os.getenv('SYSLOG_PORT')
  proto = os.getenv('SYSLOG_PROTOCOL') or 'tcp'
  base64_flag = os.getenv('APICAST_PAYLOAD_BASE64') or 'true'
  flush_limit = os.getenv('SYSLOG_FLUSH_LIMIT') or '0'
  periodic_flush = os.getenv('SYSLOG_PERIODIC_FLUSH') or '5'
  drop_limit = os.getenv('SYSLOG_DROP_LIMIT') or '1048576'

  port = tonumber(port)
  flush_limit = tonumber(flush_limit)
  drop_limit = tonumber(drop_limit)
  periodic_flush = tonumber(periodic_flush)

  
  
  return apicast:init()
end

function _M:init_worker()
  ngx.log(ngx.INFO, "Initializing the underlying logger")
  if not logger.initted() then
      -- default parameters
      local params = {
          host = host,
          port = port,
          sock_type = proto,
          flush_limit = flush_limit,
          drop_limit = drop_limit
      }

      -- periodic_flush == 0 means 'disable this feature'
      if periodic_flush > 0 then
        params["periodic_flush"] = periodic_flush
      end

 
  end

  return apicast:init_worker()
end

function do_log(payload)
  -- construct the custom access log message in
  -- the Lua variable "msg"
  --
  -- do not forget the \n in order to have one request per line on the syslog server
  --
  
  ngx.log(ngx.WARN, " PAYLOAD: " .. payload)
end

function _M:rewrite()
  -- change the request before it reaches upstream
    ngx.req.set_header('X-CustomPolicy', 'customValue')
end

function _M:access()
  -- ability to deny the request before it is sent upstream
end

function _M:content()
  -- can create content instead of connecting to upstream
end

function _M:post_action()
  -- do something after the response was sent to the client
end

function _M:header_filter()
  -- can change response headers
end

function _M.body_filter()
  ngx.ctx.buffered = (ngx.ctx.buffered or "") .. ngx.arg[1]

  if ngx.arg[2] then -- EOF
    local dict = {}

    -- Gather information of the request
    local request = {}
    if ngx.var.request_body then
      if (base64_flag == 'true') then
        request["body"] = ngx.encode_base64(ngx.var.request_body)
      else
        request["body"] = ngx.var.request_body
      end
    end
    request["headers"] = ngx.req.get_headers()
    request["start_time"] = ngx.req.start_time()
    request["http_version"] = ngx.req.http_version()
    if (base64_flag == 'true') then
      request["raw"] = ngx.encode_base64(ngx.req.raw_header())
    else
      request["raw"] = ngx.req.raw_header()
    end

    request["method"] = ngx.req.get_method()
    request["uri_args"] = ngx.req.get_uri_args()
    request["request_id"] = ngx.var.request_id
    dict["request"] = request

    -- Gather information of the response
    local response = {}
    if ngx.ctx.buffered then
      if (base64_flag == 'true') then
        response["body"] = ngx.encode_base64(ngx.ctx.buffered)
      else
        response["body"] = ngx.ctx.buffered
      end
    end
    response["headers"] = ngx.resp.get_headers()
    response["status"] = ngx.status
    dict["response"] = response

    -- timing stats
    local upstream = {}
    upstream["addr"] = ngx.var.upstream_addr
    upstream["bytes_received"] = ngx.var.upstream_bytes_received
    upstream["cache_status"] = ngx.var.upstream_cache_status
    upstream["connect_time"] = ngx.var.upstream_connect_time
    upstream["header_time"] = ngx.var.upstream_header_time
    upstream["response_length"] = ngx.var.upstream_response_length
    upstream["response_time"] = ngx.var.upstream_response_time
    upstream["status"] = ngx.var.upstream_status
    dict["upstream"] = upstream

    do_log(cjson.encode(dict))
  end
  return apicast:body_filter()
end

function _M:log()
  -- can do extra logging
end

function _M:balancer()
  -- use for example require('resty.balancer.round_robin').call to do load balancing
end

return _M