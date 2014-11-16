-module(tor_http_tunnel_sup).

-behaviour(supervisor).

%% public API
-export([start_link/0]).

%% supervisor callbacks
-export([init/1]).


%% public API

-spec start_link() -> {ok, pid()}.
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).


%% supervisor callbacks

init([]) ->
    PrivDir = code:priv_dir(tor_http_tunnel),

    {ok, HttpListenAddress} = inet:parse_address(
        tor_http_tunnel:get_app_env(http_listen_address)),
    HttpListenPort = tor_http_tunnel:get_app_env(http_listen_port),

    {ok, HttpsListenAddress} = inet:parse_address(
        tor_http_tunnel:get_app_env(https_listen_address)),
    HttpsListenPort = tor_http_tunnel:get_app_env(https_listen_port),

    RemoveCookies = lists:map(fun(Hostname) ->
        list_to_binary(string:to_lower(Hostname))
    end, tor_http_tunnel:get_app_env(remove_cookies, [])),

    RanchSupervisor = {
        ranch_sup,
        {ranch_sup, start_link, []},
        permanent, 5000, supervisor, [ranch_sup]
    },

    HttpSupervisor = ranch:child_spec(
        tor_http_tunnel,
        64,
        ranch_tcp, [
            {ip, HttpListenAddress},
            {port, HttpListenPort}
        ],
        tor_http_tunnel_protocol, RemoveCookies),

    HttpsSupervisor = ranch:child_spec(
        tor_https_tunnel,
        64,
        ranch_ssl, [
            {ip, HttpsListenAddress},
            {port, HttpsListenPort},
            {cacertfile, PrivDir ++ "/ssl/ca.pem"},
            {certfile, PrivDir ++ "/ssl/server.pem"},
            {keyfile, PrivDir ++ "/ssl/server.key"},
            {versions, ['tlsv1', 'tlsv1.1', 'tlsv1.2']},
            {secure_renegotiate, true},
            {reuse_sessions, true}
        ],
        tor_http_tunnel_protocol, RemoveCookies),

    Processes = [RanchSupervisor, HttpSupervisor, HttpsSupervisor],

    {ok, {{one_for_one, 5, 10}, Processes}}.
