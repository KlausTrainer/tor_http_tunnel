-module(tor_http_tunnel).

%% public API
-export([start/0]).

%% intermodule exports
-export([get_app_env/1, get_app_env/2]).

start() ->
    ok = application:start(crypto),
    ok = application:start(asn1),
    ok = application:start(public_key),
    ok = application:start(ssl),
    ok = application:start(cowlib),
    ok = application:start(sasl),
    ok = application:start(?MODULE).

-spec get_app_env(atom()) -> term().
get_app_env(Opt) ->
    get_app_env(Opt, undefined).

-spec get_app_env(atom(), term()) -> term().
get_app_env(Opt, Default) ->
    case application:get_env(?MODULE, Opt) of
    {ok, Val} ->
        Val;
    _ ->
        case init:get_argument(Opt) of
        {ok, [[Val|_]]} -> Val;
        error -> Default
        end
    end.
