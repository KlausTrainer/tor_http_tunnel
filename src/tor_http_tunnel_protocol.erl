-module(tor_http_tunnel_protocol).

-behaviour(ranch_protocol).

%% public API
-export([start_link/4, init/4]).

-define(RECEIVE_TIMEOUT, 8000).

-define(SSL_OPTIONS, [
    {versions, ['tlsv1', 'tlsv1.1', 'tlsv1.2']},
    {secure_renegotiate, true},
    {reuse_sessions, true}
]).


start_link(Ref, Socket, Transport, RemoveCookies) when Transport =:= ranch_tcp; Transport =:= ranch_ssl ->
	Pid = spawn_link(?MODULE, init, [Ref, Socket, Transport, RemoveCookies]),
	{ok, Pid}.

init(Ref, Socket, Transport, RemoveCookies) when Transport =:= ranch_tcp; Transport =:= ranch_ssl ->
	ok = ranch:accept_ack(Ref),
	loop(Socket, Transport, RemoveCookies).


%% internal API

loop(Socket, Transport, RemoveCookies) ->
    Result = try
        ResponseData = handle_request(Socket, Transport, RemoveCookies),
        Transport:send(Socket, ResponseData)
    catch error:Reason ->
        {error, Reason}
    end,
    % This is necessary to keep this tail-recursive. Calling `loop/3` in
    % the catch clause would turn it into a body recursive call.
    case Result of
    {error, _} ->
        Transport:close(Socket);
    ok ->
        loop(Socket, Transport, RemoveCookies)
    end.

handle_request(Socket, Transport, RemoveCookies) ->
    {ok, RequestHeaders, RequestData} = do_receive(Socket, Transport),
    {Hostname, Port} = parse_host(RequestHeaders, Transport),
    {ok, ProxySocket} = tor_http_tunnel_socks5:connect(Hostname, Port),
    case lists:member(Hostname, RemoveCookies) of
    true ->
        RequestData2 = remove_cookies(RequestHeaders, RequestData),
        proxy_request(ProxySocket, Transport, RequestData2);
    false ->
        proxy_request(ProxySocket, Transport, RequestData)
    end.

do_receive(Socket, Transport) ->
    {ok, SomeData} = Transport:recv(Socket, 0, ?RECEIVE_TIMEOUT),
    [_, HeadersAndBody] = binary:split(SomeData, <<"\r\n">>),
    {Headers, BodyPart} = cow_http:parse_headers(HeadersAndBody),
    case proplists:get_value(<<"transfer-encoding">>, Headers) of
    <<"chunked">> ->
        [StatusLineAndHeaders, _] = binary:split(SomeData, <<"\r\n\r\n">>),
        {ok, FullBody} = receive_chunks(Socket, Transport, BodyPart),
        {ok, Headers, [StatusLineAndHeaders, <<"\r\n\r\n">>, FullBody]};
    _ ->
        case proplists:get_value(<<"content-length">>, Headers) of
        undefined ->
            {ok, Headers, SomeData};
        ContentLengthHeaderValue ->
            ContentLength = list_to_integer(
                binary_to_list(ContentLengthHeaderValue)),
            case ContentLength - byte_size(BodyPart) of
            BytesLeft when BytesLeft > 0 ->
                {ok, SomeMoreData} = Transport:recv(Socket, BytesLeft, ?RECEIVE_TIMEOUT),
                {ok, Headers, [SomeData, SomeMoreData]};
            _ ->
                {ok, Headers, SomeData}
            end
        end
    end.

receive_chunks(Socket, Transport, Data) ->
    receive_chunks(Socket, Transport, Data, [], {0, 0}).

receive_chunks(Socket, Transport, Data, Buffer, State) ->
	case cow_http_te:stream_chunked(Data, State) of
    more ->
        {ok, MoreData} = Transport:recv(Socket, 0, ?RECEIVE_TIMEOUT),
        receive_chunks(Socket, Transport, <<Data/binary,MoreData/binary>>, Buffer, State);
    {more, _Chunk, NewState} ->
        {ok, MoreData} = Transport:recv(Socket, 0, ?RECEIVE_TIMEOUT),
        receive_chunks(Socket, Transport, MoreData, [Data|Buffer], NewState);
    {more, _Chunk, Length, NewState} when is_integer(Length) ->
        {ok, MoreData} = Transport:recv(Socket, Length, ?RECEIVE_TIMEOUT),
        receive_chunks(Socket, Transport, MoreData, [Data|Buffer], NewState);
    {more, _Chunk, Rest, NewState} ->
        {ok, MoreData} = Transport:recv(Socket, 0, ?RECEIVE_TIMEOUT),
        receive_chunks(Socket, Transport, <<Rest/binary,MoreData/binary>>, Buffer, NewState);
    {done, _TotalLength, _Rest} ->
        {ok, lists:reverse([Data|Buffer])};
    {done, _Chunk, _TotalLength, _Rest} ->
        {ok, lists:reverse([Data|Buffer])}
	end.

proxy_request(Socket, ranch_tcp, RequestData) ->
    ok = gen_tcp:send(Socket, RequestData),
    {ok, _ResponseHeaders, ResponseData} = do_receive(Socket, gen_tcp),
    ResponseData;
proxy_request(Socket, ranch_ssl, RequestData) ->
    {ok, TlsSocket} = ssl:connect(Socket, ?SSL_OPTIONS),
    ok = ssl:send(TlsSocket, RequestData),
    {ok, _ResponseHeaders, ResponseData} = do_receive(TlsSocket, ssl),
    ResponseData.

parse_host(RequestHeaders, Transport) ->
    HostHeaderValue = proplists:get_value(<<"host">>, RequestHeaders),
    case cow_http:parse_fullhost(HostHeaderValue) of
    {Hostname, undefined} when Transport =:= ranch_tcp -> {Hostname, 80};
    {Hostname, undefined} when Transport =:= ranch_ssl -> {Hostname, 443};
    {Hostname, Port} -> {Hostname, Port}
    end.

remove_cookies(RequestHeaders, RequestData) ->
    case proplists:delete(<<"cookie">>, RequestHeaders) of
    RequestHeaders2 when RequestHeaders2 =/= RequestHeaders ->
        [StatusLine, RawHeadersAndBody] = binary:split(RequestData, <<"\r\n">>),
        [_RawHeaders, Body] = binary:split(RawHeadersAndBody, <<"\r\n\r\n">>),
        RawHeaders2 = lists:map(fun({HeaderName, HeaderValue}) ->
            [HeaderName,<<": ">>,HeaderValue,<<"\r\n">>]
        end, RequestHeaders2),
        [StatusLine,<<"\r\n">>,RawHeaders2,<<"\r\n">>,Body];
    _ ->
        RequestData
    end.
