-module(routes_v1_server).

%% this file was generated by grpc

-include("../../include/sibyl.hrl").

-export([
    decoder/0,
    get_routes/3,
    stream_route_updates/3
]).

-type 'Empty'() :: #{}.

-type routing_v1() :: #{
    oui => integer(),
    owner => binary(),
    router_addresses => [binary()],
    filters => [binary()],
    subnets => [binary()]
}.

-type routing_v1_response() :: #{
    routes => [routing_v1()],
    signature => binary(),
    height => integer()
}.

-type routing_v1_update() :: #{
    routes => [routing_v1()],
    signature => binary(),
    height => integer(),
    action => binary()
}.

-spec decoder() -> module().
%% The module (generated by gpb) used to encode and decode protobuf
%% messages.
decoder() -> routes_v1.

%% RPCs for service routes_v1

-spec get_routes(Message :: 'Empty'(), Stream :: grpc:stream(), State :: any()) ->
    {routing_v1_response(), grpc:stream()} | grpc:error_response().
%% This is a unary RPC
get_routes(_Message, Stream, _State) ->
    %% get our chain and only handle the request if the chain is up
    % if chain not up we have no way to get routing data so just return a 503/14
    Chain = sibyl_mgr:blockchain(),
    case is_chain_ready(Chain) of
        false ->
            {error, 14, <<"temporarily unavavailable">>, Stream};
        true ->
            %% get the route data
            %% get the route data
            Ledger = blockchain:ledger(Chain),
            {ok, CurHeight} = blockchain_ledger_v1:current_height(Ledger),
            case blockchain_ledger_v1:get_routes(Ledger) of
                {ok, Routes} ->
                    RoutesPB = encode_response(Routes, CurHeight, sibyl_mgr:sigfun()),
                    {RoutesPB, Stream};
                {error, Reason} ->
                    {error, 2, Reason, Stream}
            end
    end.

-spec stream_route_updates(Message :: 'Empty'(), Stream :: grpc:stream(), State :: any()) ->
    {[routing_v1_update()], grpc:stream()} | grpc:error_response().
%% This is a server-to-client streaming RPC
stream_route_updates(_Message, Stream, _State) ->
    %% get our chain and only handle the request if the chain is up
    % if chain not up we have no way to return routing data so just return a 503
    Chain = sibyl_mgr:blockchain(),
    case is_chain_ready(Chain) of
        false ->
            {error, 14, <<"temporarily unavavailable">>, Stream};
        true ->
            {ok, _WorkerPid} = route_updates_sup:start_route_stream_worker(Stream),
            lager:debug("started route update worker pid ~p", [_WorkerPid]),
            {continue, Stream, _State}
    end.

%% ------------------------------------------------------------------
%% Internal functions
%% ------------------------------------------------------------------

-spec encode_response([blockchain_ledger_routing_v1:routing()], non_neg_integer(), function()) ->
    routing_v1_response().
encode_response(Routes, Height, SigFun) ->
    RoutingInfo = [to_routing_pb(R) || R <- Routes],
    Resp = #{
        routes => RoutingInfo,
        height => Height
    },
    EncodedRoutingInfoBin = routes_v1:encode_msg(Resp, routing_v1_response),
    Resp#{signature => SigFun(EncodedRoutingInfoBin)}.

-spec to_routing_pb(blockchain_ledger_routing_v1:routing()) -> routing_v1().
to_routing_pb(Route) ->
    #{
        oui => blockchain_ledger_routing_v1:oui(Route),
        owner => blockchain_ledger_routing_v1:owner(Route),
        router_addresses => blockchain_ledger_routing_v1:addresses(Route),
        filters => blockchain_ledger_routing_v1:filters(Route),
        subnets => blockchain_ledger_routing_v1:subnets(Route)
    }.

-spec is_chain_ready(undefined | blockchain:blockchain()) -> boolean().
is_chain_ready(undefined) ->
    false;
is_chain_ready(_Chain) ->
    true.
