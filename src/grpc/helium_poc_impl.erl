-module(helium_poc_impl).

-include("../../include/sibyl.hrl").
-include("../grpc/autogen/server/gateway_pb.hrl").

-record(handler_state, {
    streaming_initialized = false :: boolean()
}).

-export([
    init/2,
    handle_info/2
]).

-export([
    pocs/2,
    check_challenge_target/2,
    send_report/2
]).

%% ------------------------------------------------------------------
%% helium_gateway_state_channels_bhvr callbacks
%% ------------------------------------------------------------------
-spec init(atom(), grpcbox_stream:t()) -> grpcbox_stream:t().
init(_RPC, StreamState) ->
    lager:info("handler init, stream state ~p", [StreamState]),
    NewStreamState = grpcbox_stream:stream_handler_state(
        StreamState,
        #handler_state{}
    ),
    NewStreamState.

-spec check_challenge_target(
    ctx:ctx(),
    gateway_pb:gateway_poc_check_challenge_target_req_v1_pb()
) -> {ok, gateway_pb:gateway_resp_v1(), ctx:ctx()} | grpcbox_stream:grpc_error_response().
check_challenge_target(Ctx, #gateway_poc_check_challenge_target_req_v1_pb{} = Message) ->
    Chain = sibyl_mgr:blockchain(),
    check_challenge_target(Chain, Ctx, Message).

-spec send_report(
    ctx:ctx(),
    gateway_pb:gateway_poc_report_req_v1_pb()
) -> {ok, gateway_pb:gateway_resp_v1(), ctx:ctx()} | grpcbox_stream:grpc_error_response().
send_report(Ctx, #gateway_poc_report_req_v1_pb{} = Message) ->
    Chain = sibyl_mgr:blockchain(),
    send_report(Chain, Ctx, Message).

-spec pocs(
    gateway_pb:gateway_poc_req_v1(),
    grpcbox_stream:t()
) -> {ok, grpcbox_stream:t()} | grpcbox_stream:grpc_error_response().
pocs(#gateway_poc_req_v1_pb{} = Msg, StreamState) ->
    Chain = sibyl_mgr:blockchain(),
    HandlerState = grpcbox_stream:stream_handler_state(StreamState),
    StreamState0 = maybe_init_stream_state(HandlerState, StreamState),
    #handler_state{streaming_initialized = IsAlreadyStreamingPOCs} = grpcbox_stream:stream_handler_state(
        StreamState0
    ),
    pocs(Chain, IsAlreadyStreamingPOCs, Msg, StreamState0).

-spec handle_info(sibyl_mgr:event() | any(), grpcbox_stream:t()) -> grpcbox_stream:t().
handle_info(
    {event, _EventTopic, _Payload} = Event,
    StreamState
) ->
    lager:debug("received event ~p", [Event]),
    NewStreamState = handle_event(Event, StreamState),
    NewStreamState;
handle_info(
    _Msg,
    StreamState
) ->
    lager:warning("unhandled info msg: ~p", [_Msg]),
    StreamState.

%% ------------------------------------------------------------------
%% callback breakout functions
%% ------------------------------------------------------------------

-spec check_challenge_target(
    undefined | blockchain:blockchain(),
    ctx:ctx(),
    gateway_pb:gateway_poc_check_challenge_target_req_v1_pb()
) -> {ok, gateway_pb:gateway_resp_v1_pb(), ctx:ctx()} | grpcbox_stream:grpc_error_response().
check_challenge_target(
    undefined = _Chain,
    _Ctx,
    #gateway_poc_check_challenge_target_req_v1_pb{} = _Msg
) ->
    lager:info("chain not ready, returning error response for msg ~p", [_Msg]),
    {grpc_error, {grpcbox_stream:code_to_status(14), <<"temporarily unavailable">>}};
check_challenge_target(
    Chain,
    Ctx,
    #gateway_poc_check_challenge_target_req_v1_pb{
        address = ChallengeePubKeyBin,
        challenger = _ChallengerPubKeyBin,
        height = _ChallengeHeight,
        block_hash = BlockHash,
        onion_key_hash = POCKey,
        notifier = _Notifier,
        challengee_sig = Signature
    } = Request
) ->
    lager:info("executing RPC check_challenge_target with msg ~p", [Request]),
    Ledger = blockchain:ledger(Chain),
    CurHeight = blockchain_ledger_v1:current_height(Ledger),

    %% verify the signature of the request
    BaseReq = Request#gateway_poc_check_challenge_target_req_v1_pb{challengee_sig = <<>>},
    EncodedReq = gateway_poc_check_challenge_target_req_v1_pb:encode_msg(BaseReq),
    case libp2p_crypto:verify(EncodedReq, Signature, ChallengeePubKeyBin) of
        false ->
            {grpc_error, {grpcbox_stream:code_to_status(14), <<"bad signature">>}};
        true ->
            %% are we the target  ?
            case blockchain_poc_mgr:check_target(ChallengeePubKeyBin, BlockHash, POCKey, Chain) of
                {error, Reason} ->
                    %% something went wrong, return error
                    {grpc_error, {grpcbox_stream:code_to_status(14), Reason}};
                false ->
                    %% nope, we are not the target
                    Response0 = #gateway_poc_check_challenge_target_resp_v1_pb{
                        target = false,
                        onion = undefined
                    },
                    Response1 = sibyl_utils:encode_gateway_resp_v1(
                        Response0,
                        CurHeight,
                        sibyl_mgr:sigfun()
                    ),
                    {ok, Response1, Ctx};
                {true, Onion} ->
                    %% we are the target, return the onion
                    Response0 = #gateway_poc_check_challenge_target_resp_v1_pb{
                        target = true,
                        onion = Onion
                    },
                    Response1 = sibyl_utils:encode_gateway_resp_v1(
                        Response0,
                        CurHeight,
                        sibyl_mgr:sigfun()
                    ),
                    {ok, Response1, Ctx}
            end
    end.

-spec send_report(
    undefined | blockchain:blockchain(),
    ctx:ctx(),
    gateway_pb:gateway_poc_report_req_v1_pb()
) -> {ok, gateway_pb:gateway_resp_v1_pb(), ctx:ctx()} | grpcbox_stream:grpc_error_response().
send_report(undefined = _Chain, _Ctx, #gateway_poc_report_req_v1_pb{} = _Msg) ->
    lager:info("chain not ready, returning error response for msg ~p", [_Msg]),
    {grpc_error, {grpcbox_stream:code_to_status(14), <<"temporarily unavailable">>}};
send_report(
    Chain,
    Ctx,
    #gateway_poc_report_req_v1_pb{msg = Report, onion_key_hash = OnionKeyHash} = _Message
) ->
    lager:info("executing RPC send_report with msg ~p", [_Message]),
    Chain = sibyl_mgr:blockchain(),
    Ledger = blockchain:ledger(Chain),
    CurHeight = blockchain_ledger_v1:current_height(Ledger),
    %% find the POC in the ledger using onionkeyhash as key
    RespPB =
        case blockchain_ledger_v1:find_poc(OnionKeyHash, Ledger) of
            {ok, PoCs} ->
                %% clients send POC reports to their usual validator
                %% we now need to route those reports to the challenger over p2p
                %% clients cannot send a report directly to the challenger as in the case
                %% of a witness report, it has no data on who the challenger is
                lists:foreach(
                    fun(PoC) ->
                        spawn_link(fun() -> send_poc_report(OnionKeyHash, PoC, Report) end)
                    end,
                    PoCs
                ),
                #gateway_success_resp_pb{resp = <<"ok">>, details = <<>>};
            _ ->
                #gateway_error_resp_pb{error = <<"invalid onion key hash">>, details = OnionKeyHash}
        end,
    Resp = sibyl_utils:encode_gateway_resp_v1(
        RespPB,
        CurHeight,
        sibyl_mgr:sigfun()
    ),
    {ok, Resp, Ctx}.

-spec pocs(
    blockchain:blockchain(),
    boolean(),
    gateway_pb:gateway_poc_req_v1_pb(),
    grpcbox_stream:t()
) -> {ok, grpcbox_stream:t()} | grpcbox_stream:grpc_error_response().
pocs(
    undefined = _Chain,
    _IsAlreadyStreamingPOCs,
    #gateway_poc_req_v1_pb{} = _Msg,
    _StreamState
) ->
    %% if chain not up we have no way to retrieve data so just return a 14/503
    lager:info("chain not ready, returning error response for msg ~p", [_Msg]),
    {grpc_error, {grpcbox_stream:code_to_status(14), <<"temporarily unavailable">>}};
pocs(
    _Chain,
    true = _IsAlreadyStreamingPOCs,
    #gateway_poc_req_v1_pb{} = _Msg,
    StreamState
) ->
    %% we are already streaming POCs so do nothing further here
    {ok, StreamState};
pocs(
    _Chain,
    false = _IsAlreadyStreamingPOCs,
    #gateway_poc_req_v1_pb{address = Addr, signature = Sig} = Msg,
    StreamState
) ->
    %% start a POC stream
    %% confirm the sig is valid
    PubKey = libp2p_crypto:bin_to_pubkey(Addr),
    BaseReq = Msg#gateway_poc_req_v1_pb{signature = <<>>},
    EncodedReq = gateway_pb:encode_msg(BaseReq),
    case libp2p_crypto:verify(EncodedReq, Sig, PubKey) of
        false ->
            {grpc_error, {grpcbox_stream:code_to_status(14), <<"bad signature">>}};
        true ->
            %% topic key for POC streams is the pub key bin
            %% streamed msgs will be received & published by the sibyl_poc_mgr
            %% streamed POC msgs will be potential challenge notifications
            Topic = sibyl_utils:make_poc_topic(Addr),
            lager:info("subscribing to poc events for gw ~p", [Addr]),
            ok = sibyl_bus:sub(Topic, self()),
            NewStreamState = grpcbox_stream:stream_handler_state(
                StreamState,
                #handler_state{
                    streaming_initialized = true
                }
            ),
            {ok, NewStreamState}
    end.

%% ------------------------------------------------------------------
%% Internal functions
%% ------------------------------------------------------------------
-spec handle_event(sibyl_mgr:event(), grpcbox_stream:t()) -> grpcbox_stream:t().
handle_event(
    {event, ?EVENT_POC_NOTIFICATION, Payload} = _Event,
    StreamState
) ->
    %% received a poc notification event, we simply have to forward this unmodified to the client
    %% the payload is fully formed and encoded
    lager:debug("handling poc notification event with payload:  ~p", [
        Payload
    ]),
    NewStream = grpcbox_stream:send(false, Payload, StreamState),
    NewStream;
handle_event(
    {event, _EventType, _Payload} = _Event,
    StreamState
) ->
    lager:warning("received unhandled event ~p", [_Event]),
    StreamState.

send_poc_report(OnionKeyHash, POC, Report) ->
    send_poc_report(OnionKeyHash, POC, Report, 30).
send_poc_report(OnionKeyHash, POC, Report, Retries) when Retries > 0 ->
    Challenger = blockchain_ledger_poc_v2:challenger(POC),
    SelfPubKeyBin = blockchain_swarm:pubkey_bin(),
    P2PAddr = libp2p_crypto:pubkey_bin_to_p2p(Challenger),
    case SelfPubKeyBin =:= Challenger of
        true ->
            lager:info("challenger is ourself so sending directly to poc statem"),
            case blockchain_poc_report_handler:decode(Report) of
                {witness, Witness} ->
                    blockchain_poc_mgr:witness(SelfPubKeyBin, OnionKeyHash, Witness);
                {receipt, Receipt} ->
                    blockchain_poc_mgr:receipt(SelfPubKeyBin, OnionKeyHash, Receipt, P2PAddr);
                {error, _Reason} ->
                    noop
            end;
        false ->
            case miner_poc:dial_framed_stream(blockchain_swarm:swarm(), P2PAddr, []) of
                {error, _Reason} ->
                    %% TODO add a retry attempt limit
                    lager:error(
                        "failed to dial challenger ~p (~p).  Will try agai in 30 seconds",
                        [P2PAddr, _Reason]
                    ),
                    timer:sleep(timer:seconds(30)),
                    send_poc_report(OnionKeyHash, POC, Report, Retries - 1);
                {ok, P2PStream} ->
                    _ = blockchain_poc_report_handler:send(P2PStream, {OnionKeyHash, Report}),
                    ok
            end
    end;
send_poc_report(OnionKeyHash, _POC, _Report, _Retries) ->
    lager:warning("failed to dial challenger, max retry, POC: ~p", [OnionKeyHash]),
    ok.

-spec maybe_init_stream_state(undefined | #handler_state{}, grpcbox_stream:t()) ->
    grpcbox_stream:t().
maybe_init_stream_state(undefined, StreamState) ->
    lager:debug("handler init, stream state ~p", [StreamState]),
    NewStreamState = grpcbox_stream:stream_handler_state(
        StreamState,
        #handler_state{
            streaming_initialized = false
        }
    ),
    NewStreamState;
maybe_init_stream_state(_HandlerState, StreamState) ->
    StreamState.
