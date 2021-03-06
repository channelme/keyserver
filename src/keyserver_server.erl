%% @author Maas-Maarten Zeeman <maas@channel.me>
%% @copyright 2018 Maas-Maarten Zeeman
%%
%% @doc Keyserver.
%%
%% Copyright 2018 Maas-Maarten Zeeman
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%% 
%%     http://www.apache.org/licenses/LICENSE-2.0
%% 
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.


-module(keyserver_server).
-behaviour(gen_server).

-include("keyserver.hrl").

-export([
    start_link/4,
    public_enc_key/1,
    connect/2,  
    request/4,      
    stop/1
]).

% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         code_change/3, terminate/2]).

-record(state, {
    name :: binary(),
    public_key :: keyserver_crypto:pub_enc_key(),
    private_key :: keyserver_crypto:priv_dec_key(),
          
    timer :: timer:tref(),

    communication_key_table :: ets:tab(),
    session_key_table :: ets:tab(),

    callback_module :: module(),
    user_context :: term()
}).

-type match(A) :: A | '_' | '$1' | '$2'. % type for use in match expression

-record(register_entry, {
    owner_id :: match(keyserver_crypto:entity_id()),
    key :: match(keyserver_crypto:key()),
    nonce :: match(keyserver_crypto:nonce()),
    server_nonce :: match(keyserver_crypto:nonce()),
    expiration_time :: match(keyserver_utils:timestamp()),
    lifetime :: match(pos_integer()) 
}).

-record(session_record, {
    key_id :: match(keyserver_crypto:key_id()),
    key :: match(keyserver_crypto:key()),
    owner_id :: match(keyserver_crypto:entity_id()),
    expiration_time :: match(keyserver_utils:timestamp()),
    lifetime :: match(pos_integer())
}).

%%
%% API
%%

start_link(Name, {_PublicKey, _PrivateKey}=KeyPair, CallbackModule, UserContext) ->
    CommunicationKeyTable = ensure_communication_key_table(Name),
    SessionKeyTable = ensure_session_key_table(Name),

    case gen_server:start_link({local, Name}, ?MODULE, [Name, KeyPair, CallbackModule, UserContext], []) of
        {ok, Pid} ->
            true = ets:give_away(CommunicationKeyTable, Pid, communication_key_table),
            true = ets:give_away(SessionKeyTable, Pid, session_key_table),
            {ok, Pid};
        Else ->
            Else
    end.

stop(Name) ->
    gen_server:call(Name, stop).
     
public_enc_key(Name) ->
    gen_server:call(Name, public_enc_key).

connect(Name, Message) ->
    gen_server:call(Name, {connect, Message}).

request(Name, Id, Message, IV) ->
    gen_server:call(Name, {request, Id, Message, IV}).

%%
%% gen_server callbacks
%%

init([Name, {PublicKey, PrivateKey}, CallbackModule, UserContext]) ->
    {ok, TRef} = timer:send_interval(60000, purge),
    State = #state{name=z_convert:to_binary(Name), 
                   timer=TRef,
                   public_key=PublicKey, private_key=PrivateKey,
                   callback_module=CallbackModule, user_context=UserContext},
    {ok, State}.

handle_call({connect, _}, _From, #state{communication_key_table=undefined}=State) ->
    {reply, {error, not_ready}, State};
handle_call({connect, CipherText}, _From, #state{name=Name,
                                                 private_key=PrivateKey, communication_key_table=Table,
                                                 callback_module=M, user_context=C}=State) ->
    case keyserver_crypto:decrypt_hello(CipherText, PrivateKey) of
        {hello, EntityId, EEncKey, Nonce} ->
            case ets:lookup(Table, EntityId) of
                [] ->
                    case check_allowed(connect, [{id, EntityId}], M, C) of 
                        ok ->
                            ServerNonce = keyserver_crypto:generate_nonce(),
                            Nonce1 = keyserver_crypto:inc_nonce(Nonce),

                            KeyES = keyserver_crypto:generate_key(),
                            IVS = keyserver_crypto:generate_iv(),
                    
                            Timestamp = keyserver_utils:unix_time(),
                            Lifetime = 3600,

                            %% Store the communication key for later use.
                            true = ets:insert_new(Table, #register_entry{owner_id=EntityId, key=KeyES, 
                                                                         nonce=Nonce1, server_nonce=ServerNonce,
                                                                         expiration_time = Timestamp + Lifetime,
                                                                         lifetime = Lifetime}),

                            Response = {hello_answer, KeyES, Nonce1},
                            EncryptedResponse = keyserver_crypto:encrypt_response(Name, ServerNonce, Response, EEncKey, IVS),
                            {reply, {ok, EncryptedResponse, IVS}, State};
                        _ ->
                            %% TODO: should this be an encrypted message?
                            {reply, {error, not_allowed}, State}
                    end;
                _ ->
                    {reply, {error, already_connected}, State}
            end;
        _ ->
            {reply, {error, invalid_request}, State}
    end;

handle_call({request, Id, Message, IV}, _From, #state{name=Name, communication_key_table=Table}=State) ->
    case ets:lookup(Table, Id) of
        [] -> 
            {reply, {error, not_found}, State};
        [#register_entry{owner_id=Id, key=KeyES}=Entry] ->
            case keyserver_crypto:decrypt_request(Id, Message, KeyES, IV) of
                {error, _}=E ->
                    {reply, E, State};
                {ok, _RequestNonce, Request} ->
                    %% TODO add replay detection
                    {Response, State1} = handle_request(Request, Entry, State),

                    IVS = keyserver_crypto:generate_iv(),
                    ServerNonce1 = inc_server_nonce(Id, Table),

                    EncryptedResponse = keyserver_crypto:encrypt_response(Name, ServerNonce1, Response, KeyES, IVS),

                    {reply, {ok, EncryptedResponse, IVS}, State1}
            end
    end;

handle_call(public_enc_key, _From, #state{public_key=PublicKey}=State) ->
    {reply, {ok, PublicKey}, State};

handle_call(stop, _From, State) ->
    {stop, normal, ok, State};

handle_call(Msg, _From, State) ->
    {stop, {unknown_call, Msg}, State}.
    
handle_cast(Msg, State) ->
    {stop, {unknown_cast, Msg}, State}.   
    
handle_info({'ETS-TRANSFER', Table, _FromPid, communication_key_table}, State) ->
    {noreply, State#state{communication_key_table=Table}};
handle_info({'ETS-TRANSFER', Table, _FromPid, session_key_table}, State) ->
    {noreply, State#state{session_key_table=Table}};
handle_info(purge, State) ->
    Timestamp = keyserver_utils:unix_time(),
    purge_communication_keys(Timestamp, State#state.communication_key_table),
    purge_session_keys(Timestamp, State#state.session_key_table),
    {noreply, State};
handle_info(_Msg, State) ->
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(normal, #state{timer=TRef}=State) ->
    ets:delete(State#state.communication_key_table),
    ets:delete(State#state.session_key_table),
    {ok, cancel} = timer:cancel(TRef);
terminate(_Reason, #state{timer=TRef}) ->
    {ok, cancel} = timer:cancel(TRef),
    ok.

%%
%% Helpers
%%

-spec handle_request(keyserver_crypto:request() | {error, term()}, #register_entry{}, #state{}) -> {term(), #state{}}.
handle_request({direct, OtherId},
               #register_entry{owner_id=Id, key=KeyES},
               #state{communication_key_table=Table, 
                      callback_module=Module, user_context=Context}=State) ->
    case check_allowed(communicate, [{id, Id}, {other_id, OtherId}], Module, Context) of
        ok ->
            %% Generate a key.
            K_AB = keyserver_crypto:generate_key(),
            
            %% Timestamp
            Timestamp = keyserver_utils:unix_time(), %% 64 bit integer.

            %% Lifetime
            Lifetime = 3600, % in seconds one hour (todo, make variable)
            
            %% Lookup communication key of B
            %% Create ticket for Other, encrypt under B key
            TicketA = keyserver_crypto:encrypt_p2p_ticket(K_AB, Timestamp, Lifetime, Id, KeyES),
                             
            %% Lookup key of other user.
            %% TODO: handle other id does not exist...
            {ok, KeyOtherS} = lookup_key(Table, OtherId),
            TicketB = keyserver_crypto:encrypt_p2p_ticket(K_AB, Timestamp, Lifetime, OtherId, KeyOtherS), 

            Response = {tickets, TicketA, TicketB},

            {Response, State};
        {error, _Reason} ->
            {not_allowed, State}
    end;

handle_request({publish, Topic},
               #register_entry{owner_id=Id},
               #state{session_key_table=SessionKeyTable,
                      callback_module=Module, user_context=Context}=State) ->
    case check_allowed(publish, [{id, Id}, {topic, Topic}], Module, Context) of
        ok -> 
            %% Generate a key id. (hash of key?), link to the topic?
            SessionKeyId = keyserver_crypto:generate_key_id(),
            SessionKey = keyserver_crypto:generate_key(),
                             
            Timestamp = keyserver_utils:unix_time(),
            Lifetime = 3600, % 
            ExpirationTime = Timestamp + Lifetime,
                              
            %% Insert the session key in the table
            Record = #session_record{key_id=SessionKeyId, key=SessionKey, owner_id=Id, 
                                     expiration_time=ExpirationTime, lifetime=Lifetime},
            true = ets:insert_new(SessionKeyTable, Record),

            Response = {session_key, SessionKeyId, SessionKey, Timestamp, Lifetime},

            {Response, State};
        {error, _Reason} ->
            {not_allowed, State}
    end;
handle_request({subscribe, SessionKeyId, Topic},
               #register_entry{owner_id=Id},
               #state{session_key_table=SessionKeyTable,
                      callback_module=Module, user_context=Context}=State) ->
    case check_allowed(subscribe, [{id, Id}, {topic, Topic}, {key_id, SessionKeyId}], Module, Context) of
        ok ->
            case ets:lookup(SessionKeyTable, SessionKeyId) of
                [] ->
                    {{error, nokey}, State};
                [#session_record{key=SessionKey, 
                                 expiration_time=ExpirationTime}] ->
                    Timestamp = keyserver_utils:unix_time(),
                    Lifetime = ExpirationTime - Timestamp, % What is left of the validity period

                    Response = {session_key, SessionKeyId, SessionKey, Timestamp, Lifetime},
                    {Response, State}
            end;
        {error, _Reason} ->
            {not_allowed, State}
    end.
    

-spec inc_server_nonce(binary(), ets:tab()) -> integer().
inc_server_nonce(Id, Table) ->
    ets:update_counter(Table, Id, {#register_entry.server_nonce, 1, ?MAX_NONCE, 0}).

-spec lookup_key(ets:tab(), binary()) -> {ok, keyserver_crypto:key()} | undefined.
lookup_key(Table, Id) ->
    case ets:lookup(Table, Id) of
        [] -> undefined; 
        [#register_entry{owner_id=Id, key=KeyES}] -> {ok, KeyES}
    end.


check_allowed(What, Args, Module, Context) when is_atom(What) andalso is_list(Args) ->
    case catch Module:is_allowed(What, Args, Context) of
        true -> ok;
        false -> {error, not_allowed};
        Response -> {error, {unexpected_response, Response, Module, Context}}
    end.

ensure_communication_key_table(Name) ->
    ensure_table(communication_key_table_name(Name), 2).

ensure_session_key_table(Name) ->
    ensure_table(session_key_table_name(Name), 2).

-spec purge_communication_keys(keyserver_utils:timestamp(), ets:tab()) -> any().
purge_communication_keys(Timestamp, Table) ->
    ets:select_delete(Table, [{#register_entry{expiration_time='$1', _='_'},
                               [{'=<', '$1', Timestamp}], [true]}]).

-spec purge_session_keys(keyserver_utils:timestamp(), ets:tab()) -> any().
purge_session_keys(Timestamp, Table) ->
    ets:select_delete(Table, [{#session_record{expiration_time='$1', _='_'},
                               [{'=<', '$1', Timestamp}], [true]}]).

ensure_table(Name, KeyPos) ->
    case ets:info(Name) of
        undefined ->
            ets:new(Name, [named_table, set, {keypos, KeyPos}, protected, {heir, self(), []}]);
        _ ->
            Name
    end.
           
communication_key_table_name(Name) ->
    z_convert:to_atom(z_convert:to_list(Name) ++ "$communication_keys").

session_key_table_name(Name) ->
    z_convert:to_atom(z_convert:to_list(Name) ++ "$session_keys").

%%
%% Tests
%%

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

communication_table_purge_test() ->
    Table = ensure_communication_key_table(eunit),
    purge_communication_keys(0, Table),

    ets:insert(Table, #register_entry{owner_id=1, expiration_time=10}),
    ets:insert(Table, #register_entry{owner_id=2, expiration_time=50}),
    ets:insert(Table, #register_entry{owner_id=3, expiration_time=60}),
    ets:insert(Table, #register_entry{owner_id=4, expiration_time=70}),

    ?assertEqual(4, length(ets:tab2list(Table))),
    
    purge_communication_keys(50, Table),
    
    ?assertEqual(2, length(ets:tab2list(Table))),
    ?assertEqual(true, ets:member(Table, 3)),
    ?assertEqual(true, ets:member(Table, 4)),

    purge_communication_keys(60, Table),
    
    ?assertEqual(1, length(ets:tab2list(Table))),
    ?assertEqual(true, ets:member(Table, 4)),

    ok.

session_table_purge_test() ->
    Table = ensure_session_key_table(eunit),
    purge_communication_keys(0, Table),

    ets:insert(Table, #session_record{key_id=1, expiration_time=10}),
    ets:insert(Table, #session_record{key_id=2, expiration_time=50}),
    ets:insert(Table, #session_record{key_id=3, expiration_time=60}),
    ets:insert(Table, #session_record{key_id=4, expiration_time=70}),

    ?assertEqual(4, length(ets:tab2list(Table))),
    
    purge_session_keys(50, Table),
    
    ?assertEqual(2, length(ets:tab2list(Table))),
    ?assertEqual(true, ets:member(Table, 3)),
    ?assertEqual(true, ets:member(Table, 4)),

    purge_session_keys(60, Table),
    
    ?assertEqual(1, length(ets:tab2list(Table))),
    ?assertEqual(true, ets:member(Table, 4)),

    ok.

-endif.
