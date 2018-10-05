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

    connect_to_server/3,  

    request/4      
]).

% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         code_change/3, terminate/2]).

-record(state, {
    name,
    public_key,
    private_key,

    communication_key_table,
    session_key_table,

    callback_module,
    user_context
}).

-record(register_entry, {
    owner_id,
    key,
    nonce,
    server_nonce,
    expiration_time,
    lifetime  
}).

-record(session_record, {
    key_id,
    key,
    owner_id,
    expiration_time,
    lifetime
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
     
public_enc_key(Name) ->
    gen_server:call(Name, public_enc_key).

connect_to_server(Name, Id, Message) ->
    gen_server:call(Name, {connect_to_server, Id, Message}).
    

request(Name, Id, Message, IV) ->
    gen_server:call(Name, {request, Id, Message, IV}).

%%
%% gen_server callbacks
%%

init([Name, {PublicKey, PrivateKey}, CallbackModule, UserContext]) ->
    State = #state{name=z_convert:to_binary(Name), 
                   public_key=PublicKey, private_key=PrivateKey,
                   callback_module=CallbackModule, user_context=UserContext},
    {ok, State}.

handle_call({connect_to_server, _, _}, _From, #state{communication_key_table=undefined}=State) ->
    {reply, {error, not_ready}, State};
handle_call({connect_to_server, Id, CipherText}, _From, #state{name=Name, private_key=PrivateKey, communication_key_table=Table}=State) ->
    case ets:lookup(Table, Id) of
        [] ->
            case keyserver_crypto:decrypt_hello(CipherText, PrivateKey) of
                {hello, EEncKey, Nonce} ->
                    ServerNonce = keyserver_crypto:generate_nonce(),
                    Nonce1 = keyserver_crypto:inc_nonce(Nonce),

                    KeyES = keyserver_crypto:generate_key(),
                    IVS = keyserver_crypto:generate_iv(),

                    %% Store the communication key for later use.
                    true = ets:insert_new(Table, #register_entry{owner_id=Id, key=KeyES, 
                                                                 nonce=Nonce1, server_nonce=ServerNonce}),

                    Response = {hello_answer, KeyES, Nonce1},
                    EncryptedResponse = keyserver_crypto:encrypt_response(Name, ServerNonce, Response, EEncKey, IVS),

                    {reply, {ok, EncryptedResponse, IVS}, State};
                _ ->
                    {reply, {error, invalid_request}, State}
            end;
        _ ->
            {reply, {error, already_connected}, State}
    end;

handle_call({request, Id, Message, IV}, _From, #state{name=Name, communication_key_table=Table}=State) ->
    case ets:lookup(Table, Id) of
        [] -> 
            {reply, {error, not_found}, State};
        [#register_entry{owner_id=Id, key=KeyES, nonce=StoredNonce}=Entry] ->
            case keyserver_crypto:decrypt_request(Id, Message, KeyES, IV) of
                {error, _}=E ->
                    {reply, E, State};
                {ok, RequestNonce, Request} ->
                    io:fwrite(standard_error, "TODO: Replay detection: ~p: ~p~n", [RequestNonce, StoredNonce]),
                    {Response, State1} = handle_request(Request, Entry, State),

                    io:fwrite(standard_error, "Request: ~p, ~p~n", [Request, Response]),
                    
                    IVS = keyserver_crypto:generate_iv(),
                    ServerNonce1 = inc_server_nonce(Id, Table),

                    io:fwrite(standard_error, "ServerNonce: ~p~n", [ServerNonce1]),
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
handle_info(_Msg, State) ->
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(_Reason, _State) ->
    ok.

%%
%% Helpers
%%

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
            TicketA = create_p2p_ticket(K_AB, Timestamp, Lifetime, Id, KeyES),
                             
            %% Lookup key of other user.
            %% TODO: handle other id does not exist...
            {ok, KeyOtherS} = lookup_key(Table, OtherId),
            TicketB = create_p2p_ticket(K_AB, Timestamp, Lifetime, OtherId, KeyOtherS), 

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
            io:fwrite("secure subscribe request~n", []),

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
    end;
handle_request(_Id, {error, _Reason}, #state{}=State) ->
    {ok, State}.
    

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

-spec create_p2p_ticket(keyserver_crypto:key(), keyserver_util:timestamp(), non_neg_integer(), binary(), keyserver_crypto:key()) -> keyserver_crypto:p2p_ticket().
create_p2p_ticket(Key, Timestamp, Lifetime, OtherId, EncKey) ->
    keyserver_crypto:create_p2p_ticket(Key, Timestamp, Lifetime, OtherId, EncKey).
    
ensure_communication_key_table(Name) ->
    ensure_table(communication_key_table_name(Name), 2).

ensure_session_key_table(Name) ->
    ensure_table(session_key_table_name(Name), 2).

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
