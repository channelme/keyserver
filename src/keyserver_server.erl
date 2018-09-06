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
    start_link/2,
    public_enc_key/1,
    connect_to_server/3    
]).

% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         code_change/3, terminate/2]).

-record(state, {
    public_key,
    private_key,

    communication_key_table
}).

%%
%% API
%%

start_link(Name, {_PublicKey, _PrivateKey}=KeyPair) ->
    
    CommunicationKeyTable = ensure_communication_key_table(Name),

    case gen_server:start_link({local, Name}, ?MODULE, [KeyPair], []) of
        {ok, Pid} ->
            true = ets:give_away(CommunicationKeyTable, Pid, communication_key_table),
            {ok, Pid};
        {already_started, Pid} ->
            true = ets:give_away(CommunicationKeyTable, Pid, communication_key_table),
            {already_started, Pid};
        Else ->
            Else
    end.
     
public_enc_key(Name) ->
    gen_server:call(Name, public_enc_key).

connect_to_server(Name, Id, CipherText) ->
    gen_server:call(Name, {connect_to_server, Id, CipherText}).
    

%%
%% gen_server callbacks
%%

init([{PublicKey, PrivateKey}]) ->
    {ok, #state{public_key=PublicKey, private_key=PrivateKey}}.

handle_call({connect_to_server, _, _}, _From, #state{communication_key_table=undefined}=State) ->
    {reply, {error, not_ready}, State};
handle_call({connect_to_server, Id, CipherText}, _From, #state{private_key=PrivateKey, communication_key_table=Table}=State) ->
    case ets:lookup(Table, Id) of
        [] ->
            case crypto:private_decrypt(rsa, CipherText, PrivateKey, rsa_pkcs1_oaep_padding) of
                <<"hello", EEncKey:32/binary, Nonce:64>> -> 
                    ServerNonce = keyserver_crypto:generate_nonce(),
                    KeyES = keyserver_crypto:generate_key(),
                    Nonce1 = keyserver_crypto:inc_nonce(Nonce),
                    
                    Message = <<"hello_answer", KeyES/binary, ServerNonce/binary, Nonce1/binary>>,
                    
                    IV = keyserver_crypto:generate_iv(),
                    
                    %% TODO: opslaan van KeyES, de server nonce, en de client nonce.
                    true = ets:insert_new(Table, {Id, KeyES, Nonce1, ServerNonce}),
                    
                    {CipherMsg, CipherTag} = crypto:block_encrypt(aes_gcm, EEncKey, IV, {Nonce1, Message}),
                    % Validate with: crypto:block_decrypt(aes_gcm, Key, IV, {ServerNonce, CipherText, CipherTag}),
                    
                    {reply, {ok, Nonce1, IV, CipherTag, CipherMsg}, State};
                _ ->
                    {reply, {error, invalid_request}, State}
            end;
        _ ->
            {reply, {error, already_connected}, State}
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
handle_info(_Msg, State) ->
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(_Reason, _State) ->
    ok.

%%
%% Helpers
%%

ensure_communication_key_table(Name) ->
    TableName = communication_key_table_name(Name),

    case ets:info(TableName) of
        undefined ->
            ets:new(TableName, [named_table, set, {keypos, 1}, protected, {heir, self(), []}]);
        _ ->
            TableName
    end.


           
communication_key_table_name(Name) ->
    z_convert:to_atom(z_convert:to_list(Name) ++ "$communication_key_table").
