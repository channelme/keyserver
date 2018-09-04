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

-export([
    start_link/2,
    public_enc_key/1,
    connect_to_server/2     
]).

% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         code_change/3, terminate/2]).

-record(state, {
    public_key,
    private_key
}).

%%
%% API
%%

start_link(Name, {_PublicKey, _PrivateKey}=KeyPair) ->
    gen_server:start_link({local, Name}, ?MODULE, [KeyPair], []).

public_enc_key(Name) ->
    gen_server:call(Name, public_enc_key).

connect_to_server(Name, CipherText) ->
    gen_server:call(Name, {connect_to_server, CipherText}).
    

%%
%% gen_server callbacks
%%

init([{PublicKey, PrivateKey}]) ->
    {ok, #state{public_key=PublicKey, private_key=PrivateKey}}.

handle_call({connect_to_server, CipherText}, _From, #state{private_key=PrivateKey}=State) ->

    case crypto:private_decrypt(rsa, CipherText, PrivateKey, rsa_pkcs1_oaep_padding) of
        <<"hello", EEncKey:256, Nonce:64>> -> 

            ServerNonce = keyserver:generate_nonce(),
            KeyES = keyserver:generate_key(),
            Nonce1 = keyserver:inc_nonce(Nonce),
            
            Message = <<"hello_answer", KeyES/binary, ServerNonce/binary, Nonce1/binary>>,
            
            io:fwrite(standard_error, "~p~n", [Message]),

            {reply, {ok, todo}, State};
        _ ->
            {reply, {error, invalid_request}, State}
    end;

handle_call(public_enc_key, _From, #state{public_key=PublicKey}=State) ->
    {reply, {ok, PublicKey}, State};

handle_call(stop, _From, State) ->
    {stop, normal, ok, State};

handle_call(Msg, _From, State) ->
    {stop, {unknown_call, Msg}, State}.
    
handle_cast(Msg, State) ->
    {stop, {unknown_cast, Msg}, State}.   
    
handle_info(_Msg, State) ->
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(_Reason, _State) ->
    ok.