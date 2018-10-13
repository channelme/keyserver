%% @author Maas-Maarten Zeeman <maas@channel.me>
%% @copyright 2018 Maas-Maarten Zeeman

%% Copyright 2018 Maas-Maarten Zeeman
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASI,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

-module(keyserver).
-author("Maas-Maarten Zeeman <maas@channel.me>").


-export([
    start/3,
    stop/1,

    public_enc_key/1,

    connect/5,

    p2p_request/5,
    secure_publish/5,
    secure_subscribe/6
]).

-include("keyserver.hrl").

start(Name, CallbackModule, UserContext) when is_atom(Name) ->
    keyserver_app_sup:start_keyserver(Name, CallbackModule, UserContext).

stop(Name) when is_atom(Name) ->
    keyserver_app_sup:stop_keyserver(Name).

%% Get the public encryption key of the keyserver.
public_enc_key(Name) when is_atom(Name) ->
    keyserver_server:public_enc_key(Name).

connect(Name, Id, EncKey, Nonce, ServerEncKey) when is_binary(Id) andalso size(EncKey) =:= ?KEY_BYTES ->
    Message = keyserver_crypto:encrypt_hello(Id, EncKey, Nonce, ServerEncKey),
     
    %% Server handles the request.
    handle_response(keyserver_server:connect(Name, Message), Name, EncKey).

    
p2p_request(Name, Id, OtherId, Nonce, Key) when is_binary(Id) andalso is_binary(OtherId) andalso size(Key) =:= ?KEY_BYTES ->
    IV = keyserver_crypto:generate_iv(),
    EncryptedRequest = keyserver_crypto:encrypt_request(Id, Nonce, {direct, OtherId}, Key, IV),
    handle_request(Name, Id, EncryptedRequest, Key, IV).
 
secure_publish(Name, Id, Topic, Nonce, Key) when is_binary(Id) andalso is_binary(Topic) ->
    IV = keyserver_crypto:generate_iv(),
    EncryptedRequest = keyserver_crypto:encrypt_request(Id, Nonce, {publish, Topic}, Key, IV),
    handle_request(Name, Id, EncryptedRequest, Key, IV).
    
secure_subscribe(Name, Id, KeyId, Topic, Nonce, Key) when is_binary(Id) andalso is_binary(Topic) andalso size(Key) =:= ?KEY_BYTES ->
    IV = keyserver_crypto:generate_iv(),
    EncryptedRequest = keyserver_crypto:encrypt_request(Id, Nonce, {subscribe, KeyId, Topic}, Key, IV),
    handle_request(Name, Id, EncryptedRequest, Key, IV).

%%
%% Helpers
%%

handle_request(Name, Id, EncryptedRequest, Key, IV) ->
    handle_response(
      keyserver_server:request(Name, Id, EncryptedRequest, IV), 
      Name, Key).

handle_response({ok, Result, IVS}, Name, Key) ->
    %% TODO: replay check
    keyserver_crypto:decrypt_response(z_convert:to_binary(Name), Result, Key, IVS);
handle_response({error, _}=Error, _Name, _Key) ->
    Error.
    
