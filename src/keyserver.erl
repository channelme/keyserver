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
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

-module(keyserver).
-author("Maas-Maarten Zeeman <maas@channel.me>").


-export([
    start/3,
    stop/1,

    public_enc_key/1,
    connect_to_server/5,

    p2p_request/5,

    secure_publish/5,
    secure_publish_new/5,

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
    
-spec connect_to_server(atom(), term(), keyserver_crypto:key(), keyserver_crypto:nonce(), keyserver_crypto:pub_enc_key()) -> _.
connect_to_server(Name, Id, EncKey, Nonce, ServerEncKey) when is_binary(Id) andalso size(EncKey) =:= ?KEY_BYTES ->
    Message = keyserver_crypto:encrypt_hello(EncKey, Nonce, ServerEncKey),
     
    %% Server handles the request.
    case keyserver_server:connect_to_server(Name, Id, Message) of
        {ok, SNonce1, IVS, Result} ->
            %% TODO: replay check
            keyserver_crypto:decrypt_hello_answer(SNonce1, Result, EncKey, IVS);
        {error, _} = Error -> Error
    end;

connect_to_server(Name, Id, EncKey, Nonce, ServerEncKey) ->
    connect_to_server(Name, z_convert:to_binary(Id), EncKey, Nonce, ServerEncKey).
    

%% Request a communication key for another party.
p2p_request(Name, Id, OtherId, Nonce, Key) when is_binary(Id) andalso is_binary(OtherId) andalso size(Key) =:= ?KEY_BYTES ->
    IV = keyserver_crypto:generate_iv(),
    Message = keyserver_crypto:encrypt_p2p_request(Id, OtherId, Nonce, Key, IV),
    keyserver_server:p2p_request(Name, Id, Nonce, Message, IV);
p2p_request(Name, Id, OtherId, Nonce, Key) ->
    p2p_request(Name, z_convert:to_binary(Id), z_convert:to_binary(OtherId), Nonce, Key).

%% Request a communication key for another party.
secure_publish(Name, Id, Topic, Nonce, Key) when is_binary(Id) andalso is_binary(Topic) andalso size(Key) =:= ?KEY_BYTES ->
    IV = keyserver_crypto:generate_iv(),
    Message = keyserver_crypto:encrypt_secure_publish_request(Id, Topic, Nonce, Key, IV),

    case keyserver_server:publish_request(Name, Id, Nonce, Message, IV) of
        {ok, SNonce1, IVS, Result} ->
            %% TODO: replay check
            keyserver_crypto:decrypt_secure_publish_response(SNonce1, Result, Key, IVS);
        {error, _} = Error -> Error
    end;
secure_publish(Name, Id, Topic, Nonce, Key) ->
    secure_publish(Name, z_convert:to_binary(Id), z_convert:to_binary(Topic), Nonce, Key).

secure_publish_new(Name, Id, Topic, Nonce, Key) when is_binary(Id) andalso is_binary(Topic) ->
    IV = keyserver_crypto:generate_iv(),
    EncryptedRequest = keyserver_crypto:encrypt_request(Id, Nonce, {publish, Topic}, Key, IV),

    case keyserver_server:request(Name, Id, EncryptedRequest, IV) of
        {ok, SNonce1, IVS, Result} ->
            %% TODO: replay check
            keyserver_crypto:decrypt_secure_publish_response(SNonce1, Result, Key, IVS);
        {error, _} = Error -> Error
    end.


secure_subscribe(Name, Id, KeyId, Topic, Nonce, Key) when is_binary(Id) andalso is_binary(Topic) andalso size(Key) =:= ?KEY_BYTES ->
    IV = keyserver_crypto:generate_iv(),
    Message = keyserver_crypto:encrypt_secure_subscribe_request(Id, KeyId, Topic, Nonce, Key, IV),

    case keyserver_server:subscribe_request(Name, Id, Nonce, Message, IV) of
        {ok, SNonce1, IVS, Result} ->
            %% TODO: replay check...    
            keyserver_crypto:decrypt_session_key(SNonce1, Result, Key, IVS);
        {error, _} = Error -> Error
    end;
secure_subscribe(Name, Id, KeyId, Topic, Nonce, Key) ->
    secure_subscribe(Name, z_convert:to_binary(Id), KeyId, z_convert:to_binary(Topic), Nonce, Key).
