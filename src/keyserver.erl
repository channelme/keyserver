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
    start/1,
    stop/1,

    public_enc_key/1,
    connect_to_server/5,
    session_key_request/1
]).

-include("keyserver.hrl").

start(Name) when is_atom(Name) ->
    keyserver_app_sup:start_keyserver(Name).

stop(Name) when is_atom(Name) ->
    keyserver_app_sup:stop_keyserver(Name).

%% Get the public encryption key of the keyserver.
public_enc_key(Name) when is_atom(Name) ->
    keyserver_server:public_enc_key(Name).
    
-spec connect_to_server(atom(), term(), keyserver_crypto:key(), keyserver_crypto:nonce(), _) -> _.
connect_to_server(Name, Id, EncKey, Nonce, ServerEncKey) when size(EncKey) =:= ?KEY_BYTES andalso size(Nonce) =:= ?NONCE_BYTES->
    % {CipherText, CipherTag}=V = crypto:block_encrypt(aes_gcm, Key, IV, {<<"123">>, <<"dit is een test">>}),
    % R = crypto:block_decrypt(aes_gcm, Key, IV, {<<"123">>, CipherText, CipherTag}),
    CipherText = crypto:public_encrypt(rsa, <<"hello", EncKey/binary, Nonce/binary>>, ServerEncKey, rsa_pkcs1_oaep_padding),
     
    %% Server handles the request.
    keyserver_server:connect_to_server(Name, Id, CipherText).

session_key_request(_Pid) ->
    ok.

 
