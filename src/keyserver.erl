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
    session_key_request/1,
         
    generate_key/0,
    generate_iv/0,
    generate_nonce/0,
         
    inc_nonce/1

]).

-define(KEY_BYTES, 32).  %% 256 bits
-define(NONCE_BYTES, 8). %% 64 bits

-type key() :: <<_:(?KEY_BYTES*8)>>.
-type nonce() :: <<_:(?NONCE_BYTES*8)>>.

start(Name) when is_atom(Name) ->
    keyserver_app_sup:start_keyserver(Name).

stop(Name) when is_atom(Name) ->
    keyserver_app_sup:stop_keyserver(Name).

%% Get the public encryption key of the keyserver.
public_enc_key(Name) when is_atom(Name) ->
    keyserver_server:public_enc_key(Name).
    
-spec connect_to_server(atom(), term(), key(), nonce(), _) -> _.
connect_to_server(Name, Id, EncKey, Nonce, ServerEncKey) when size(EncKey) =:= ?KEY_BYTES andalso size(Nonce) =:= ?NONCE_BYTES->
    % {CipherText, CipherTag}=V = crypto:block_encrypt(aes_gcm, Key, IV, {<<"123">>, <<"dit is een test">>}),
    % R = crypto:block_decrypt(aes_gcm, Key, IV, {<<"123">>, CipherText, CipherTag}),

    CipherText = crypto:public_encrypt(rsa, <<"hello", EncKey/binary, Nonce/binary>>, ServerEncKey, rsa_pkcs1_oaep_padding),
     
    %% Server handles the request.
    keyserver_server:connect_to_server(Name, Id, CipherText).

session_key_request(_Pid) ->
    ok.

%%
%% Crypto helpers
%%

-spec generate_key() -> key().
generate_key() ->
    crypto:strong_rand_bytes(?KEY_BYTES).

-spec generate_iv() -> <<_:128>>.
generate_iv() ->
    crypto:strong_rand_bytes(16).
    
-spec generate_nonce() -> nonce().
generate_nonce() ->
    crypto:strong_rand_bytes(?NONCE_BYTES).


-spec inc_nonce(integer() | nonce()) -> nonce().
inc_nonce(Nonce) when is_binary(Nonce) ->
    <<N:64>> = Nonce,
    inc_nonce(N);
inc_nonce(Nonce) when is_integer(Nonce) ->
    Nonce1 = Nonce + 1,
    <<Nonce1:64>>.
    
 
