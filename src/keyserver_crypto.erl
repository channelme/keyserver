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

-module(keyserver_crypto).
-author("Maas-Maarten Zeeman <maas@channel.me>").

-define(AES_GCM_TAG_SIZE, 16). % The security of GCM depends on the tag size , so we use the full 128 bits.

-export([
    generate_key/0,
    generate_iv/0,
    generate_nonce/0,

    inc_nonce/1,

    encrypt_hello/3,
    decrypt_hello/2,

    encrypt_hello_answer/3,
    decrypt_hello_answer/4
]).

-include("keyserver.hrl").

-type key() :: <<_:(?KEY_BYTES*8)>>.
-type nonce() :: <<_:(?NONCE_BYTES*8)>>.

-export_type([
    key/0,
    nonce/0
]).


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


encrypt_hello(EncKey, Nonce, ServerEncKey) ->
    crypto:public_encrypt(rsa, 
        <<"hello", EncKey/binary, Nonce/binary>>, ServerEncKey, rsa_pkcs1_oaep_padding).

decrypt_hello(Message, PrivateKey) ->
    <<"hello", EEncKey:32/binary, Nonce:8/binary>> =
        crypto:private_decrypt(rsa, Message, PrivateKey, rsa_pkcs1_oaep_padding),
    {hello, EEncKey, Nonce}.

encrypt_hello_answer({hello_answer, KeyES, ServerNonce, Nonce}, EncKey, IV) ->
    Message = <<"hello_answer", KeyES/binary, ServerNonce/binary, Nonce/binary>>,
    {Msg, Tag} = crypto:block_encrypt(aes_gcm, EncKey, IV, {Nonce, Message, ?AES_GCM_TAG_SIZE}),
    <<Tag/binary, $:, Msg/binary>>.

decrypt_hello_answer(Nonce, Message, EncKey, IV) ->
    <<Tag:?AES_GCM_TAG_SIZE/binary, $:, Msg/binary>> = Message,
    case Message of
        <<Tag:?AES_GCM_TAG_SIZE/binary, $:, Msg/binary>> ->
            Plain = crypto:block_decrypt(aes_gcm, EncKey, IV, {Nonce, Msg, Tag}),
            case Plain of
                <<"hello_answer", KeyES:?KEY_BYTES/binary, SNonce:?NONCE_BYTES/binary, Nonce:?NONCE_BYTES/binary>> -> 
                    {hello_answer, KeyES, SNonce, Nonce};
                _ ->
                    {error, plain_msg}
            end;
        _ ->
           {error, cipher_msg}
    end.
    
    

%decrypt_hello_answer({hello_answer, KeyES, ServerNonce, Nonce}, Key, IV) ->
%
%    <<"hello_answer", _/binary>> = crypto:block_decrypt(aes_gcm, AliceKey, IVAlice, {AliceNonce1, AliceCipherText, AliceCipherTag}).
