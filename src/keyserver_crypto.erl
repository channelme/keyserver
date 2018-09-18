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
-define(MAX_NONCE, ((1 bsl 64) -1)).

-export([
    generate_key/0,
    generate_iv/0,
    generate_nonce/0,
         
    hash/1,

    inc_nonce/1,
         

    encrypt_hello/3,
    decrypt_hello/2,

    encrypt_hello_answer/3,
    decrypt_hello_answer/4,

    encrypt_p2p_request/5,
    decrypt_p2p_request/4
]).

-include("keyserver.hrl").

-type key() :: <<_:(?KEY_BYTES*8)>>.
-type nonce() :: <<_:(?NONCE_BYTES*8)>>.
-type hash() :: <<_:(?HASH_BYTES*8)>>.

-type timestamp() :: <<_:(?HASH_BYTES*8)>>.

-export_type([
    key/0,
    nonce/0,
    timestamp/0,
    hash/0
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
    inc_nonce(decode_nonce(Nonce));
inc_nonce(Nonce) when is_integer(Nonce) ->
    (Nonce + 1) rem ?MAX_NONCE.

% Decode Nonce binary value into an integer.
decode_nonce(<<Nonce:64>>) -> 
    Nonce;
decode_nonce(Nonce) when Nonce >= 0 andalso Nonce < ?MAX_NONCE -> 
    Nonce.
    
% Encode a nonce into a 64 bit binary value.
encode_nonce(<<_:64>>=Nonce) -> Nonce;
encode_nonce(Nonce) when Nonce >= 0 andalso Nonce < ?MAX_NONCE -> 
    <<Nonce:64>>.


-spec hash(iodata()) -> hash().
hash(Data) ->
    crypto:hash(sha256, Data).
    

%%
%% Hello
%%

encrypt_hello(EncKey, Nonce, ServerEncKey) ->
    EncNonce = encode_nonce(Nonce),
    crypto:public_encrypt(rsa, 
        <<"hello", EncKey/binary, EncNonce/binary>>, ServerEncKey, rsa_pkcs1_oaep_padding).

decrypt_hello(Message, PrivateKey) ->
    <<"hello", EEncKey:?KEY_BYTES/binary, Nonce:?NONCE_BYTES/binary>> =
        crypto:private_decrypt(rsa, Message, PrivateKey, rsa_pkcs1_oaep_padding),
    {hello, EEncKey, decode_nonce(Nonce)}.

encrypt_hello_answer({hello_answer, KeyES, ServerNonce, Nonce}, EncKey, IV) ->
    EncNonce = encode_nonce(Nonce),
    Message = <<"hello_answer", KeyES/binary, ServerNonce/binary, EncNonce/binary>>,
    {Msg, Tag} = crypto:block_encrypt(aes_gcm, EncKey, IV, {EncNonce, Message, ?AES_GCM_TAG_SIZE}),
    <<Tag/binary, $:, Msg/binary>>.

decrypt_hello_answer(Nonce, Message, EncKey, IV) ->
    EncNonce = encode_nonce(Nonce),
    case decrypt_message(Message, EncNonce, EncKey, IV) of
        <<"hello_answer", KeyES:?KEY_BYTES/binary, SNonce:?NONCE_BYTES/binary, EncNonce:?NONCE_BYTES/binary>> -> 
            {hello_answer, KeyES, decode_nonce(SNonce), decode_nonce(EncNonce)};
        Bin when is_binary(Bin) -> {error, plain_msg};
        {error, _}=E -> E
    end.
    
%%
%% p2p requests
%%
    
encrypt_p2p_request(Id, OtherId, Nonce, Key, IV) when is_binary(Id) andalso is_binary(OtherId) ->
    IdHash = keyserver_crypto:hash(Id),
    EncNonce = encode_nonce(Nonce),
    Message = <<"p2p_request", EncNonce/binary, IdHash/binary, OtherId/binary>>,
    {Msg, Tag} = crypto:block_encrypt(aes_gcm, Key, IV, {EncNonce, Message, ?AES_GCM_TAG_SIZE}),
    <<Tag/binary, $:, Msg/binary>>.

decrypt_p2p_request(Nonce, Message, Key, IV) ->
    case decrypt_message(Message, Nonce, Key, IV) of
        <<"p2p_request", EncNonce:?NONCE_BYTES/binary, IdHash:?HASH_BYTES/binary, OtherId/binary>> ->
            {p2p_request, IdHash, OtherId, decode_nonce(EncNonce)};
        Bin when is_binary(Bin) -> {error, plain_msg};
        {error, _}=E -> E
    end.
       
%%
%% Helpers
%%
            
decrypt_message(<<Tag:?AES_GCM_TAG_SIZE/binary, $:, Msg/binary>>, Nonce, Key, IV) when size(Key) =:= ?KEY_BYTES->
    EncNonce = encode_nonce(Nonce),
    crypto:block_decrypt(aes_gcm, Key, IV, {EncNonce, Msg, Tag});
decrypt_message(_Msg, _Nonce, _Key, _IV) ->
    {error, cipher_msg}.

