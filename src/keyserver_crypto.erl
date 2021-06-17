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

-define(V1, $1).

-define(HELLO, $H).
-define(HELLO_ANSWER, $A).

-define(PUBLISH, $P).
-define(SUBSCRIBE, $S).
-define(DIRECT, $D).

-define(TICKETS, $T).
-define(SESSION_KEY, $K).
-define(P2P_TICKET, $I).

-define(SECURE_PUBLISH, $E).

-define(PUBLIC_MODULUS, 65537).
-define(MODULUS_SIZE, 2048).

-export([
    generate_keypair/0,
    generate_key/0,
    generate_key_id/0,
    generate_iv/0,
    generate_nonce/0,
         
    hash/1,

    inc_nonce/1,

    encrypt_hello/4,
    decrypt_hello/2,

    encrypt_p2p_ticket/5,
    decrypt_p2p_ticket/3,

    p2p_encrypt/5,
    p2p_decrypt/6,

    encrypt_request/5,
    decrypt_request/4,
         
    encrypt_response/5,
    decrypt_response/4,

    encrypt_secure_publish/3,
    decrypt_secure_publish/3
]).

-include("keyserver.hrl").

-type entity_id() :: binary(). %% <<_:(?MAX_ID_BYTES*8)>>.
-type nonce() :: 0..?MAX_NONCE.
-type key_id() :: <<_:(?KEY_ID_BYTES*8)>>.
-type key() :: <<_:(?KEY_BYTES*8)>>.
-type iv() :: <<_:(?IV_BYTES*8)>>.
-type pub_enc_key() :: crypto:rsa_public().
-type priv_dec_key() :: crypto:rsa_private().
-type hash() :: <<_:(?HASH_BYTES*8)>>.
-type encoded_nonce() :: <<_:(?NONCE_BYTES*8)>>.

-type timestamp() :: <<_:(?HASH_BYTES*8)>>.
-type p2p_ticket() :: binary().

-type topic() :: binary().
-type request() :: {direct, entity_id()} | {publish, topic()} | {subscribe, key_id(), topic()}.

-export_type([
    entity_id/0,
    key/0,
    iv/0,
    nonce/0,
    encoded_nonce/0,
    timestamp/0,
    p2p_ticket/0,
    hash/0
]).


-spec generate_key() -> key().
generate_key() ->
    crypto:strong_rand_bytes(?KEY_BYTES).

-spec generate_keypair() -> {pub_enc_key(), priv_dec_key()}.
generate_keypair() ->
    crypto:generate_key(rsa, {?MODULUS_SIZE, ?PUBLIC_MODULUS}).

-spec generate_key_id() -> key_id().
generate_key_id() ->
    crypto:strong_rand_bytes(?KEY_ID_BYTES).

-spec generate_iv() -> <<_:128>>.
generate_iv() ->
    crypto:strong_rand_bytes(?IV_BYTES).
    
-spec generate_nonce() -> nonce().
generate_nonce() ->
    decode_nonce(crypto:strong_rand_bytes(?NONCE_BYTES)).

-spec inc_nonce(encoded_nonce() | nonce()) -> nonce().
inc_nonce(Nonce) when is_binary(Nonce) ->
    inc_nonce(decode_nonce(Nonce));
inc_nonce(Nonce) when is_integer(Nonce) ->
    (Nonce + 1) rem ?MAX_NONCE.

% Decode Nonce binary value into an integer.
-spec decode_nonce(encoded_nonce()) -> nonce().
decode_nonce(<<Nonce:64/big-unsigned-integer>>) -> 
    Nonce.
    
% Encode a nonce into a 64 bit binary value.
encode_nonce(<<_:64/big-unsigned-integer>>=Nonce) -> Nonce;
encode_nonce(Nonce) when Nonce >= 0 andalso Nonce < ?MAX_NONCE -> 
    <<Nonce:64/big-unsigned-integer>>.


-spec hash(iodata()) -> hash().
hash(Data) ->
    crypto:hash(sha256, Data).
    
%%
%% Hello
%%

-spec encrypt_hello(entity_id(), key(), nonce(), pub_enc_key()) -> binary(). 
encrypt_hello(Id, EncKey, Nonce, ServerEncKey) ->
    EncNonce = encode_nonce(Nonce),
    crypto:public_encrypt(rsa, 
        <<?V1, ?HELLO, EncKey/binary, EncNonce/binary, Id/binary>>, 
                          ServerEncKey, rsa_pkcs1_oaep_padding).

decrypt_hello(Message, PrivateKey) ->
    case crypto:private_decrypt(rsa, Message, PrivateKey, rsa_pkcs1_oaep_padding) of
        <<?V1, ?HELLO, EEncKey:?KEY_BYTES/binary, Nonce:?NONCE_BYTES/binary, EntityId/binary>> ->
            {hello, EntityId, EEncKey, decode_nonce(Nonce)};
        Bin when is_binary(Bin) ->
            {error, message}
    end.

% -spec encode_p2p_ticket() -> p2p_ticket().
encrypt_p2p_ticket(Key, Timestamp, Lifetime, OtherId, EncKey) ->
    Ticket = <<Timestamp:64/big-unsigned-integer, Lifetime:16/big-unsigned-integer, Key/binary, OtherId/binary>>,
    IV = keyserver_crypto:generate_iv(),
    Msg = aes_gcm_encrypt(Ticket, EncKey, IV, OtherId),
    <<?P2P_TICKET, IV/binary, Msg/binary>>.

decrypt_p2p_ticket(<<?P2P_TICKET, IV:?IV_BYTES/binary, Message/binary>>, OtherId, Key) ->
    case aes_gcm_decrypt(Message, Key, IV, OtherId) of
	<<Timestamp:64/big-unsigned-integer, Lifetime:16/big-unsigned-integer, TicketKey:?KEY_BYTES/binary, EntityId/binary>> ->
	    {ticket, EntityId, TicketKey, Timestamp, Lifetime}; 
        Bin when is_binary(Bin) -> 
	    {error, ticket_format};
        error ->
	    {error, integrity}
    end.
    
p2p_encrypt(MyId, Message, <<?P2P_TICKET, _/binary>> = Ticket, Key, IV) ->
    case decrypt_p2p_ticket(Ticket, MyId, Key) of
	{ticket, MyId, TheKey, Timestamp, Lifetime} ->
	    case Timestamp + Lifetime > keyserver_utils:unix_time() of
		true -> aes_gcm_encrypt(Message, TheKey, IV, MyId);
		false -> {error, ticket_expired}
            end;
        {ticket, _Id, _Key, _Timestamp, _Lifetime} -> {error, not_ticket_owner};
	{error, _}=E -> E
    end.
    
p2p_decrypt(MyId, OtherId, Message, <<?P2P_TICKET, _/binary>> = Ticket, Key, IV) ->
    case decrypt_p2p_ticket(Ticket, MyId, Key) of
	{ticket, MyId, TheKey, Timestamp, Lifetime} ->
	    case Timestamp + Lifetime > keyserver_utils:unix_time() of
		true -> aes_gcm_decrypt(Message, TheKey, IV, OtherId);
		false -> {error, ticket_expired}
	    end;
	{ticket, _Id, _Key, _Timestamp, _Lifetime} -> {error, not_ticket_owner};
	{error, _}=E -> E
    end.

encrypt_secure_publish(Message, KeyId, Key) when size(KeyId) =:= ?KEY_ID_BYTES andalso size(Key) =:= ?KEY_BYTES ->
    IV = keyserver_crypto:generate_iv(),
    Msg = aes_gcm_encrypt(Message, Key, IV, KeyId),
    <<?V1, ?SECURE_PUBLISH, IV/binary, Msg/binary>>.

decrypt_secure_publish(<<?V1, ?SECURE_PUBLISH, IV:?IV_BYTES/binary, Message/binary>>, KeyId, Key) when size(KeyId) =:= ?KEY_ID_BYTES andalso size(Key) =:= ?KEY_BYTES ->
    case  aes_gcm_decrypt(Message, Key, IV, KeyId) of
        Bin when is_binary(Bin) -> {ok, Bin};
        error -> {error, integrity}
    end.
    
encrypt_request(Id, Nonce, Request, Key, IV) ->
    EncNonce = encode_nonce(Nonce),
    Message = encode_request(Request),
    M = <<?V1, EncNonce/binary, Message/binary>>,   
    aes_gcm_encrypt(M, Key, IV, Id).

encode_request({direct, OtherId}) ->
    <<?DIRECT, OtherId/binary>>;
encode_request({publish, Topic}) ->
    <<?PUBLISH, Topic/binary>>; 
encode_request({subscribe, KeyId, Topic}) ->
    <<?SUBSCRIBE, KeyId/binary, Topic/binary>>.

decode_request(<<?DIRECT, OtherId/binary>>) ->
    {direct, OtherId};
decode_request(<<?PUBLISH, Topic/binary>>) ->
    {publish, Topic};
decode_request(<<?SUBSCRIBE, KeyId:?KEY_ID_BYTES/binary, Topic/binary>>) ->
    {subscribe, KeyId, Topic};
decode_request(_) ->
    {error, unknown_request}.

-spec decrypt_request(binary(), binary(), key(), iv()) ->  {ok, nonce(), request()} |
                             {error, unknown_request} | 
                             {error, plaintext} | 
                             {error, ciphertext} | 
                             {error, cipher_integrity}.
decrypt_request(Id, Message, Key, IV) ->
    case aes_gcm_decrypt(Message, Key, IV, Id) of
        <<?V1, EncNonce:?NONCE_BYTES/binary, Protocol/binary>> ->
            {ok, decode_nonce(EncNonce), decode_request(Protocol)};
        error -> 
            {error, cipher_integrity};
        _ ->
            {error, plaintext}
    end.

encrypt_response(Id, Nonce, Response, Key, IV) -> 
    EncNonce = encode_nonce(Nonce),
    Message = encode_response(Response),
    M = <<?V1, EncNonce/binary, Message/binary>>,   
    aes_gcm_encrypt(M, Key, IV, Id).


decrypt_response(Id, Message, Key, IV) ->
    case aes_gcm_decrypt(Message, Key, IV, Id) of
        <<?V1, EncNonce:?NONCE_BYTES/binary, Protocol/binary>> ->
            {ok, decode_nonce(EncNonce), decode_response(Protocol)};
        error -> 
            {error, cipher_integrity};
        _ ->
            {error, plaintext}
    end.

encode_response({tickets, TicketA, TicketB}) ->
    <<?TICKETS, (length_prefix(TicketA))/binary, (length_prefix(TicketB))/binary>>;
encode_response({session_key, KeyId, Key, Timestamp, Lifetime}) ->
    <<?SESSION_KEY, KeyId:?KEY_ID_BYTES/binary, Key:?KEY_BYTES/binary, Timestamp:64/big-unsigned-integer, Lifetime:16/big-unsigned-integer>>;
encode_response({hello_answer, Key, Nonce}) ->
    EncodedNonce = encode_nonce(Nonce),
    <<?HELLO_ANSWER, Key:?KEY_BYTES/binary, EncodedNonce/binary>>.


%% TODO: add error handling
    
decode_response(<<?TICKETS, Tickets/binary>>) ->
    {TicketA, Rest} = get_length_prefixed_data(Tickets),
    {TicketB, _} = get_length_prefixed_data(Rest),
    {tickets, TicketA, TicketB};
decode_response(<<?SESSION_KEY, KeyId:?KEY_ID_BYTES/binary, Key:?KEY_BYTES/binary, 
                  Timestamp:64/big-unsigned-integer, Lifetime:16/big-unsigned-integer>>) ->
    {session_key, KeyId, Key, Timestamp, Lifetime};
decode_response(<<?HELLO_ANSWER, Key:?KEY_BYTES/binary, EncodedNonce/binary>>) ->
    {hello_response, Key, decode_nonce(EncodedNonce)};
decode_response(_) ->
    {error, unknown_response}.

%%
%% Helpers
%%

length_prefix(Bin) when size(Bin) =< 255 ->
    S = size(Bin),
    <<S:8/unsigned-integer, Bin/binary>>.

get_length_prefixed_data(<<S:8/unsigned-integer, Rest/binary>>) ->
    <<Data:S/binary, More/binary>> = Rest,
    {Data, More}.

% Encryption and decryption uses the convention used in javascript
% subtle crypto to append the tag to the ciphertext.
aes_gcm_encrypt(Message, Key, IV, AdditionalData) ->
    {Msg, Tag} = crypto:crypto_one_time_aead(aes_gcm, Key, IV, Message, AdditionalData, ?AES_GCM_TAG_SIZE, true),
    % {Msg, Tag} = crypto:block_encrypt(aes_gcm, Key, IV, {AdditionalData, Message, ?AES_GCM_TAG_SIZE}),
    <<Msg/binary, Tag/binary>>.

aes_gcm_decrypt(CipherText, Key, IV, AdditionalData) ->
    MessageSize = size(CipherText) - ?AES_GCM_TAG_SIZE,
    <<Msg:MessageSize/binary, Tag:?AES_GCM_TAG_SIZE/binary>> = CipherText,
    crypto:crypto_one_time_aead(aes_gcm, Key, IV, Msg, AdditionalData, Tag, false).
    % crypto:block_decrypt(aes_gcm, Key, IV, {AdditionalData, Msg, Tag}).
