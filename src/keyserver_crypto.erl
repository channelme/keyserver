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
-define(PUBLISH, $P).
-define(SUBSCRIBE, $S).
-define(DIRECT, $D).
-define(TICKETS, $T).
-define(SESSION_KEY, $K).

-export([
    generate_key/0,
    generate_key_id/0,
    generate_iv/0,
    generate_nonce/0,
         
    hash/1,

    inc_nonce/1,

    encrypt_hello/3,
    decrypt_hello/2,

    encrypt_hello_answer/3,
    decrypt_hello_answer/4,

    create_p2p_ticket/5,

    encrypt_session_key/7,
    decrypt_session_key/4,
         
    encrypt_request/5,
    decrypt_request/4,
         
    encrypt_response/5,
    decrypt_response/4,

    encrypt_secure_publish/3,
    decrypt_secure_publish/3
]).

-include("keyserver.hrl").

-type nonce() :: 0..?MAX_NONCE.
-type key_id() :: <<_:(?KEY_ID_BYTES*8)>>.
-type key() :: <<_:(?KEY_BYTES*8)>>.
-type iv() :: <<_:(?IV_BYTES*8)>>.
-type pub_enc_key() :: crypto:rsa_public().
-type hash() :: <<_:(?HASH_BYTES*8)>>.
-type encoded_nonce() :: <<_:(?NONCE_BYTES*8)>>.

-type timestamp() :: <<_:(?HASH_BYTES*8)>>.
-type p2p_ticket() :: binary().

-export_type([
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

-spec encrypt_hello(key(), nonce(), pub_enc_key()) -> binary(). 
encrypt_hello(EncKey, Nonce, ServerEncKey) ->
    EncNonce = encode_nonce(Nonce),
    crypto:public_encrypt(rsa, 
        <<"hello", EncKey/binary, EncNonce/binary>>, ServerEncKey, rsa_pkcs1_oaep_padding).

decrypt_hello(Message, PrivateKey) ->
    case crypto:private_decrypt(rsa, Message, PrivateKey, rsa_pkcs1_oaep_padding) of
        <<"hello", EEncKey:?KEY_BYTES/binary, Nonce:?NONCE_BYTES/binary>> ->
            {hello, EEncKey, decode_nonce(Nonce)};
        Bin when is_binary(Bin) ->
            {error, message}
    end.

encrypt_hello_answer({hello_answer, KeyES, ServerNonce, Nonce}, EncKey, IV) ->
    EncNonce = encode_nonce(Nonce),
    EncServerNonce = encode_nonce(ServerNonce),
    Message = <<"hello_answer", KeyES/binary, EncServerNonce/binary, EncNonce/binary>>,
    encrypt_message(Message, EncNonce, EncKey, IV).

decrypt_hello_answer(Nonce, Message, EncKey, IV) ->
    %% TODO: no check on the nonce is done here.
    case decrypt_message(Message, Nonce, EncKey, IV) of
        <<"hello_answer", KeyES:?KEY_BYTES/binary, SNonce:?NONCE_BYTES/binary, EncNonce:?NONCE_BYTES/binary>> -> 
            {hello_answer, KeyES, decode_nonce(SNonce), decode_nonce(EncNonce)};
        Bin when is_binary(Bin) -> {error, plain_msg};
        {error, _}=E -> E
    end.


% -spec create_p2p_ticket() -> p2p_ticket().
create_p2p_ticket(Key, Timestamp, Lifetime, OtherId, EncKey) ->
    Ticket = <<Timestamp:64/big-unsigned-integer, Lifetime:16/big-unsigned-integer, Key/binary, OtherId/binary>>,
    IV = keyserver_crypto:generate_iv(),
    {Msg, Tag} = crypto:block_encrypt(aes_gcm, EncKey, IV, {OtherId, Ticket, ?AES_GCM_TAG_SIZE}),
    <<"p2p-ticket", IV/binary, $:, Tag/binary, $:, Msg/binary>>.


%% TODO: same as above.
encrypt_session_key(Nonce, SessionKeyId, SessionKey, Timestamp, Lifetime, Key, IV) ->
    EncNonce = encode_nonce(Nonce),
    
    Message = <<"session-key", EncNonce/binary, 
                SessionKeyId/binary, SessionKey/binary,
                Timestamp:64/big-unsigned-integer, Lifetime:16/big-unsigned-integer>>,

    encrypt_message(Message, EncNonce, Key, IV).

decrypt_session_key(Nonce, Message, Key, IV) ->
     case decrypt_message(Message, Nonce, Key, IV) of
        <<"session-key", EncNonce:?NONCE_BYTES/binary, 
          SessionKeyId:?KEY_ID_BYTES/binary, SessionKey:?KEY_BYTES/binary,
          Timestamp:64/big-unsigned-integer, Lifetime:16/big-unsigned-integer>> ->
            case Nonce =:= decode_nonce(EncNonce) of
                false ->
                    {error, nonce};
                true ->
                    {session_key, SessionKeyId, SessionKey, Timestamp, Lifetime, Nonce}
            end;
        Bin when is_binary(Bin) -> {error, plain_msg};
        {error, _}=Error -> Error
    end.


encrypt_secure_publish(Message, KeyId, Key) when size(KeyId) =:= ?KEY_ID_BYTES andalso size(Key) =:= ?KEY_BYTES ->
    IV = keyserver_crypto:generate_iv(),
    {Msg, Tag} = crypto:block_encrypt(aes_gcm, Key, IV, {KeyId, Message, ?AES_GCM_TAG_SIZE}),
    <<"sec-pub", IV/binary, $:, Tag/binary, $:, Msg/binary>>.

decrypt_secure_publish(<<"sec-pub", IV:?IV_BYTES/binary, $:, Tag:?AES_GCM_TAG_SIZE/binary, $:, Msg/binary>>, KeyId, Key) when size(KeyId) =:= ?KEY_ID_BYTES andalso size(Key) =:= ?KEY_BYTES ->
    case crypto:block_decrypt(aes_gcm, Key, IV, {KeyId, Msg, Tag}) of
        Bin when is_binary(Bin) -> {ok, Bin};
        {error, _}=Error -> Error
    end.
    
encrypt_request(Id, Nonce, Request, Key, IV) ->
    EncNonce = encode_nonce(Nonce),
    Message = encode_request(Request),
    M = <<?V1, EncNonce/binary, Message/binary>>,   
    {Msg, Tag} = crypto:block_encrypt(aes_gcm, Key, IV, {Id, M, ?AES_GCM_TAG_SIZE}),
    <<Tag/binary, $:, Msg/binary>>.

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

-spec decrypt_request(binary(), binary(), key(), iv()) -> 
                             {direct, binary()} | 
                             {publish, binary()} | 
                             {subscribe, key_id(), binary()} | 
                             {error, unknown_request} | 
                             {error, plaintext} | 
                             {error, ciphertext} | 
                             {error, cipher_integrity}.
decrypt_request(Id, Message, Key, IV) ->
    case Message of
        <<Tag:?AES_GCM_TAG_SIZE/binary, $:, Msg/binary>> ->
            case crypto:block_decrypt(aes_gcm, Key, IV, {Id, Msg, Tag}) of
                <<?V1, EncNonce:?NONCE_BYTES/binary, Protocol/binary>> ->
                    {ok, decode_nonce(EncNonce), decode_request(Protocol)};
                error -> 
                    {error, cipher_integrity};
                _ ->
                    {error, plaintext}
            end;
        _ ->
            {error, ciphertext}
    end.

encrypt_response(Id, Nonce, Response, Key, IV) -> 
    EncNonce = encode_nonce(Nonce),
    Message = encode_response(Response),
    M = <<?V1, EncNonce/binary, Message/binary>>,   
    {Msg, Tag} = crypto:block_encrypt(aes_gcm, Key, IV, {Id, M, ?AES_GCM_TAG_SIZE}),
    <<Tag/binary, $:, Msg/binary>>.


decrypt_response(Id, Message, Key, IV) ->
    %% TODO: merge with decrypt request.
    case Message of
        <<Tag:?AES_GCM_TAG_SIZE/binary, $:, Msg/binary>> ->
            case crypto:block_decrypt(aes_gcm, Key, IV, {Id, Msg, Tag}) of
                <<?V1, EncNonce:?NONCE_BYTES/binary, Protocol/binary>> ->
                    {ok, decode_nonce(EncNonce), decode_response(Protocol)};
                error -> 
                    {error, cipher_integrity};
                _ ->
                    {error, plaintext}
            end;
        _ ->
            {error, ciphertext}
    end.

encode_response({tickets, TicketA, TicketB}) ->
    <<?TICKETS, (length_prefix(TicketA))/binary, (length_prefix(TicketB))/binary>>;
encode_response({session_key, KeyId, Key, Timestamp, Lifetime}) ->
    <<?SESSION_KEY, KeyId:?KEY_ID_BYTES/binary, Key:?KEY_BYTES/binary, Timestamp:64/big-unsigned-integer, Lifetime:16/big-unsigned-integer>>.
%% TODO: add error handling
    
decode_response(<<?TICKETS, Tickets/binary>>) ->
    {TicketA, Rest} = get_length_prefixed_data(Tickets),
    {TicketB, _} = get_length_prefixed_data(Rest),
    {tickets, TicketA, TicketB};
decode_response(<<?SESSION_KEY, KeyId:?KEY_ID_BYTES/binary, Key:?KEY_BYTES/binary, 
                  Timestamp:64/big-unsigned-integer, Lifetime:16/big-unsigned-integer>>) ->
    {session_key, KeyId, Key, Timestamp, Lifetime};
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

encrypt_message(Message, Nonce, Key, IV) ->
    %% Use the nonce as associated authentication data.
    EncNonce = encode_nonce(Nonce),
    {Msg, Tag} = crypto:block_encrypt(aes_gcm, Key, IV, {EncNonce, Message, ?AES_GCM_TAG_SIZE}),
    <<Tag/binary, $:, Msg/binary>>.
            
decrypt_message(<<Tag:?AES_GCM_TAG_SIZE/binary, $:, Msg/binary>>, Nonce, Key, IV) when size(Key) =:= ?KEY_BYTES->
    EncNonce = encode_nonce(Nonce),
    case crypto:block_decrypt(aes_gcm, Key, IV, {EncNonce, Msg, Tag}) of
        error -> {error, cipher_integrity};
        Data when is_binary(Data) -> Data
    end;
decrypt_message(_Msg, _Nonce, _Key, _IV) ->
    {error, cipher_msg}.

