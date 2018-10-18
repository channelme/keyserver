%% Some tests

-module(keyserver_test).

-include_lib("eunit/include/eunit.hrl").

-export([is_allowed/3]).

%% Callback functions 
is_allowed(connect, _Args, _Context) -> true;
is_allowed(publish, _Args, _Context) -> true;
is_allowed(subscribe, _Args, _Context) -> true;
is_allowed(communicate, _Args, _Context) -> true;
is_allowed(_, _, _) -> false.

setup() ->
    application:start(keyserver).

teardown(_) ->
    application:stop(keyserver).

application_start_stop_test() ->
    ?assertEqual(ok, setup()),
    ?assertEqual(ok, teardown([])).


keyserver_test_() ->
    {setup,
     fun setup/0,
     fun teardown/1,
     [
      {"Test starting and stopping a keyserver", fun() -> 
              {ok, _SupPid} = keyserver:start(test, ?MODULE, []),
              ok = keyserver:stop(test)
          end},

      {"Get the public encryption key from the keyserver", fun() -> 
              {ok, _SupPid} = keyserver:start(test, ?MODULE, []),
              {ok, ServerEncKey} = keyserver:public_enc_key(test),
              ok = keyserver:stop(test)
          end},

      {"Connect to the keyserver", fun connect/0},
      {"Setup point to point", fun point_to_point/0},
      {"Secure subscribe", fun secure_subscribe/0},
      {"Secure publish", fun secure_publish/0}
     ]
    }.

connect() ->
    {ok, _SupPid} = keyserver:start(test, ?MODULE, []),
    {ok, ServerEncKey} = keyserver:public_enc_key(test),

    Key = keyserver_crypto:generate_key(),
    Nonce = keyserver_crypto:generate_nonce(),

    {ok, _ServerNonce, {hello_response, _KeyES, Nonce1}} = keyserver:connect(test, <<"me">>, Key, Nonce, ServerEncKey),
    %% Check the response
    %%
    %% Nonce1 should be > Nonce (in this case +1)
    Nonce1 = keyserver_crypto:inc_nonce(Nonce),

    ok = keyserver:stop(test).

point_to_point() ->
    {ok, _SupPid} = keyserver:start(test, ?MODULE, []),
    {ok, ServerEncKey} = keyserver:public_enc_key(test),
                                                                   
    AliceKey = keyserver_crypto:generate_key(),
    AliceNonce = keyserver_crypto:generate_nonce(),

    BobKey = keyserver_crypto:generate_key(),
    BobNonce = keyserver_crypto:generate_nonce(),

    {ok, _ServerNonce, {hello_response, KeyAliceServer, AliceNonce1}} =
        keyserver:connect(test, <<"alice">>, AliceKey, AliceNonce, ServerEncKey),

    {ok, _, {hello_response, KeyBobServer, _}} =
        keyserver:connect(test, <<"bob">>, BobKey, BobNonce, ServerEncKey),

    R = keyserver:p2p_request(test, <<"alice">>, <<"bob">>, AliceNonce1, KeyAliceServer),
    ?assertMatch({ok, _, {tickets, _, _}}, R),

    {ok, _, {tickets, AliceTicket, BobTicket}} = R,
    IV = keyserver_crypto:generate_iv(),
    CipherText = keyserver_crypto:p2p_encrypt(<<"alice">>, <<"Hello Bob, this is Alice.">>, AliceTicket, KeyAliceServer, IV),
    ?assertEqual(<<"Hello Bob, this is Alice.">>,
                 keyserver_crypto:p2p_decrypt(<<"bob">>, <<"alice">>, CipherText, BobTicket, KeyBobServer, IV)),

    ok = keyserver:stop(test).


secure_subscribe() ->
    {ok, _SupPid} = keyserver:start(test, ?MODULE, []),
    {ok, ServerEncKey} = keyserver:public_enc_key(test),

    AliceKey = keyserver_crypto:generate_key(),
    AliceNonce = keyserver_crypto:generate_nonce(),

    {ok, _ServerNonce, {hello_response, KeyAliceServer, AliceNonce1}} =
        keyserver:connect(test, <<"alice">>, AliceKey, AliceNonce, ServerEncKey),

    %% Register a key
    R = keyserver:secure_publish(test, <<"alice">>, <<"test/test/test">>, AliceNonce1, KeyAliceServer),
    ?assertMatch({ok, _, {session_key, _, _, _, _}}, R),
    
    {ok, _Nonce, {session_key, SessionKeyId, SessionKey, Timestamp, Lifetie}} = R,

    %% Now it must be possible to retrieve the key.

    SR = keyserver:secure_subscribe(test, <<"alice">>, SessionKeyId, <<"test/test/test">>, AliceNonce1, KeyAliceServer),
    ?assertMatch({ok, _, {session_key, _, _, _, _}}, SR),

    %% It should be the same key 
    {ok, _, {session_key, SesKeyId, SesKey, _Ts1, _Lt1}} = SR,
    
    ok = keyserver:stop(test).

secure_publish() ->
    {ok, _SupPid} = keyserver:start(test, ?MODULE, []),
    {ok, ServerEncKey} = keyserver:public_enc_key(test),

    AliceKey = keyserver_crypto:generate_key(),
    AliceNonce = keyserver_crypto:generate_nonce(),

    {ok, _ServerNonce, {hello_response, KeyAliceServer, AliceNonce1}} =
        keyserver:connect(test, <<"alice">>, AliceKey, AliceNonce, ServerEncKey),

    R = keyserver:secure_publish(test, <<"alice">>, <<"test/test/test">>, AliceNonce1, KeyAliceServer),

    ?assertMatch({ok, _Nonce, {session_key, _, _, _, _}}, R),
    {ok, Nonce, {session_key, SessionKeyId, SessionKey, Timestamp, Lifetie}} = R,

    ok = keyserver:stop(test).
