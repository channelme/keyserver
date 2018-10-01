%% Some tests

-module(keyserver_test).

-include_lib("eunit/include/eunit.hrl").

-export([is_allowed/3]).

%% Callback functions 
is_allowed(publish, _Args, _Context) -> true;
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
      {"Secure publish", fun secure_publish/0}
     ]
    }.

connect() ->
    {ok, _SupPid} = keyserver:start(test, ?MODULE, []),
    {ok, ServerEncKey} = keyserver:public_enc_key(test),

    Key = keyserver_crypto:generate_key(),
    Nonce = keyserver_crypto:generate_nonce(),

    {hello_answer, _KeyES, _ServerNonce, Nonce1} = keyserver:connect_to_server(test, "me", Key, Nonce, ServerEncKey),

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

    {hello_answer, KeyAliceServer, _ServerNonce, AliceNonce1} = 
        keyserver:connect_to_server(test, "alice", AliceKey, AliceNonce, ServerEncKey),

    {hello_answer, KeyBobServer, _, _} =
        keyserver:connect_to_server(test, "bob", BobKey, BobNonce, ServerEncKey),

    %% 
    {ok, SNonce1, IVS, Result} = keyserver:p2p_request(test, "alice", "bob", AliceNonce1, KeyAliceServer),

    ?assertMatch({p2p_response, _,_,_}, 
                 keyserver_crypto:decrypt_p2p_response(SNonce1, Result, KeyAliceServer, IVS)),

    ok = keyserver:stop(test).


secure_publish() ->
    {ok, _SupPid} = keyserver:start(test, ?MODULE, []),
    {ok, ServerEncKey} = keyserver:public_enc_key(test),

    AliceKey = keyserver_crypto:generate_key(),
    AliceNonce = keyserver_crypto:generate_nonce(),

    %% 
    {hello_answer, KeyAliceServer, _ServerNonce, AliceNonce1} =
        keyserver:connect_to_server(test, "alice", AliceKey, AliceNonce, ServerEncKey),

    R = keyserver:secure_publish(test, "alice", <<"test/test/test">>, AliceNonce1, KeyAliceServer),
    ?assertMatch({publish_response, _, _, _, _, _}, R),
    {publish_response, SesKeyId, SesKey, _Ts, _Lt, _N} = R,
    
    %% We know the key...
    Message = <<"Hallo allemaal">>,
    CipherText = keyserver_crypto:encrypt_secure_publish(Message, SesKeyId, SesKey),
    {ok, Message} = keyserver_crypto:decrypt_secure_publish(CipherText, SesKeyId, SesKey),

    ok = keyserver:stop(test).
  
