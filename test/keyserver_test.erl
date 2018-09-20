%% Some tests

-module(keyserver_test).

-include_lib("eunit/include/eunit.hrl").

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
              {ok, _SupPid} = keyserver:start(test),
              ok = keyserver:stop(test)
          end},

      {"Get the public encryption key from the keyserver", fun() -> 
              {ok, _SupPid} = keyserver:start(test),
              {ok, ServerEncKey} = keyserver:public_enc_key(test),
              ok = keyserver:stop(test)
          end},

      {"Connect to the keyserver", fun() -> 
              {ok, _SupPid} = keyserver:start(test),
              {ok, ServerEncKey} = keyserver:public_enc_key(test),
                                                                   
              Key = keyserver_crypto:generate_key(),
              Nonce = keyserver_crypto:generate_nonce(),
                                                                   
              {ok, Nonce1, IV, CipherText} = keyserver:connect_to_server(test, "me", Key, Nonce, ServerEncKey),
                                           
              %% Check the response
              %%
              %% Nonce1 should be > Nonce (in this case +1)
              Nonce1 = keyserver_crypto:inc_nonce(Nonce),

              %% And it should be possible to decrypt the response with Key.
              {hello_answer, _KeyES, _ServerNonce, _Nonce} = keyserver_crypto:decrypt_hello_answer(Nonce1, CipherText, Key, IV),
                      
              ok = keyserver:stop(test)
          end},
      
      {"Setup point to point", fun() -> 
              {ok, _SupPid} = keyserver:start(test),
              {ok, ServerEncKey} = keyserver:public_enc_key(test),
                                                                   
              AliceKey = keyserver_crypto:generate_key(),
              AliceNonce = keyserver_crypto:generate_nonce(),

              BobKey = keyserver_crypto:generate_key(),
              BobNonce = keyserver_crypto:generate_nonce(),
                                       
                                                                   
              {ok, AliceNonce1, IVAlice, AliceCipherText} = keyserver:connect_to_server(test, "alice", AliceKey, AliceNonce, ServerEncKey),
              {ok, BobNonce1, IVBob, BobCipherText} = keyserver:connect_to_server(test, "bob", BobKey, BobNonce, ServerEncKey),


              {hello_answer, KeyAliceServer, _ServerNonce, _Nonce} = keyserver_crypto:decrypt_hello_answer(AliceNonce1, AliceCipherText, AliceKey, IVAlice),
              {hello_answer, KeyBobServer, _, _} = keyserver_crypto:decrypt_hello_answer(BobNonce1, BobCipherText, BobKey, IVBob),

              %% 
              {ok, SNonce1, IVS, Result} = keyserver:p2p_request(test, "alice", "bob", AliceNonce1, KeyAliceServer),
                                       
              ?assertMatch({p2p_response, _,_,_}, 
                             keyserver_crypto:decrypt_p2p_response(SNonce1, Result, KeyAliceServer, IVS)),

              ok = keyserver:stop(test)
          end}
     ]
    }.
    
