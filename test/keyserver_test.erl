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
                                                                   
              Key = keyserver:generate_key(),
              Nonce = keyserver:generate_nonce(),
                                                                   
              {ok, Nonce1, IV, CipherTag, CipherText} = keyserver:connect_to_server(test, Key, Nonce, ServerEncKey),
                                           
              %% Check the response
              %%
              %% Nonce1 should be > Nonce (in this case +1)
              Nonce1 = keyserver:inc_nonce(Nonce),

              %% And it should be possible to decrypt the response with Key.
              <<"hello_answer", _/binary>> = crypto:block_decrypt(aes_gcm, Key, IV, {Nonce1, CipherText, CipherTag}),
                      
              ok = keyserver:stop(test)
          end}
     ]
    }.
    
