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
              {ok, EncKey} = keyserver:public_enc_key(test),
                                                                   
              X = keyserver:connect_to_keyserver(test, <<"foo">>, <<"test">>, EncKey),
                                                                   
              io:fwrite(standard_error, "~p~n", [X]),

              ok = keyserver:stop(test)
          end}
     ]
    }.
    
