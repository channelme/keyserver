-module(prop_server).
-include_lib("proper/include/proper.hrl").

%%%%%%%%%%%%%%%%%%
%%% Properties %%%
%%%%%%%%%%%%%%%%%%

-export([is_allowed/3]).

%% Callback functions
is_allowed(connect, _Args, _Context) -> true;
is_allowed(publish, _Args, _Context) -> true;
is_allowed(subscribe, _Args, _Context) -> true;
is_allowed(communicate, _Args, _Context) -> true;
is_allowed(_, _, _) -> false.


prop_start_stop() ->
    {PubKey, _} = KeyPair = keyserver_crypto:generate_keypair(),
    ?FORALL({Name, Ids}, {atom(), list(binary())},
	    begin
		keyserver_server:start_link(Name, KeyPair, ?MODULE, []),
		{ok, PubKey} = keyserver_server:public_enc_key(Name),

		Registered = register_all(Ids, Name, PubKey, #{}),
                
                true = valid_responses(Name, Ids, Registered),

		ok =:= keyserver_server:stop(Name)
	    end).

%%
%% Helpers
%%

valid_responses(_Name, [], _Registered) ->
    true;
valid_responses(Name, [Id|Rest], Registered) ->
    case maps:find(Id, Registered) of
        {ok, R} -> 
            case valid_response(Name, R) of
                true -> valid_responses(Name, Rest, Registered);
                _ -> false
            end;
        error -> false
    end.

valid_response(Name, #{key := Key, nonce := Nonce, encrypted_response := ER, iv := IV }) ->
    {ok, _ServerNonce, {hello_response, _KeyES, Nonce1}} =
        keyserver_crypto:decrypt_response(z_convert:to_binary(Name), ER, Key, IV),
    Nonce1 = keyserver_crypto:inc_nonce(Nonce),
    true;
valid_response(_Name, _E) ->
    io:fwrite(standard_error, "R: ~p~n", [_E]),
    false.
     

register_all([], _Name, _Key, Registered) -> Registered;
register_all([Id|Rest], Name, Key, Registered) ->
    case maps:find(Id, Registered) of 	   
        error ->
            %% This id is not yet registered. Registering should work 
	    ClientKey = keyserver_crypto:generate_key(),
	    ClientNonce = keyserver_crypto:generate_nonce(),
	    Message = keyserver_crypto:encrypt_hello(ClientKey, ClientNonce, Key),

            {ok, ER, IV} = keyserver_server:connect_to_server(Name, Id, Message),

            register_all(Rest, Name, Key, Registered#{Id => #{key => ClientKey, 
                                                              nonce => ClientNonce,
                                                              encrypted_response => ER,
                                                              iv => IV}});
        {ok, _} ->
            %% This client is already connected... make sure
            ClientKey = keyserver_crypto:generate_key(),
	    ClientNonce = keyserver_crypto:generate_nonce(),
	    Message = keyserver_crypto:encrypt_hello(ClientKey, ClientNonce, Key),

            {error, already_connected} = keyserver_server:connect_to_server(Name, Id, Message),

            register_all(Rest, Name, Key, Registered)
    end.
