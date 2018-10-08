-module(prop_server).
-include_lib("proper/include/proper.hrl").

%%%%%%%%%%%%%%%%%%
%%% Properties %%%
%%%%%%%%%%%%%%%%%%

-export([is_allowed/3]).

%% Callback functions
is_allowed(publish, _Args, _Context) -> true;
is_allowed(subscribe, _Args, _Context) -> true;
is_allowed(communicate, _Args, _Context) -> true;
is_allowed(_, _, _) -> false.


prop_start_stop() ->
    {PubKey, _} = KeyPair = keyserver_crypto:generate_keypair(),
    ?FORALL({Name, Ids}, {atom(), list(binary())},
	    begin
		io:fwrite(standard_error, "list: ~p~n", [Ids]),
		keyserver_server:start_link(Name, KeyPair, ?MODULE, []),
		{ok, PubKey} = keyserver_server:public_enc_key(Name),

		register_all(Ids, Name, PubKey),

		ok =:= keyserver_server:stop(Name)
	    end).

%%
%% Helpers
%%

register_all([], _Name, _Key) -> done;
register_all([Id|Rest], Name, Key) ->
    ClientKey = keyserver_crypto:generate_key(),
    ClientNonce = keyserver_crypto:generate_nonce(),
    Message = keyserver_crypto:encrypt_hello(ClientKey, ClientNonce, Key),

    {ok, ER, IV} = keyserver_server:connect_to_server(Name, Id, Message),
    io:fwrite(standard_error, "R: ~p: ~p ~n", [ER, IV]),

    register_all(Rest, Name, Key).
