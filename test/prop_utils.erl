-module(prop_utils).
-include_lib("proper/include/proper.hrl").

%%%%%%%%%%%%%%%%%%
%%% Properties %%%
%%%%%%%%%%%%%%%%%%

prop_unix_time_to_datetime() ->
    ?FORALL(Timestamp, timestamp(),
	    begin
		case keyserver_utils:unix_time_to_datetime(Timestamp) of
		    {{_, _, _}, {_, _, _}} = Datetime -> 
			%% A date time tuple was created, now check if
			%% this is the timestamp.
			Timestamp =:= keyserver_utils:unix_time(Datetime);
		    _ -> 
			false
		end
	    end).


timestamp() -> 
    %% Cover a wide range of integers
    resize(1 bsl 31 - 1, range(0, 1 bsl 64 - 1)).
