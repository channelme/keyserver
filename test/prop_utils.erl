-module(prop_utils).
-include_lib("proper/include/proper.hrl").

-define(TS_MAX, ((1 bsl 64) -1)).

%%%%%%%%%%%%%%%%%%
%%% Properties %%%
%%%%%%%%%%%%%%%%%%

prop_unix_time_to_datetime() ->
    ?FORALL(Timestamp, integer(0, ?TS_MAX),
	    begin
		case keyserver_utils:unix_time_to_datetime(Timestamp) of
		    {{_, _, _}, {_, _, _}} = Datetime -> 
			Timestamp =:= keyserver_utils:unix_time(Datetime);
		    _ -> 
			false
		end
	    end).

