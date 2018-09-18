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


-module(keyserver_utils).
-author("Maas-Maarten Zeeman <maas@channel.me>").

%% calendar:datetime_to_gregorian_seconds({{1970,1,1},{0,0,0}}).
-define(UNIX_EPOCH, 62167219200).

-export([
    unix_time/0,
    unix_time/1,
    unix_time_to_datetime/1
]).

-type timestamp() :: integer().

-export_type([
    timestamp/0
]).

-spec unix_time() -> timestamp().
unix_time() ->
    unix_time(erlang:universaltime()).

-spec unix_time(calendar:datetime()) -> timestamp().
unix_time({{_,_,_},{_,_,_}}=DateTime) ->
    datetime_to_epoch_seconds(DateTime, ?UNIX_EPOCH).

-spec unix_time_to_datetime(timestamp()) -> calendar:datetime().
unix_time_to_datetime(Ts) ->
    epoch_seconds_to_datetime(Ts, ?UNIX_EPOCH).

datetime_to_epoch_seconds({{_,_,_},{_,_,_}}=DateTime, Epoch) ->
    calendar:datetime_to_gregorian_seconds(DateTime) - Epoch.

epoch_seconds_to_datetime(Ts, Epoch) ->
    calendar:gregorian_seconds_to_datetime(Ts + Epoch).


%%
%% Tests
%%

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

unix_time_test() ->
    Ts = unix_time(),
    ?assertEqual(true, is_integer(Ts)),
    ok.

unix_time_epoch_test() ->
    Ts = unix_time({{1970, 1, 1}, {0,0,0}}),
    ?assertEqual(0, Ts),
    ok.

unix_time_known_times_test() ->
    ?assertEqual(315532800, unix_time({{1980, 1, 1}, {0,0,0}})),
    ?assertEqual(26902800, unix_time({{1970, 11, 8}, {9,0,0}})),
    ok.
    
unix_time_to_datetime_test() ->
    ?assertEqual({{1970,1,1}, {0,0,0}}, unix_time_to_datetime(0)),
    ?assertEqual({{1970, 11, 8}, {9,0,0}}, unix_time_to_datetime(26902800)),
    ok.

-endif.
