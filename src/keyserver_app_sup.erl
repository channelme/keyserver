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

-module(keyserver_app_sup).
-behaviour(supervisor).

-export([init/1]).

-export([
    start_link/0,
    stop/0,

    start_keyserver/1,
    stop_keyserver/1
]).

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

%% Brutal kill the supervisor.
stop() ->
    case whereis(?MODULE) of
        Pid when is_pid(Pid) ->
            exit(Pid, kill);
        _ -> ok
    end.

start_keyserver(Name) ->
    ChildSpec = {Name,
                 {keyserver_sup, start_link, [Name]},
                 permanent, 10000, supervisor, [keyserver_sup]},
    supervisor:start_child(?MODULE, ChildSpec).

stop_keyserver(Name) ->
    case supervisor:terminate_child(?MODULE, Name) of
        ok -> 
            case supervisor:delete_child(?MODULE, Name) of
                ok -> ok;
                {error, _} = Error -> Error
            end;
        {error, not_found} ->
            ok
    end.

init([]) ->
    {ok, {{one_for_one, 6, 3600}, []}}.
