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

-module(keyserver_app).
-behaviour(application).

%% Application callbacks
-export([start/2, stop/1]).

% @doc Start authy supervisor.
start(_StartType, _StartArgs) ->
    io:fwrite(standard_error, "Starting keyserver supervisor", []),
    keyserver_app_sup:start_link().

% @doc and stop it.
stop(_State) ->
    ok.
