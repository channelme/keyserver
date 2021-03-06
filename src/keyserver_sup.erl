%% @author Maas-Maarten Zeeman <maas@channe.me>
%% @copyright 2018 Maas-Maarten Zeeman
%%
%% @doc Supervisor for a single keyserver.
%%
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

-module(keyserver_sup).
-behaviour(supervisor).

-export([start_link/3]).

% supervisor callback.
-export([init/1]).

start_link(Name, CallbackModule, UserContext) ->
    supervisor:start_link(?MODULE, [Name, CallbackModule, UserContext]).

init([Name, CallbackModule, UserContext]) ->
    KeyPair = keyserver_crypto:generate_keypair(),
    
    {ok, {{one_for_all, 1, 3600},
          [{keyserver_server,
            {keyserver_server, start_link, [Name, KeyPair, CallbackModule, UserContext]},
            permanent, 5000, worker, [keyserver_server]}]}}.
