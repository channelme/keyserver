
-module(keyserver_app_sup).
-behaviour(supervisor).

-export([init/1]).

-export([
    start_link/0,
    stop/0,
    start_keyserver/3
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

start_keyserver(Name, Limit, MFA) ->
    ChildSpec = {Name,
                 {keyserver_sup, start_link, [Name, Limit, MFA]},
                 permanent, 10000, supervisor, [keyserver_sup]},
    supervisor:start_child(?MODULE, ChildSpec).

init([]) ->
    {ok, {{one_for_one, 6, 3600}, []}}.
