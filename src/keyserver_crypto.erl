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

-module(keyserver_crypto).
-author("Maas-Maarten Zeeman <maas@channel.me>").

-export([
    generate_key/0,
    generate_iv/0,
    generate_nonce/0,

    inc_nonce/1
         
]).

-include("keyserver.hrl").

-type key() :: <<_:(?KEY_BYTES*8)>>.
-type nonce() :: <<_:(?NONCE_BYTES*8)>>.

-export_type([
    key/0,
    nonce/0
]).


-spec generate_key() -> key().
generate_key() ->
    crypto:strong_rand_bytes(?KEY_BYTES).

-spec generate_iv() -> <<_:128>>.
generate_iv() ->
    crypto:strong_rand_bytes(16).
    
-spec generate_nonce() -> nonce().
generate_nonce() ->
    crypto:strong_rand_bytes(?NONCE_BYTES).


-spec inc_nonce(integer() | nonce()) -> nonce().
inc_nonce(Nonce) when is_binary(Nonce) ->
    <<N:64>> = Nonce,
    inc_nonce(N);
inc_nonce(Nonce) when is_integer(Nonce) ->
    Nonce1 = Nonce + 1,
    <<Nonce1:64>>.
