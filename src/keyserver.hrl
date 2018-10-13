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

-define(MAX_ID_BYTES, 170).

-define(IV_BYTES, 16).     %% 128 bits
-define(KEY_BYTES, 32).    %% 256 bits
-define(KEY_ID_BYTES, 4).  %% 32 bits
-define(NONCE_BYTES, 8).   %% 64 bits
-define(HASH_BYTES, 32).   %% 256 bits

-define(MAX_NONCE, ((1 bsl 64) -1)).

