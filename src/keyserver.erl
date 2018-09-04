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

-module(keyserver).
-author("Maas-Maarten Zeeman <maas@channel.me>").


-export([
    start/1,
    stop/1,

    public_enc_key/1,
    connect_to_keyserver/4,
    session_key_request/1
]).


start(Name) when is_atom(Name) ->
    keyserver_app_sup:start_keyserver(Name).

stop(Name) when is_atom(Name) ->
    keyserver_app_sup:stop_keyserver(Name).

%% Get the public encryption key of the keyserver.
public_enc_key(Name) when is_atom(Name) ->
    keyserver_server:public_enc_key(Name).
    
connect_to_keyserver(Name, Key, Nonce, PubEncKey) ->
    crypto:public_encrypt(rsa, <<"dit is een test, asdfasf  sdf sad asd f a hallo hallo hallo dfaskfiasfdkasjdfk,asjfajslfjaslfjaslkdjflasdjfasd fs df sadfds f fads sdf saf asfdas f asdf asd fas df daf a  df dssdfgsdfg sdf gsdfgsd g sdg dg sdf gsd g sdg sdf gsdfg 123 132 123 123 1 2313 13 1 3 13 1 3 13  13 123123123 123 13 123 12 31 23 123 1 23 123 13 12 3 13 123 13  dsgdsgdsg dg dfg ds g asfasdf asdf s df asf as f as f asf as df sa f sdf as fd sd f sadf s df sfd safd s df as f asd f as fdasdfsdf sadf s adf sda  fsd fs sd as  as f safdsadfasf asdf asdf a sfd as fas f asd f asfasd fasdfasdfsd fasd f sdf wre rwe r wer we r r wer e e rwew rasdf sadf asd sf afa sdf sd f sdgallo">>, PubEncKey, rsa_pkcs1_oaep_padding).

session_key_request(_Pid) ->
    ok.

