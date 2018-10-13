%% Crypto tests

-module(keyserver_crypto_test).

-include_lib("eunit/include/eunit.hrl").

encrypt_hello_test() ->
    {PubEnc, PrivKey} = keyserver_crypto:generate_keypair(),
    Key = keyserver_crypto:generate_key(),
    Nonce = keyserver_crypto:generate_nonce(),

    M = keyserver_crypto:encrypt_hello(<<"my-id">>, Key, Nonce, PubEnc),
    {hello, <<"my-id">>, Key, Nonce} = keyserver_crypto:decrypt_hello(M, PrivKey),

    MaxId = <<"01234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789">>,

    M2 = keyserver_crypto:encrypt_hello(MaxId, Key, Nonce, PubEnc),
    
    {hello, MaxId, Key, Nonce} = keyserver_crypto:decrypt_hello(M2, PrivKey),
    
    ok.
    
    
