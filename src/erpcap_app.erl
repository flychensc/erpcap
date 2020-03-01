%%%-------------------------------------------------------------------
%% @doc erpcap public API
%% @end
%%%-------------------------------------------------------------------

-module(erpcap_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    erpcap_sup:start_link().

stop(_State) ->
    ok.

%% internal functions
