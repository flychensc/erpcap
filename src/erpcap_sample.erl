
-module(erpcap_sample).

-export([start/0, stop/0]).

start() ->
    erpcap:start("\\Device\\NPF_{97501407-6BF5-4D31-ADC4-5AFBD53A2192}").

stop() ->
    erpcap:stop().
