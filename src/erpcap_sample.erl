
-module(erpcap_sample).

-export([start/0, stop/0]).

start() ->
    erpcap:start("\\Device\\NPF_{97501407-6BF5-4D31-ADC4-5AFBD53A2192}"),
    send_arp(),
    erpcap:reg_handler(fun(Pkt)-> dump_l2(Pkt) end).

stop() ->
    erpcap:stop().

send_arp() ->
    erpcap:send(<<16#FF, 16#FF, 16#FF, 16#FF, 16#FF, 16#FF,
                  16#00, 16#01, 16#02, 16#03, 16#04, 16#05,
                  16#08, 16#06,
                  16#00, 16#00, 16#00, 16#00,
                  16#00, 16#00, 16#00, 16#00,
                  16#00, 16#00, 16#00, 16#00,
                  16#00, 16#00, 16#00, 16#00>>).

dump_l2(Packet) when byte_size(Packet) < 14 ->
    io:format("Packet ~w too short ~n", [Packet]);
dump_l2(Packet) ->
    <<Dst:6/binary, Src:6/binary, EthType:16/big-integer, Data/binary>> = Packet,
    io:format("L2 Header:~n"),
    io:format("  Destination:~w~n", [Dst]),
    io:format("  Source:~w~n", [Src]),
    io:format("  EthType:~w~n", [EthType]),
    io:format("  Data Length:~w~n", [byte_size(Data)]),
    io:format("~n").
