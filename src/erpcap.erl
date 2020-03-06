
-module(erpcap).

-export([start/0]).

-define(CMD_LISTIF, 1).
-define(CMD_BINDIF, 2).

start() ->
    IF_Name = application:get_env(erpcap, if_name),
    io:format("Interface Name:~w~n", [IF_Name]),
    Port = open_port({spawn, erpcap}, [{packet, 2}]),
    Port ! {self(), {command, ?CMD_LISTIF}},
    read_replies(Port).

read_replies(Port) ->
    receive
        {Port, _Msg} ->
            io:format("erlang received from port:~n"),
            read_replies(Port)
    end.
