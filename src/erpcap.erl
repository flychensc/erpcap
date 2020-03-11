
-module(erpcap).

-export([start/1, stop/0, init/1]).
-export([send/1]).

start(Interface) ->
    % io:format("start erpcap on ~w~n", [Interface]),
    spawn(?MODULE, init, [Interface]).

stop() ->
    erpcap ! stop.

send(Packet) ->
    call_port({send, Packet}).

call_port(Msg) ->
    erpcap ! {call, self(), Msg},
    receive
        {erpcap, Result} ->
            Result
    end.

init(Interface) ->
    register(erpcap, self()),
    process_flag(trap_exit, true),
    Command = unicode:characters_to_list("erpcap -b ", Interface),
    % io:format("Command:~s~n", [Command]),
    Port = open_port({spawn, Command}, [{packet, 2}]),
    loop(Port).

loop(Port) ->
    receive
        {call, Caller, Msg} ->
            Port ! {self(), {command, encode(Msg)}},
            receive
                {Port, {data, Data}} ->
                    Caller ! {complex, decode(Data)}
            end,
            loop(Port);
        stop ->
            Port ! {self(), close},
            receive
                {Port, closed} ->
                    exit(normal)
            end;
        {'EXIT', Port, Reason} ->
            io:format("exit b/z ~w~n", [Reason]),
            exit(port_terminated)
    end.

encode({send, Packet}) -> <<Packet>>.

decode([Packet]) ->
    io:format("Recv Packet ~w~n", [Packet]),
    Packet.
