
-module(erpcap).

-export([start/0, stop/0, init/0]).
-export([list/0, open/1]).
-export([send/1]).

-define(CMD_LISTIF, 1).
-define(CMD_BINDIF, 2).

start() ->
    _Interface = application:get_env(erpcap, interface),
    spawn(?MODULE, init, []).

stop() ->
    erpcap ! stop.

list() ->
    call_port({list}).

open(Interface) ->
    call_port({open, Interface}).

send(Packet) ->
    call_port({send, Packet}).

call_port(Msg) ->
    erpcap ! {call, self(), Msg},
    receive
        {erpcap, Result} ->
            Result
    end.

init() ->
    register(erpcap, self()),
    process_flag(trap_exit, true),
    Port = open_port({spawn, erpcap}, [{packet, 2}]),
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

encode({list}) -> [1];
encode({open, Interface}) -> [2, Interface];
encode({send, Packet}) -> [3, Packet].

decode([1 | IfListMsg]) ->
    io:format("IfListMsg ~w~n", [IfListMsg]),
    IfListMsg;
decode([Msg]) -> Msg.

ifInfo(<NameLen, Rest)
ifListMsg(<Count, Msg>) ->
    
deLenVal(<Len, Data>) ->
    <Value/Len:binary, Rest> = Data,