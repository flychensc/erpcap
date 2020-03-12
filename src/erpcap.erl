
-module(erpcap).

-export([start/1, stop/0, init/1]).
-export([send/1, reg_handler/1]).

start(Interface) ->
    % io:format("start erpcap on ~w~n", [Interface]),
    spawn(?MODULE, init, [Interface]).

stop() ->
    erpcap ! stop.

send(Packet) ->
    erpcap ! {send, Packet}.

reg_handler(Handler) ->
    erpcap ! {reg, Handler}.

init(Interface) ->
    register(erpcap, self()),
    process_flag(trap_exit, true),
    Command = unicode:characters_to_list(["erpcap -b ", Interface]),
    % io:format("Command:~s~n", [Command]),
    Port = open_port({spawn, Command}, [{packet, 2}]),
    loop(Port, []).

loop(Port, RxHandlers) ->
    receive
        % receive packet
        {Port, {data, Data}} ->
            handle_packet(list_to_binary(Data), RxHandlers),
            loop(Port, RxHandlers);
        {send, Packet} ->
            Port ! {self(), {command, Packet}},
            loop(Port, RxHandlers);
        {reg, Handler} ->
            loop(Port, lists:append(RxHandlers, [Handler]));
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

handle_packet(Pkt, Handlers) ->
    % io:format("recv ~w bytes~n", [byte_size(Pkt)]),
    lists:foreach(fun(Handler)-> Handler(Pkt) end, Handlers).
