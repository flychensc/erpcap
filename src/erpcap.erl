
-module(erpcap).

-export([start/0]).

start() ->
    IF_Name = application:get_env(erpcap, if_name),
    io:format("Interface Name:~w~n", [IF_Name]),
    Port = open_port({spawn, erpcap}, [{packet, 2}]),
    read_replies(Port).

read_replies(Port) ->
    receive
        {Port, Any} ->
            io:format("erlang received from port:~w~n", [Any]),
            read_replies(Port)
    after 2000 ->
        Port ! {self(), close},
        receive
            {Port, closed} ->
                true
        end
    end.