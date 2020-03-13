
-module(erpcap).

-behaviour(gen_server).

%% API
-export([start/1, stop/0]).
-export([send/1, reg_handler/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).
-record(state, {port, handlers}).

start(Interface) ->
   gen_server:start_link({local, ?MODULE}, ?MODULE, Interface, []).

stop() ->
   gen_server:call(?MODULE, stop).

send(Packet) ->
    gen_server:cast(?MODULE, {send, Packet}).

reg_handler(Handler) ->
    gen_server:cast(?MODULE, {reg, Handler}).

init(Interface) ->
    Command = unicode:characters_to_list(["erpcap -b ", Interface]),
    % io:format("Command:~s~n", [Command]),
    Port = open_port({spawn, Command}, [{packet, 2}]),
   {ok, #state{port=Port, handlers=[]}}.

handle_call(stop, _From, State) ->
   {stop, normal, stopped, State};

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast({reg, Handler}, State) ->
    #state{handlers=Handlers} = State,
   {noreply, #state{handlers=lists:append(Handlers, [Handler])}};

handle_cast({send, Packet}, State) ->
    #state{port=Port} = State,
    Port ! {self(), {command, Packet}},
   {noreply, State};

handle_cast(_Msg, State) ->
   {noreply, State}.

handle_info({_Port, {data, Data}}, State) ->
    #state{handlers=Handlers} = State,
    Packet = list_to_binary(Data),
    % io:format("recv ~w bytes~n", [byte_size(Packet)]),
    lists:foreach(fun(Handler)-> Handler(Packet) end, Handlers),
   {noreply, State};

handle_info(_Info, State) ->
   {noreply, State}.

terminate(_Reason, _State) ->
   ok.

code_change(_OldVsn, State, _Extra) ->
   {ok, State}.
