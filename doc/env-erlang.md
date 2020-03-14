# Erlang development environment on Windows

## Reference
1. [win10 64位系统 搭建 erlang + vscode 开发环境](https://blog.csdn.net/wwwmewww/article/details/102529612)
2. [windows下使用rebar3](https://www.jianshu.com/p/3695efada042)
3. [VS Code与CMake真乃天作之合](https://zhuanlan.zhihu.com/p/52874931)

## Erlang

1. Install `otp_win64_22.2`
2. Set erlang bin to path, e.g.: `D:\Program Files\erl10.6\bin`

## Rebar3

1. Copy rebar3 binary into erlang bin folder
2. create `rebar3.cmd` as following:

    ```cmd
    @echo off
    setlocal
    set rebarscript=%~f0
    escript.exe "%rebarscript:.cmd=%" %*
    ```
