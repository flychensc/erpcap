erpcap
=====

An OTP library

The `erpcap` library is used to capture packets from NIC on Windows.

You can develop some L2 protocol (e.g. 802.1X) with this library.

Build
-----

    $ rebar3 compile

Usage
-----
1. List your NICs via `erpcap.exe -l`

    ```cmd
    >erpcap.exe -h

    -l                -- List all interfaces
    -b INTERFACE_NAME -- Bind a interface
    -r INTERFACE_NAME -- Debug receive packet on a interface

    >erpcap.exe -l

    \Device\NPF_{97501407-6BF5-4D31-ADC4-5AFBD53A2192}
            Description: Microsoft
            Loopback: no
            Address Family: #23
            Address Family Name: AF_INET6
            Address: (null)
            Address Family: #2
            Address Family Name: AF_INET
            Address: 192.168.3.102
            Netmask: 255.255.255.0
            Broadcast Address: 255.255.255.255

    >
    ```

2. Run `erpcap:start(Name).`, e.g.: `erpcap:start("\\Device\\NPF_{97501407-6BF5-4D31-ADC4-5AFBD53A2192}").`

3. Send Packdet via `erpcap:send(Packet).`

4. Register RX handler via `erpcap:reg_handler(Handler).`

Sample
------

Refer to [erpcap_sample.erl](.src/erpcap_sample.erl)
