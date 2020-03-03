# CMakeList.txt: erpcap 的 CMake 项目，在此处包括源代码并定义
# 项目特定的逻辑。
#
cmake_minimum_required (VERSION 3.8)

project ("erpcap")

include_directories("D:/flych/wsl/source/npcap-sdk-1.04/Include")
link_directories("D:/flych/wsl/source/npcap-sdk-1.04/Lib")

link_libraries("x64/Packet")
link_libraries("x64/wpcap")

# 将源代码添加到此项目的可执行文件。
aux_source_directory(. SRC_LIST)

add_executable (erpcap ${SRC_LIST})

# TODO: 如有需要，请添加测试并安装目标。
