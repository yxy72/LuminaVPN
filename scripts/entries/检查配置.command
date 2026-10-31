#!/bin/sh
cd "$(dirname "$0")" || exit 1
./netlaunch config validate "$@"
rc=$?
printf "\n命令已结束（退出码 %s）。按回车关闭。\n" "$rc"
read answer
exit "$rc"
