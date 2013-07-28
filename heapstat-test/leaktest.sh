#!/bin/sh
pid=`pgrep -x leak`
gcore -o /var/tmp/core $pid
pmap /var/tmp/core.$pid|grep heap
echo "Open /var/tmp/core.$pid"
./heapstat $1 /var/tmp/core.$pid
