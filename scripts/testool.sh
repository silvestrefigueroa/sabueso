#!/bin/bash
arping -i wlan0 -p -s 13:ff:aa:dd:aa:f1 192.168.1.213 -c 1
arping -i wlan0 -p -s 55:ff:aa:dd:aa:f1 192.168.1.111 -c 1
arping -i wlan0 -p -s 56:ff:aa:dd:aa:f1 192.168.1.112 -c 1
arping -i wlan0 -p -s ef:3c:dd:dd:aa:f1 192.168.1.28 -c 1
arping -i wlan0 -p -s ee:3c:cc:dd:aa:f1 192.168.1.23 -c 1
arping -i wlan0 -p -s 22:3b:cc:dd:aa:f1 192.168.1.226 -c 1
arping -i wlan0 -p -s a2:2b:cc:dd:ea:f1 192.168.1.190 -c 1
arping -i wlan0 -p -s aa:2b:cc:dd:ea:f1 192.168.1.19 -c 1
arping -i wlan0 -p -s aa:3b:cc:dd:ea:f1 192.168.1.180 -c 1
arping -i wlan0 -p -s aa:3b:cc:dd:aa:f1 192.168.1.181 -c 1
arping 192.168.1.1 -c 1 -I wlan0
