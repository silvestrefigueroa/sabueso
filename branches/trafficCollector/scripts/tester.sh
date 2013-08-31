#Esta primer prueba se hizo con server windows XP, cliente RDESKTOP desde el USB sysresccd

#$srcMac = $1
#$srcIp = $2
#$dstMac = $3
#$dstIp = $4


for((i=0; i<1;i++))
do
	#s=0, adelante arpeo por el cliente
#	arping 192.168.222.6 -c 1 -w 1000000
	#s=1, luego portsteleo 
	arping -p -s 10:1f:e2:14:5a:af 192.168.0.2 -S 192.168.0.3 -c 20 -w 100
	clear
	#s=1.1
	echo -------------------------------------------------------------
	arping -p -s 00:01:4a:09:c3:32 192.168.0.2 -S 192.168.0.3 -c 7 -w 1000000
	echo -------------------------------------------------------------
	#s=8
	arping 192.168.0.2 -c 10 -w 100000
	#s=9
	sleep 1
	#s=11
done
