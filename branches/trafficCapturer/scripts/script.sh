while true
do
	arping -i wlan0 -s aa:bb:cc:dd:ee:ff 192.168.1.167 -c 1
	sleep 2
	arping -i wlan0 192.168.1.1 -c 1
	sleep 2
done
