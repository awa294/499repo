#!/bin/bash

if [ "$1" == "" ]; then
	echo "No label provided. USAGE: ./run.sh [LABEL NUMBER]"
	exit 1
fi

label=$1

amount=1000
ttl=128

echo "Starting packet sniffing for label $label"

for i in {1..10}
do
	echo "Sniff number: $i. $amount packets with $ttl ttl."
	sudo python scapy-skeleton.py $label $amount $ttl ./tmp/sniff${i}.csv
	echo "Written to ./tmp/sniff${i}.csv"
done

time=$(date +"%H%M%S")

touch ./result/result${time}.csv

echo "tran_proto, avg_sent_len, avg_rec_len, avg_sent_ttl, average_rec_ttl, label" >> ./result/result${time}.csv

for i in {1..10}
do
	echo "Processing ./tmp/sniff${i}.csv"
	python processor.py ./tmp/sniff${i}.csv $label >> ./result/result${time}.csv
	echo "Finished processing ./tmp/sniff${i}.csv. Data appended to ./result/result${time}.csv."
done
