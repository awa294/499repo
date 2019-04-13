#!/bin/bash

label=1

for i in {1..10}
do
	sudo python scapy-skeleton.py $label 1000 128 ./tmp/sniff${i}.csv
done

time=(date +"%H%M%S")

touch ./result/result${time}.csv

echo "tran_proto, avg_sent_len, avg_rec_len, avg_sent_ttl, average_rec_ttl, label" >> ./result/result${time}.csv

for i in {1..10}
do
	python processor.py ./tmp/sniff${i}.csv label >> ./result/result${time}.csv
done
