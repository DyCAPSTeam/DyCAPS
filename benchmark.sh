#!/bin/bash

n=1
while [ $n -le 5 ]
do
  echo "This is iteration $n"
  go test -benchmem -run=^$ -bench ^BenchmarkDpss$ github.com/DyCAPSTeam/DyCAPS/internal/party -benchtime=1x -cpu 1 >> benchmark-$n.log
  n=$((n+1))
done
