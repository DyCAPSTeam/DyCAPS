#!/bin/bash

COUNTER=$1
FAULT=$2

#calculate the necessary coefficients and store them in files.
go run main.go -n $COUNTER -f $FAULT -op1 1 &&
echo "coefficients generated successfully."
# start a thread representing the client
echo "protocol start"
go run main.go -n $COUNTER -f $FAULT -op1 2 -op2 client &

# start threads representing nodes in the Commitee
for i in `seq 0 $(($COUNTER-1))`;
do
  go run main.go -n $COUNTER -f $FAULT -op1 2 -op2 onlyOneCommitee -id $i &
  echo "Commitee $i established"
done

sleep 100
