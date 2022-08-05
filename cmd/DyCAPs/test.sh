#!/bin/bash

COUNTER=$1
FAULT=$2

if [ ! -d "metadata" ]; then
  mkdir metadata
fi

#calculate the necessary coefficients and store them in files.
go run main.go -n $COUNTER -f $FAULT -op1 1 &&
echo "coefficients generated successfully."
# start a thread representing the client
echo "protocol start"

go run main.go -n $COUNTER -f $FAULT -op1 2 -op2 client &

# start threads representing nodes in the currentCommitee
for i in `seq 0 $(($COUNTER-1))`;
do
  go run main.go -n $COUNTER -f $FAULT -op1 2 -op2 currentCommitee -id $i &
  echo "currentCommitee $i established"
done
# start threads representing nodes in the newCommitee
for i in `seq 0 $(($COUNTER-1))`;
do
  go run main.go -n $COUNTER -f $FAULT -op1 2 -op2 newCommitee -id $i &
  echo "newCommitee $i established"
done

sleep 10000
