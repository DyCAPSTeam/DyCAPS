#!/bin/bash


COUNTER=$1
FAULT=$2
Length=$3

if [ ! -d "metadata" ]; then
  mkdir metadata
fi

./reset.sh

#calculate the necessary coefficients and store them in files.
go run main.go -n $COUNTER -f $FAULT -op1 1 &&
echo "coefficients generated successfully."
# start a thread representing the client
echo "protocol start"

go run main.go -n $COUNTER -f $FAULT -op1 2 -op2 client -mp metadata -id 12345 -lp list -t1 10 -t2 15 -t3 20 -ml $Length&

# start threads representing nodes in the currentCommitee
for i in `seq 0 $(($COUNTER-1))`;
do
  go run main.go -n $COUNTER -f $FAULT -op1 2 -op2 currentCommitee -id $i -mp metadata -lp list -t1 10 -t2 15 -t3 20 -ml $Length&
  echo "currentCommitee $i established"
done
# start threads representing nodes in the newCommitee
for i in `seq 0 $(($COUNTER-1))`;
do
  go run main.go -n $COUNTER -f $FAULT -op1 2 -op2 newCommitee -id $i -mp metadata -lp list -t1 10 -t2 15 -t3 20 -ml $Length&
  echo "newCommitee $i established"
done

sleep 10000
