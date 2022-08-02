COUNTER=18980
for i in `seq 18880 $COUNTER`;
do
  ans=`lsof -t -i tcp:$i`
  for element in $ans
  do
    kill -9 $element
    echo "killed $element when i=$i"
  done
done
