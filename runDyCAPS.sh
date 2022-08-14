#!/bin/bash

#第三个参数表示是否重新上传并替换代码
COUNTER=$1
FAULT=$2
UPDATE=$3

USER=ec2-user

#待上传文件根目录，SRCDIR1用于执行代码，SRCDIR2用于更新代码
SRCDIR1=/xx/Implementation/DyCAPSTeam/DyCAPS/cmd/DyCAPs
SRCDIR2=/xx/Implementation/

#目标目录，DESDIR1用于执行代码，DESDIR2用于更新代码
DESDIR1=/home/ec2-user/DyCAPSTeam/DyCAPS/cmd/DyCAPs
DESDIR2=/home/ec2-user/

#第一个IP是client，其余是客户端
IP=()
instanceID=()
clientID=
PORT=22

if (($UPDATE == 1))
then
  #删除已有代码
  aws ssm send-command --document-name "AWS-RunShellScript" --targets "Key=instanceids,Values=${clientID}" --parameters '{"commands":["#!/bin/bash", "rm -rf DyCAPSTeam DyCAPSTeam.zip"]}' &

  #删除已有代码
  for i in `seq 0 $(($COUNTER))`;
  do
  aws ssm send-command --document-name "AWS-RunShellScript" --targets "Key=instanceids,Values=${instanceID[$i]}" --parameters '{"commands":["#!/bin/bash", "rm -rf DyCAPSTeam DyCAPSTeam.zip"]}' &
  done

  echo "delete existing codes done"

  #上传代码
  for i in `seq 0 $(($COUNTER))`;
  do
  sftp ${USER}@${IP[$i]}<<EOF
  lcd ${SRCDIR2}
  cd ${DESDIR2}
  put DyCAPSTeam.zip
  bye
EOF
  done

  #解压
  aws ssm send-command --document-name "AWS-RunShellScript" --targets "Key=instanceids,Values=${clientID}" --parameters '{"commands":["#!/bin/bash", "cd /home/ec2-user", "unzip DyCAPSTeam.zip"]}' &

  #解压
  for i in `seq 0 $(($COUNTER))`;
  do
  aws ssm send-command --document-name "AWS-RunShellScript" --targets "Key=instanceids,Values=${instanceID[$i]}" --parameters '{"commands":["#!/bin/bash", "cd /home/ec2-user", "unzip DyCAPSTeam.zip"]}' &
  done
fi

#上传ipList和portList
for i in `seq 0 $(($COUNTER))`;
do
sftp ${USER}@${IP[$i]}<<EOF
  lcd ${SRCDIR1}
  cd ${DESDIR1}
  put -r list
  bye
EOF
done

#开启client
aws ssm send-command --document-name "AWS-RunShellScript" --targets "Key=instanceids,Values=${clientID}" --parameters '{"commands":["#!/bin/bash", "cd /home/ec2-user/DyCAPSTeam/DyCAPS/cmd/DyCAPs/", "export PATH=$PATH:/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/usr/local/go/bin:/usr/local/lib:/home/ec2-user/.local/bin:/home/ec2-user/bin", "export GOPATH=/home/ec2-user/go","export GOCACHE=/home/ec2-user/.cache/go-build","export GOENV=/home/ec2-user/.config/go/env","export GOMODCACHE=/home/ec2-user/go/pkg/mod", "export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/lib", "export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib", "go run main.go -n '${COUNTER}' -f '${FAULT}' -op1 2 -op2 client"]}' &

#开启客户端
for i in `seq 0 $(($COUNTER-1))`;
do
aws ssm send-command --document-name "AWS-RunShellScript" --targets "Key=instanceids,Values=${instanceID[$i]}" --parameters '{"commands":["#!/bin/bash", "cd /home/ec2-user/DyCAPSTeam/DyCAPS/cmd/DyCAPs/", "./reset.sh", "export PATH=$PATH:/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/usr/local/go/bin:/usr/local/lib:/home/ec2-user/.local/bin:/home/ec2-user/bin", "export GOPATH=/home/ec2-user/go","export GOCACHE=/home/ec2-user/.cache/go-build","export GOENV=/home/ec2-user/.config/go/env","export GOMODCACHE=/home/ec2-user/go/pkg/mod", "export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/lib", "export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib", "go run main.go -n '${COUNTER}' -f '${FAULT}' -op1 2 -op2 onlyOneCommitee -id '$i'"]}' &
done
