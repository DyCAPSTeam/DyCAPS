执行前准备：\
1.在/DyCAPs目录下执行go build -o DyCAPs，得到可执行文件DyCAPs\
2.在/DyCAPs目录下执行./internal/party/keyGen，输入N和T（T=2*F+1）,得到/DyCAPs目录下的两个文件coefficients和coefficients_new，用于新旧委员会公私钥生成\
3.在/DyCAPs目录下执行./DyCAPs，首先输入client，currentCommitee，newCommitee其中的一个（表示节点的种类），若为新/旧委员会节点，再输入节点编号（均为0~N-1）。当所有节点对应的终端都完成上述步骤后，在毎一终端输入任意数字，启动协议（client最后启动）。
