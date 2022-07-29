执行前准备：\
1.在`/cmd/DyCAPs`目录下执行'go build -o DyCAPs'，得到同文件夹下的可执行文件'DyCAPs'\
2.在`/cmd/DyCAPs`目录下执行`./DyCAPs`，输入选项1（参数生成选项），再输入`N`和`T`(`T=2*F+1`)得到同目录下的两个文件`coefficients`和`coefficients_new`，用于新旧委员会公私钥生成\
3.在`/cmd/DyCAPs`目录下执行`./DyCAPs`，输入选项2（执行协议选项），然后输入`client`，`currentCommitee`，`newCommitee`其中的一个（表示节点的种类），若为新/旧委员会节点，再输入节点编号（均为`0~N-1`）。当所有节点对应的终端都完成上述步骤后，在毎一终端输入任意数字，启动协议（`client`最后启动）。
