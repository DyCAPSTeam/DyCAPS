This repo contains the implementation of the paper [*DyCAPS: Asynchronous Proactive Secret Sharing for Dynamic Committees*](https://eprint.iacr.org/2022/1169).

Three branches are included in this repo:

* `main` :  evaluate the latency of `DyCAPS.Handoff`.

* `byStep` :  evaluate the latency of each step in `DyCAPS.Handoff`, where the steps are executed sequentially. *Sequential execution consumes around 20% more seconds than concurrent execution.

* `payload ` : evaluate the latency and throughput of `DyCAPS.Handoff` with different payload sizes. In this case, `DyCAPS.Handoff` can be seen as a dynamic-committee version of [Dumbo](https://eprint.iacr.org/2020/841.pdf).

We note that altough we have implemented both `DyCAPS.Share` and `DyCAPS.Handoff` in this repo, the shares are transferred to the  parties by a trusted dealer when we test the latency of `DyCAPS.Handoff`.

### Dependencies

* go v1.18 or later versions
* Reed-Solomon Erasure Coding in Go : [klauspost/reedsolomon](https://github.com/klauspost/reedsolomon)
* DEDIS Advanced Crypto Library for Go: [drand/kyber](https://github.com/drand/kyber)
* [KZG and FFT utils](https://github.com/protolambda/go-kzg) built on top of BLS12-381 (experimental)

### Configure

Before executing DyCAPS, come into the directory `./cmd/DyCAPs/list` and configure the IP addresses and port numbers for parties in both the old committee and the new committee.

* Write `n` lines of IP addresses in file `ipList`, where `line i` is for `party i` in the old committee, and `n` denotes the maximum of parties in each committee.
* Write `n` lines of port numbers in file `portList`.
* Do the same in `ipListNext` and `portListNext` for the new committee.

### Run DyCAPS Locally

The IP addresses for all parties are `127.0.0.1` for local configuration (we use port numbers to identify the parties).

To run branch `main` and `byStep`, execute the following script in `./cmd/DyCAPs` :

`./test_multiCommittee.sh <n> <f>`

To run branch `payload`:

`./test_multiCommittee.sh <n> <f> <payloadSize>`

where `n` is the total number of parties in each committee, `f` is the number of corrupted parties and `payloadSize` is the size of payload (in Bytes).

We require  ` n ` and ` f ` satisfies that ` n = 3f + 1 `.

We recommand ` n=4,f=1 ` if you are using a laptop for local test.

Results can be found in `./cmd/DyCAPs/metadata`, where files named `log*` show the latency information of the specified party and those named `executingLog*` show  the details of execution.

