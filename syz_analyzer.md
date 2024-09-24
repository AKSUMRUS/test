# syz-analyzer
# How to use `syz-analyzer`
After cloning the repository (see how[here](/docs/linux/setup.md#go-and-syzkaller)), build the tool as:

```
make syz-analyzer executor
```

To start using the tool, separate configuration files need to be created for
each kernel you want to include in the verification. An example of Linux
configs can be found [here](/docs/linux/setup_ubuntu-host_qemu-vm_x86-64-kernel.md#syzkaller). The configuration files
are identical to those used by `syz-manager`.

Start `syz-analyzer` as:
```
./bin/linux_amd64/syz-analyze -configs=kernel0.cfg,kernel1.cfg repro0.syz repro1.syz
```
`syz-analyzer` also has some flags:
* configs - list of paths to virtual machines config files, can't be empty
* debug - print debug info from virtual machines (default: false).
* repeat - determines how many times reproducers will be run on each virtual machine(default: 1000).
* stats - where stats will be written after execution (default: `stdout`).
* data - load data from previous analysis. Path to json file (default: empty) 