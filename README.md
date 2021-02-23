This is developed based on AFLplusplus (2.68c, Qemu mode), thanks to its amazing maintainers and community

## Build and Run

1. Please follow the instructions of building afl++ and its qemu mode (please refer to README_aflpp)

2. The running command is the same as afl++ (remember to add -Q to launch the qemu mode), in addition

    2.a To enable the multi-level coverage metric, please set the env variable "AFL_USE_MULTI_LEVEL_COV=1 "
    2.b To enable the hierarchical scheduler, please set the env variable "AFL_USE_HIER_SCHEDULE=1 "
    2.c We highly recommend to add "-d" to skip the deterministic mutation stage
    2.d We use the EXPLORE power schedule ("-p explore")

