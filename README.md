Disclaimer

This repository contains experimental patches and notes created as part of a research and bring-up effort to run a Mellanox Innova 2 Flex FPGA card on a Raspberry Pi 5 using modern Mellanox OFED (24.10) and the Mellanox innova_2_flex_open_18_12 Open Bundle.

The primary goal of the project was to restore FPGA-related functionality that existed in older Mellanox OFED releases (around OFED 5.2) and make it work on a modern kernel and ARM platform. This goal has been achieved: the Mellanox userspace tools build and run, and the FPGA on the Innova 2 Flex card can be successfully programmed using standard Mellanox utilities.

The work is based on analysis of publicly available source code from Mellanox open repositories, historical OFED versions, and limited reverse-engineering. No proprietary or confidential information is used.

This project is not an official solution and is not affiliated with, endorsed by, or supported by NVIDIA, Mellanox, AMD, or Xilinx.

The code is shared in the spirit of open research and community collaboration. Testing coverage is limited, and behavior may vary across kernel versions, distributions, and hardware platforms.

This repository is intended for research, educational, and experimental use only. Production use is strongly discouraged.

Use at your own risk.

