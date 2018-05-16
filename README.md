### Virtualized IP Multimedia System Core

Virtualized IP Multimedia System Core is a simple virtualized implementation of IP multimedia subsystem core. It simulates the working of IMS core in handling control traffic related to registration/deregistration requests. Virtualized IP Multimedia System Core is developed in C++11 for both kernel and kernel bypass(mTCP) network stack.

### Synopsis
IMS is an architectural framework for delivering IP multimedia services, for example,
Voice over LTE (VoLTE) is based on IMS. As the use of mobile internet and VoLTE deployment is growing, the performance and scalability of IMS become more important. We have currently implemented some procedures of IMS core and will be comparing performance difference between kernel and kernel bypass (mTCP) stack. Note that our code is not fully standards compliant, and is not intended for commercial use. Our code is intended for consumption by researchers to build and evaluate various setups of NFV-based IMS core.  

#### List of developed software modules

- Proxy Call Session Control Function
- Interrogating Call Session Control Function
- Serving Call Session Control Function
- Home Subscriber Server
- Radio Access Network Simulator


#### Supported IMS core procedures

- Registration:	Initial Phase
- Registration:	Authentication Phase
- Deregistration



Note: Above packages/tools correspond to linux-based machines

#### Directory structure

- **NFV_IMS**: Contains a source and documentation of IMS core. Refer usual manual in documentation for setup.



#### Authors

1. [Kanase Akash Shahaji](https://www.linkedin.com/in/akashkanase/), Master's student (2016-2018), Dept. of Computer Science and Engineering, IIT Bombay.
2. [Prof. Mythili Vutukuru](https://www.cse.iitb.ac.in/~mythili/), Dept. of Computer Science and Engineering, IIT Bombay.

#### Contact

- Prof. Mythili Vutukuru, mythili[AT]cse.iitb.ac.in

