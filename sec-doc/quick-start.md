# Quick Start - KMS

For new users to approach KMS agents and toolkits related to Oasis Security, this guide shows how to download the source and test it easily.

KMS agents and toolkits can be used in the following order.

> 1. Download and install Raspbian
> 2. Download agent and toolkit sources
> 3. Build the agent and toolkit source
> 4. Agent and toolkit library files
> 5. How to set up the agent


## Requirements
* Raspberrypi
* Rasbian OS

## Follow

#### (1) Download and install RazBian
- [Raspbian download] (https://www.raspberrypi.org/downloads/raspbian/)
- [Raspbian Installation Guide] (https://www.raspberrypi.org/documentation/installation/installing-images/README.md)

#### (2) Download agent and toolkit sources
- Download the source and installation files from [Release page](https://github.com/iotoasis/SEC/releases) and use only the source of the KMS folder.

#### (3) Build agent and toolkit sources
- Build agent source : Run make -f Makefile.linux.arm in the Agent folder
- Build Toolkit Source : Run make -f make.raspberry.32 in the Toolkit/TrustKeystoreCstk/src folder

#### (4) Agent and toolkit library files
- Agent library : libTKSAgent.so, libTKSAgent.so, libTKSAgentAdv.so, libTKSAgentLite.so
- Toolkit library : libTKSCstk.so, libTKSCstkLite.so, libTKSKmsCstk.so, libTKSKmsCstkLite.so

#### (5) How to set up the agent
- The settings are created in the TrustKeystoreAgent.conf file, located in the same folder as the CA certificate unetsystem-rootca.pem, and entered in the initialization API. The configuration file uses the sample configuration file shown below.

kmsIP=166.104.112.40
kmsPort=9002
agentID=oasis_test
agentType=1
agentHint=GeNiVZchB9QrjOy3fvViLoQuilB3im7Y3RzpRzLayp4=
Integrity=FpDvNYpuw2kZm11mdAgkmtGgaETFcWCB3kU52VS/uVU=

<br>
<br>
<br>

# Quick Start - CAS

For new users to approach CAS client and toolkit for Oasis Security, this guide shows how to download the source and test it easily.

The CAS client and toolkit can be used in the following order.

> 1. Download and install Raspbian
> 2. Download client and toolkit sources
> 3. Building client and toolkit sources
> 4. Client and Toolkit library files
> 5. How to set up the client


## Requirements
* Raspberrypi
* Rasbian OS

## Follow

#### (1) Download and install Raspbian
- [Raspbian download] (https://www.raspberrypi.org/downloads/raspbian/)
- [Raspbian Installation Guide] (https://www.raspberrypi.org/documentation/installation/installing-images/README.md)

#### (2) Download client and toolkit sources
- After downloading the source and installation files from [Release page](https://github.com/iotoasis/SEC/releases), use only the source of the CAS folder.

#### (3) Building client and toolkit sources
- Build client source: Run make in the CAClient folder
- Toolkit source build: Run make in the TrustNETCASCstk folder

#### (4) Client and toolkit library files
- Client library : libTrustNETCASClient.so
- Toolkit library : libTrustNETCASCstk.so

#### (5) How to set up the client
- The settings are created in the TrustNetCaClient.conf file, located in the same folder as the CA certificate trustnetcas-rootca.crt, and entered in the initialization API.

casIP=166.104.112.40
casPort=9005

<br>
<br>
<br>