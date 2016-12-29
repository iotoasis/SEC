# Quick Start - KMS

Oasis Security 관련해서 KMS 에이전트 및 툴킷을 처음 접하는 분들이 소스를 다운받고 쉽게 시험할 수 있도록 안내한다.

KMS 에이전트 및 툴킷은 다음과 같은 순서로 사용할 수 있다.

> 1. 라즈비안 다운로드 및 설치
> 2. 에이전트 및 툴킷 소스 다운로드
> 3. 에이전트 및 툴킷 소스 빌드
> 4. 에이전트 및 툴킷 라이브러리 파일
> 5. 에이전트 설정 방법

## Requirements
* Raspberrypi
* Rasbian OS

## 따라하기

#### (1) 라즈비안 다운로드 및 설치
- [라즈비안 다운로드] (https://www.raspberrypi.org/downloads/raspbian/)
- [라즈비안 설치안내] (https://www.raspberrypi.org/documentation/installation/installing-images/README.md)

#### (2) 에이전트 및 툴킷 소스 다운로드
- [릴리즈 페이지](https://github.com/iotoasis/SEC/releases)에서 소스 및 설치관련 파일을 다운받은 후 KMS 폴더의 소스만 사용한다.

#### (3) 에이전트 및 툴킷 소스 빌드
- 에이전트 소스 빌드 : Agent 폴더에서 make ?f Makefile.linux.arm 실행
- 툴킷 소스 빌드 : Toolkit/TrustKeystoreCstk/src 폴더에서 make ?f make.raspberry.32 실행

#### (4) 에이전트 및 툴킷 라이브러리 파일
- 에이전트 라이브러리 : libTKSAgent.so, libTKSAgent.so, libTKSAgentAdv.so, libTKSAgentLite.so
- 툴킷 라이브러리 : libTKSCstk.so, libTKSCstkLite.so, libTKSKmsCstk.so, libTKSKmsCstkLite.so

#### (5) 에이전트 설정 방법
- 설정은 TrustKeystoreAgent.conf 파일로 작성되며 CA 인증서 unetsystem-rootca.pem와 같은 폴더에 위치시킨 후 초기화 API에 그 경로를 입력한다. 설정파일은 아래 샘플 설정파일을 사용한다. 

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

Oasis Security 관련해서 CAS 클라이언트 및 툴킷을 처음 접하는 분들이 소스를 다운받고 쉽게 시험할 수 있도록 안내한다.

CAS 클라이언트 및 툴킷은 다음과 같은 순서로 사용할 수 있다.

> 1. 라즈비안 다운로드 및 설치
> 2. 클라이언트 및 툴킷 소스 다운로드
> 3. 클라이언트 및 툴킷 소스 빌드
> 4. 클라이언트 및 툴킷 라이브러리 파일
> 5. 클라이언트 설정 방법

## Requirements
* Raspberrypi
* Rasbian OS

## 따라하기

#### (1) 라즈비안 다운로드 및 설치
- [라즈비안 다운로드] (https://www.raspberrypi.org/downloads/raspbian/)
- [라즈비안 설치안내] (https://www.raspberrypi.org/documentation/installation/installing-images/README.md)

#### (2) 클라이언트 및 툴킷 소스 다운로드
- [릴리즈 페이지](https://github.com/iotoasis/SEC/releases)에서 소스 및 설치관련 파일을 다운받은 후 CAS 폴더의 소스만 사용한다.

#### (3) 클라이언트 및 툴킷 소스 빌드
- 클라이언트 소스 빌드 : ?	CAClient 폴더에서 make 실행
- 툴킷 소스 빌드 : ?	TrustNETCASCstk 폴더에서 make 실행

#### (4) 클라이언트 및 툴킷 라이브러리 파일
- 클라이언트 라이브러리 : libTrustNETCASClient.so
- 툴킷 라이브러리 : libTrustNETCASCstk.so

#### (5) 클라이언트 설정 방법
- 설정은 TrustNetCaClient.conf 파일로 작성되며 CA 인증서 trustnetcas-rootca.crt와 같은 폴더에 위치시킨 후 초기화 API에 그 경로를 입력한다.

casIP=166.104.112.40
casPort=9005

<br>
<br>
<br>