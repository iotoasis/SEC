![iotoasis](https://github.com/iotoasis/SO/blob/master/logo_oasis_m.png)

## Oasis KMS

KMS(Key Management Server)는 IoT 환경에서 디바이스게이트웨이와 디바이스 간 송수신 데이터에 대한 기밀성을 유지하기 위해 암호화를 수행할 때 사용할 수 있는 암호키 관리 방법을 제공합니다.
제공되는 소스코드는 KMS 서버에서 관리되는 암호키를 획득하기 위한 KMS Agent 와 암호키를 이용하여 데이터를 암호화하기 위한 KMS Toolkit 대한 것입니다.

 - Feature
   - 경량환경용 암호키 관리 클라이언트 환경 지원
   - 경량암호화 알고리즘 지원(LEA 등)
   - 지원가능환경 : 라즈베리파이 및 유사 디바이스용 환경


## Modules
src/Agent 는 KMS 서버에 암호키를 요청하고 수신받아 로컬 저장하는 역할을 합니다. <br>
src/Toolkit 은 Agent가 보관하고 있는 암호키를 전달받아 데이터를 암호화/복호화하는 역할을 합니다.
<br>

## License
Licensed under the BSD License, Version 2.0
<br>


