# StoreDekData Pilot Program

PSE HSM을 사용하여 DEK(Data Encryption Key)를 KEK(Key Encryption Key)로 암호화하고, 이를 `CKO_DATA` 객체로 HSM에 저장/검증하는 Java CLI 프로그램입니다.

## 기능 (Features)
1. **암호화 및 저장**: 로컬 파일(`dek.bin` 등)에서 DEK를 읽어, HSM 내부의 KEK로 암호화한 후 `CKO_DATA` 객체로 저장합니다.
2. **검증**: 저장된 `CKO_DATA`를 읽어 복호화하고, 원본 데이터와 일치하는지 검증합니다.

## 필수 요건 (Prerequisites)
- SafeNet HSM Client (PTK) 설치 완료
- Java Development Kit (JDK) 8 이상
- `setvars.sh` 환경 변수 설정 (`run.sh` 내에서 자동 처리됨)

## 사전 준비 (Preparation)
프로그램 실행 전, 테스트를 위한 암호화 키(KEK)와 데이터 파일(DEK)을 준비해야 합니다.

### 1. KEK (Master Key) 생성
HSM 내부에 KEK를 생성합니다. (예: Label=`master_key`, 256bit AES)
```bash
# 슬롯 0에 'master_key' 라벨을 가진 AES 256비트 키 생성 (비밀번호: 1111)
ctkmu c -s 0 -u 1111 -n master_key -t aes -z 256 -a E D S V T X
```
> **참고**: `ctkmu`는 PSE ptk 클라이언트 도구입니다.
> **속성 설명 (-a)**: `E`(Encrypt/암호화), `D`(Decrypt/복호화), `S`(Sign/서명), `V`(Verify/검증), `T`(Sensitive/민감), `X`(Extractable/추출가능) 권한을 부여합니다.

### 2. DEK (Data Encryption Key) 파일 생성
암호화할 원본 데이터 파일을 생성합니다. (예: 32바이트 바이너리)
```bash
dd if=/dev/urandom of=dek.bin bs=32 count=1
```

## 설치 및 빌드 (Build)
제공된 `build.sh` 스크립트를 사용하여 컴파일합니다.
```bash
./build.sh
```

## 사용법 (Usage)
`run.sh` 스크립트를 통해 실행하는 것을 권장합니다.

```bash
./run.sh [options]
```

### 옵션 (Options)
모든 주요 옵션은 **필수(REQUIRED)**입니다.
- `-s`, `--slot <slotId>`: HSM 슬롯 ID
- `-p`, `--password <pwd>`: 파티션 비밀번호
- `-kl`, `--kek-label <label>`: 암호화에 사용할 KEK (Master Key) 라벨
- `-dl`, `--dek-label <label>`: 저장될 데이터 객체의 라벨
- `-f`, `--file <file>`: 원본 DEK 바이너리 파일 경로
- `-q`, `--quiet`: (선택) Quiet 모드. 중간 프롬프트를 생략하고 상세 출력을 숨깁니다.
- `-h`, `--help`: 도움말 표시

### 실행 예시 (Example)
```bash
# 기본 실행
./run.sh -p 1111 -s 0 -kl master_key -dl test_dek_01 -f dek.bin

# Quiet 실행 (최소한의 출력)
./run.sh -q -p 1111 -s 0 -kl master_key -dl test_dek_01 -f dek.bin
```
