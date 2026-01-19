# StoreDekData Pilot Program

SafeNet HSM을 사용하여 DEK(Data Encryption Key)를 KEK(Key Encryption Key)로 암호화하고, 이를 `CKO_DATA` 객체로 HSM에 저장/검증하는 Java CLI 프로그램입니다.

## 기능 (Features)
1. **암호화 및 저장**: 로컬 파일(`dek.bin` 등)에서 DEK를 읽어, HSM 내부의 KEK로 암호화한 후 `CKO_DATA` 객체로 저장합니다.
2. **검증**: 저장된 `CKO_DATA`를 읽어 복호화하고, 원본 데이터와 일치하는지 검증합니다.
3. **Verbose 모드**: `-v` 옵션 사용 시 평문/복호화된 키 값을 출력하여 디버깅이 가능합니다.

## 필수 요건 (Prerequisites)
- SafeNet HSM Client (PTK) 설치 완료
- Java Development Kit (JDK) 8 이상
- `setvars.sh` 환경 변수 설정 (`run.sh` 내에서 자동 처리됨)

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
- `-v`, `--verbose`: (선택) 상세 출력 모드. 평문 및 복호화된 값을 화면에 표시합니다.
- `-q`, `--quiet`: (선택) Quiet 모드. 중간 프롬프트를 생략합니다.
- `-h`, `--help`: 도움말 표시

### 실행 예시 (Example)
```bash
# 기본 실행 (암호문만 출력, 검증 수행)
./run.sh -q -p 1111 -s 0 -kl k01 -dl test_dek_01 -f dek.bin

# 상세 실행 (평문/복호화문 포함 출력)
./run.sh -q -v -p 1111 -s 0 -kl k01 -dl test_dek_01 -f dek.bin
```
