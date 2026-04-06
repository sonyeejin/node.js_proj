# ── 베이스 이미지 ─────────────────────────────────────────────────────────────
# M2 맥 (arm64) + Linux 서버 (amd64) 모두 호환되는 Node.js LTS
FROM node:20-slim

# ── 시스템 패키지 설치 ────────────────────────────────────────────────────────
# strace: 시스템 콜 추적 (프로세스 실행, 파일 접근 감시)
# dnsutils: DNS 조회 탐지용
# curl: 네트워크 연결 테스트용
RUN apt-get update && apt-get install -y \
    strace \
    dnsutils \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── 작업 디렉토리 ─────────────────────────────────────────────────────────────
WORKDIR /analysis

# ── dynamic_runner.js 복사 ────────────────────────────────────────────────────
COPY dynamic_runner.js .

# ── 컨테이너 실행 시 기본 명령 ────────────────────────────────────────────────
# 실행 시 인자로 패키지 경로를 받음
# 예: docker run --rm <image> /pkg/node_modules/some-package
ENTRYPOINT ["node", "dynamic_runner.js"]
