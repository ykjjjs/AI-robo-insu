-- ══════════════════════════════════════════════════════════
-- 0003 보안 보강
--  1) 서버 시크릿 보관소 (토큰 HMAC 서명 키)
--  2) 로그인 시도 기록 (무차별 대입 차단)
--  3) 주민등록번호 해시 폐기
-- ══════════════════════════════════════════════════════════

-- 1) 앱 시크릿 — 최초 요청 시 워커가 32바이트 난수를 1회 생성해 보관한다.
--    (wrangler secret put AUTH_SECRET 을 설정하면 그쪽이 우선한다)
CREATE TABLE IF NOT EXISTS app_secrets (
  key        TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  created_at TEXT NOT NULL
);

-- 2) 로그인 시도 — 실패 누적 시 일시 차단
CREATE TABLE IF NOT EXISTS login_attempts (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  username   TEXT NOT NULL,
  ok         INTEGER NOT NULL,
  at_ms      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_attempts ON login_attempts(username, at_ms DESC);

-- 3) 주민등록번호 해시 폐기.
--    이 앱은 ssn_hash 를 어디서도 읽지 않는다(기능상 불필요한 수집이었다).
--    무염 SHA-256 은 생년월일·성별·지역 구조 때문에 사실상 역산이 가능하므로 값을 비운다.
--    NOT NULL 제약이 있어 컬럼 삭제 대신 빈 문자열로 덮어쓴다.
UPDATE users SET ssn_hash = '' WHERE ssn_hash <> '';
