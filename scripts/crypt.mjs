// data/ 폴더 암호화 / 복호화
//
// 저장소를 공개로 두더라도 성과 데이터·소재 이미지는 비밀번호 없이 못 보도록
// data/ 아래 파일을 AES-256-GCM 으로 암호화한 .enc 파일만 커밋한다.
// 대시보드(index.html)는 브라우저에서 같은 비밀번호로 풀어서 보여준다.
//
//   node scripts/crypt.mjs decrypt   # data/**/*.enc  -> 원본 (수집 전에 이전 데이터 복원)
//   node scripts/crypt.mjs encrypt   # 원본 -> data/**/*.enc (커밋용)
//
// 환경 변수: DASHBOARD_PASSWORD (필수)
//
// 파일 형식
//   data/key.json : { v, iter, salt, check }  — salt 는 처음 한 번 만들고 계속 씀
//   *.enc         : IV(12바이트) + 암호문 + 인증 태그(16바이트)
// 키: PBKDF2-SHA256(비밀번호, salt, iter) 64바이트 → 앞 32 = AES 키, 뒤 32 = IV 생성용 HMAC 키
// IV 는 HMAC(경로 + 내용)으로 정해서, 내용이 같으면 암호문도 같다 → 안 바뀐 파일은 커밋되지 않음

import { createCipheriv, createDecipheriv, createHmac, pbkdf2Sync, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DATA = join(ROOT, "data");
const KEY_FILE = join(DATA, "key.json");
const ITER = 600000;
const CHECK_TEXT = "meta-report-ok";

const password = (process.env.DASHBOARD_PASSWORD || "").trim();
if (!password) {
  console.error("DASHBOARD_PASSWORD 가 설정되지 않았습니다. 저장소 Secrets 에 등록하세요.");
  process.exit(1);
}

function deriveKeys(salt, iter) {
  const bits = pbkdf2Sync(password, salt, iter, 64, "sha256");
  return { aes: bits.subarray(0, 32), mac: bits.subarray(32) };
}

function encrypt(keys, label, plain) {
  const iv = createHmac("sha256", keys.mac).update(label + "\0").update(plain).digest().subarray(0, 12);
  const c = createCipheriv("aes-256-gcm", keys.aes, iv);
  return Buffer.concat([iv, c.update(plain), c.final(), c.getAuthTag()]);
}

function decrypt(keys, buf) {
  const d = createDecipheriv("aes-256-gcm", keys.aes, buf.subarray(0, 12));
  d.setAuthTag(buf.subarray(buf.length - 16));
  return Buffer.concat([d.update(buf.subarray(12, buf.length - 16)), d.final()]);
}

function walk(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).flatMap(name => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? walk(p) : [p];
  });
}

const rel = p => relative(ROOT, p).split(sep).join("/");

function loadKeys({ create }) {
  if (!existsSync(KEY_FILE)) {
    if (!create) return null;
    mkdirSync(DATA, { recursive: true });
    const salt = randomBytes(16);
    const keys = deriveKeys(salt, ITER);
    const check = encrypt(keys, "check", Buffer.from(CHECK_TEXT));
    writeFileSync(KEY_FILE, JSON.stringify({ v: 1, iter: ITER, salt: salt.toString("base64"), check: check.toString("base64") }, null, 1));
    console.log("새 암호화 키 정보(data/key.json)를 만들었습니다.");
    return keys;
  }
  const info = JSON.parse(readFileSync(KEY_FILE, "utf8"));
  const keys = deriveKeys(Buffer.from(info.salt, "base64"), info.iter);
  try {
    if (decrypt(keys, Buffer.from(info.check, "base64")).toString() !== CHECK_TEXT) throw new Error();
  } catch {
    console.error("비밀번호가 기존 데이터와 맞지 않습니다. (DASHBOARD_PASSWORD 를 바꿨다면 README 의 '비밀번호 바꾸기'를 참고하세요)");
    process.exit(1);
  }
  return keys;
}

const mode = process.argv[2];
if (mode === "decrypt") {
  const keys = loadKeys({ create: false });
  if (!keys) { console.log("암호화된 이전 데이터 없음 (첫 실행)"); process.exit(0); }
  let n = 0;
  for (const p of walk(DATA).filter(p => p.endsWith(".enc"))) {
    writeFileSync(p.slice(0, -4), decrypt(keys, readFileSync(p)));
    n++;
  }
  console.log(`복호화 완료: ${n}개`);
} else if (mode === "encrypt") {
  const keys = loadKeys({ create: true });
  let n = 0, same = 0;
  for (const p of walk(DATA).filter(p => !p.endsWith(".enc") && p !== KEY_FILE)) {
    const out = encrypt(keys, rel(p), readFileSync(p));
    const encPath = p + ".enc";
    if (existsSync(encPath) && readFileSync(encPath).equals(out)) { same++; continue; }
    writeFileSync(encPath, out);
    n++;
  }
  // 수집 스크립트가 지운 파일(예: 제품별 사용 안 함)은 암호화본도 지운다.
  // decrypt 단계에서 모든 .enc 를 원본으로 풀어두므로, 원본이 없는 .enc 는 일부러 지운 것뿐이다
  let removed = 0;
  for (const p of walk(DATA).filter(p => p.endsWith(".enc"))) {
    if (!existsSync(p.slice(0, -4))) { unlinkSync(p); removed++; }
  }
  console.log(`암호화 완료: 새로 쓴 파일 ${n}개, 변경 없음 ${same}개, 삭제 ${removed}개`);
} else {
  console.error("사용법: node scripts/crypt.mjs encrypt|decrypt");
  process.exit(1);
}
