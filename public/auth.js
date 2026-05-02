/* ═══════════════════════════════════════════
   SNUBH Auth Module — auth.js
   회원가입(Sign-In) / 로그인 / 로그아웃 / 자동저장
   모든 페이지에서 공통 사용
   ═══════════════════════════════════════════ */
(function(){
"use strict";

const API = "";  // same-origin

// ── Token / Session 관리 ──
function getToken(){ return localStorage.getItem("snubh_token"); }
function setToken(t){ localStorage.setItem("snubh_token",t); }
function getUser(){ try{ return JSON.parse(localStorage.getItem("snubh_user")||"null"); }catch{ return null; } }
function setUser(u){ localStorage.setItem("snubh_user",JSON.stringify(u)); }
function clearSession(){ localStorage.removeItem("snubh_token"); localStorage.removeItem("snubh_user"); }
function isLoggedIn(){ return !!getToken() && !!getUser(); }
function authHeader(){ const t=getToken(); return t?{"Authorization":"Bearer "+t}:{}; }

// ── expose globally ──
window.snubhAuth = { getToken, getUser, isLoggedIn, authHeader, clearSession, logout, savePrediction, getUserPredictions, getUserSummary };

// ── CSS injection ──
function injectCSS(){
  if(document.getElementById("auth-css")) return;
  const s=document.createElement("style"); s.id="auth-css";
  s.textContent=`
/* Auth bar */
#snubh-auth-bar{position:fixed;top:0;left:0;right:0;height:44px;background:rgba(7,11,20,.95);border-bottom:1px solid #1e2d45;display:flex;align-items:center;justify-content:flex-end;padding:0 16px;z-index:10000;backdrop-filter:blur(8px);gap:10px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;}
#snubh-auth-bar .au-name{color:#e6edf3;font-size:13px;font-weight:500;}
#snubh-auth-bar .au-badge{background:#22c55e22;color:#22c55e;font-size:11px;padding:2px 8px;border-radius:10px;}
#snubh-auth-bar .au-btn{background:none;border:1px solid #1e2d45;color:#7a9bbf;font-size:12px;padding:5px 14px;border-radius:6px;cursor:pointer;transition:.2s;}
#snubh-auth-bar .au-btn:hover{border-color:#00d4ff;color:#00d4ff;}
#snubh-auth-bar .au-btn.primary{background:#00d4ff22;border-color:#00d4ff55;color:#00d4ff;}
#snubh-auth-bar .au-summary{color:#7a9bbf;font-size:11px;}

/* Modal overlay */
.auth-overlay{position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:10001;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(4px);opacity:0;transition:opacity .25s;}
.auth-overlay.show{opacity:1;}
.auth-modal{background:#0d1220;border:1px solid #1e2d45;border-radius:14px;width:380px;max-width:92vw;max-height:90vh;overflow-y:auto;padding:28px;box-shadow:0 20px 60px rgba(0,0,0,.5);}
.auth-modal h2{color:#e6edf3;margin:0 0 6px;font-size:20px;}
.auth-modal .subtitle{color:#7a9bbf;font-size:13px;margin-bottom:20px;}
.auth-modal label{display:block;color:#7a9bbf;font-size:12px;margin:12px 0 4px;font-weight:500;}
.auth-modal input{width:100%;box-sizing:border-box;background:#111827;border:1px solid #1e2d45;color:#e6edf3;padding:10px 12px;border-radius:8px;font-size:14px;outline:none;transition:border .2s;}
.auth-modal input:focus{border-color:#00d4ff;}
.auth-modal input::placeholder{color:#3a4a60;}
.auth-modal .pin-row{display:flex;gap:8px;justify-content:center;margin-top:6px;}
.auth-modal .pin-box{width:52px;height:52px;text-align:center;font-size:22px;font-weight:700;letter-spacing:4px;border-radius:10px;background:#111827;border:2px solid #1e2d45;color:#00d4ff;}
.auth-modal .pin-box:focus{border-color:#00d4ff;box-shadow:0 0 0 3px #00d4ff22;}
.auth-modal .err-msg{color:#ef4444;font-size:12px;margin-top:8px;min-height:16px;}
.auth-modal .auth-submit{width:100%;padding:12px;margin-top:18px;background:linear-gradient(135deg,#00d4ff,#3b82f6);color:#000;border:none;border-radius:10px;font-size:15px;font-weight:700;cursor:pointer;transition:opacity .2s;}
.auth-modal .auth-submit:disabled{opacity:.5;cursor:not-allowed;}
.auth-modal .auth-submit:hover:not(:disabled){opacity:.85;}
.auth-modal .switch-link{text-align:center;margin-top:14px;font-size:13px;color:#7a9bbf;}
.auth-modal .switch-link a{color:#00d4ff;cursor:pointer;text-decoration:none;}
.auth-modal .switch-link a:hover{text-decoration:underline;}
.auth-modal .close-btn{position:absolute;top:12px;right:14px;background:none;border:none;color:#7a9bbf;font-size:20px;cursor:pointer;line-height:1;}
.auth-modal .close-btn:hover{color:#ef4444;}
.auth-modal .ssn-note{color:#3b82f6;font-size:11px;margin-top:4px;}
`;
  document.head.appendChild(s);
}

// ── Auth Bar 렌더 ──
function renderAuthBar(){
  let bar=document.getElementById("snubh-auth-bar");
  if(!bar){
    bar=document.createElement("div");
    bar.id="snubh-auth-bar";
    document.body.prepend(bar);
    // push page content down
    document.body.style.paddingTop="44px";
  }
  if(isLoggedIn()){
    const u=getUser();
    bar.innerHTML=`
      <span class="au-summary" id="au-summary"></span>
      <span class="au-badge">● 인증됨</span>
      <span class="au-name">${esc(u.name)} (${esc(u.username)})</span>
      <button class="au-btn" onclick="snubhAuth.logout()">로그아웃</button>`;
    loadSummary();
  } else {
    bar.innerHTML=`
      <span class="au-summary" style="color:#ef4444">비인증 상태 — 데이터가 저장되지 않습니다</span>
      <button class="au-btn primary" onclick="window._authShowLogin()">로그인</button>
      <button class="au-btn" onclick="window._authShowSignup()">회원가입</button>`;
  }
}

async function loadSummary(){
  const el=document.getElementById("au-summary");
  if(!el||!isLoggedIn()) return;
  try{
    const r=await fetch(API+"/api/user/summary",{headers:authHeader()});
    const d=await r.json();
    if(d.ok){
      el.textContent="누적 "+d.total_predictions+"건 저장됨";
    }
  }catch{}
}

function esc(s){ const d=document.createElement("div"); d.textContent=s; return d.innerHTML; }

// ── 모달: 회원가입 ──
function showSignupModal(){
  closeModal();
  const ov=document.createElement("div"); ov.className="auth-overlay"; ov.id="auth-modal-overlay";
  ov.innerHTML=`<div class="auth-modal" style="position:relative">
    <button class="close-btn" onclick="window._authClose()">&times;</button>
    <h2>회원가입</h2>
    <p class="subtitle">SNUBH 5대 질환 AI 시스템 계정 생성</p>
    <label>이름 <span style="color:#ef4444">*</span></label>
    <input id="su-name" placeholder="홍길동" maxlength="30" autocomplete="off">
    <label>모바일 번호 <span style="color:#ef4444">*</span></label>
    <input id="su-mobile" placeholder="010-1234-5678" maxlength="13" autocomplete="off">
    <label>주민등록번호 <span style="color:#ef4444">*</span></label>
    <input id="su-ssn" placeholder="000000-0000000" maxlength="14" autocomplete="off">
    <div class="ssn-note">🔒 SHA-256 암호화 저장 — 평문 보관하지 않음</div>
    <label>아이디 <span style="color:#ef4444">*</span></label>
    <input id="su-user" placeholder="영문/숫자 2~20자" maxlength="20" autocomplete="off">
    <label>비밀번호 (숫자 4자리) <span style="color:#ef4444">*</span></label>
    <div class="pin-row">
      <input class="pin-box" id="su-p1" type="password" maxlength="1" inputmode="numeric" pattern="[0-9]" autocomplete="off">
      <input class="pin-box" id="su-p2" type="password" maxlength="1" inputmode="numeric" pattern="[0-9]" autocomplete="off">
      <input class="pin-box" id="su-p3" type="password" maxlength="1" inputmode="numeric" pattern="[0-9]" autocomplete="off">
      <input class="pin-box" id="su-p4" type="password" maxlength="1" inputmode="numeric" pattern="[0-9]" autocomplete="off">
    </div>
    <div class="err-msg" id="su-err"></div>
    <button class="auth-submit" id="su-btn" onclick="window._authDoSignup()">가입하기</button>
    <div class="switch-link">이미 계정이 있으신가요? <a onclick="window._authShowLogin()">로그인</a></div>
  </div>`;
  document.body.appendChild(ov);
  requestAnimationFrame(()=>{ ov.classList.add("show"); });
  setupPinNav("su");
  ov.addEventListener("click",(e)=>{ if(e.target===ov) closeModal(); });
}

// ── 모달: 로그인 ──
function showLoginModal(){
  closeModal();
  const ov=document.createElement("div"); ov.className="auth-overlay"; ov.id="auth-modal-overlay";
  ov.innerHTML=`<div class="auth-modal" style="position:relative">
    <button class="close-btn" onclick="window._authClose()">&times;</button>
    <h2>로그인</h2>
    <p class="subtitle">아이디와 비밀번호 4자리를 입력하세요</p>
    <label>아이디</label>
    <input id="li-user" placeholder="아이디 입력" maxlength="20" autocomplete="off">
    <label>비밀번호 (숫자 4자리)</label>
    <div class="pin-row">
      <input class="pin-box" id="li-p1" type="password" maxlength="1" inputmode="numeric" pattern="[0-9]" autocomplete="off">
      <input class="pin-box" id="li-p2" type="password" maxlength="1" inputmode="numeric" pattern="[0-9]" autocomplete="off">
      <input class="pin-box" id="li-p3" type="password" maxlength="1" inputmode="numeric" pattern="[0-9]" autocomplete="off">
      <input class="pin-box" id="li-p4" type="password" maxlength="1" inputmode="numeric" pattern="[0-9]" autocomplete="off">
    </div>
    <div class="err-msg" id="li-err"></div>
    <button class="auth-submit" id="li-btn" onclick="window._authDoLogin()">로그인</button>
    <div class="switch-link">계정이 없으신가요? <a onclick="window._authShowSignup()">회원가입</a></div>
  </div>`;
  document.body.appendChild(ov);
  requestAnimationFrame(()=>{ ov.classList.add("show"); });
  setupPinNav("li");
  ov.addEventListener("click",(e)=>{ if(e.target===ov) closeModal(); });
}

function closeModal(){
  const ov=document.getElementById("auth-modal-overlay");
  if(ov) ov.remove();
}

// ── PIN 입력 자동 이동 ──
function setupPinNav(prefix){
  for(let i=1;i<=4;i++){
    const el=document.getElementById(prefix+"-p"+i);
    if(!el) continue;
    el.addEventListener("input",function(){
      this.value=this.value.replace(/[^0-9]/g,"");
      if(this.value.length===1 && i<4){
        const next=document.getElementById(prefix+"-p"+(i+1));
        if(next) next.focus();
      }
    });
    el.addEventListener("keydown",function(e){
      if(e.key==="Backspace" && !this.value && i>1){
        const prev=document.getElementById(prefix+"-p"+(i-1));
        if(prev){ prev.focus(); prev.value=""; }
      }
    });
  }
}

function getPin(prefix){
  return (document.getElementById(prefix+"-p1")||{}).value +
         (document.getElementById(prefix+"-p2")||{}).value +
         (document.getElementById(prefix+"-p3")||{}).value +
         (document.getElementById(prefix+"-p4")||{}).value;
}

// ── 회원가입 처리 ──
async function doSignup(){
  const errEl=document.getElementById("su-err");
  const btn=document.getElementById("su-btn");
  errEl.textContent="";
  const name=(document.getElementById("su-name")||{}).value||"";
  const mobile=(document.getElementById("su-mobile")||{}).value||"";
  const ssn=(document.getElementById("su-ssn")||{}).value||"";
  const username=(document.getElementById("su-user")||{}).value||"";
  const pin=getPin("su");

  if(!name||!mobile||!ssn||!username||pin.length!==4){
    errEl.textContent="모든 필드를 올바르게 입력해주세요.";
    return;
  }
  btn.disabled=true; btn.textContent="처리 중...";
  try{
    const r=await fetch(API+"/api/auth/signup",{
      method:"POST", headers:{"Content-Type":"application/json"},
      body:JSON.stringify({name,mobile,ssn,username,pin})
    });
    const d=await r.json();
    if(!r.ok){ errEl.textContent=d.error||"회원가입 실패"; btn.disabled=false; btn.textContent="가입하기"; return; }
    setToken(d.token);
    setUser(d.user);
    closeModal();
    renderAuthBar();
    syncLocalToServer();
  }catch(e){
    errEl.textContent="네트워크 오류"; btn.disabled=false; btn.textContent="가입하기";
  }
}

// ── 로그인 처리 ──
async function doLogin(){
  const errEl=document.getElementById("li-err");
  const btn=document.getElementById("li-btn");
  errEl.textContent="";
  const username=(document.getElementById("li-user")||{}).value||"";
  const pin=getPin("li");

  if(!username||pin.length!==4){
    errEl.textContent="아이디와 비밀번호 4자리를 입력해주세요.";
    return;
  }
  btn.disabled=true; btn.textContent="로그인 중...";
  try{
    const r=await fetch(API+"/api/auth/login",{
      method:"POST", headers:{"Content-Type":"application/json"},
      body:JSON.stringify({username,pin})
    });
    const d=await r.json();
    if(!r.ok){ errEl.textContent=d.error||"로그인 실패"; btn.disabled=false; btn.textContent="로그인"; return; }
    setToken(d.token);
    setUser(d.user);
    closeModal();
    renderAuthBar();
    syncLocalToServer();
  }catch(e){
    errEl.textContent="네트워크 오류"; btn.disabled=false; btn.textContent="로그인";
  }
}

// ── 로그아웃 — 자동 저장 후 세션 정리 ──
async function logout(){
  if(isLoggedIn()){
    await autoSaveAll();
  }
  clearSession();
  renderAuthBar();
}

// ── 자동 저장: localStorage → 서버 ──
async function autoSaveAll(){
  if(!isLoggedIn()) return;
  // Save last scores (Stage 1)
  const scores=localStorage.getItem("snubh_last_scores");
  if(scores){
    try{ await savePrediction("stage1",JSON.parse(scores)); }catch{}
  }
  // Save user profile
  const profile=localStorage.getItem("snubh_user_profile");
  if(profile){
    try{ await savePrediction("profile",JSON.parse(profile)); }catch{}
  }
  // Save tracker logs
  const logs=localStorage.getItem("snubh_logs");
  if(logs){
    try{ await savePrediction("tracker_logs",JSON.parse(logs)); }catch{}
  }
}

// ── 로그인 직후: localStorage 기존 데이터 서버 동기화 ──
async function syncLocalToServer(){
  await autoSaveAll();
}

// ── API wrappers ──
async function savePrediction(stage, resultData){
  if(!isLoggedIn()) return null;
  try{
    const r=await fetch(API+"/api/user/save-prediction",{
      method:"POST",
      headers:{"Content-Type":"application/json",...authHeader()},
      body:JSON.stringify({stage,result_data:resultData})
    });
    return await r.json();
  }catch{ return null; }
}

async function getUserPredictions(stage){
  if(!isLoggedIn()) return [];
  try{
    const url=API+"/api/user/predictions"+(stage?"?stage="+stage:"");
    const r=await fetch(url,{headers:authHeader()});
    const d=await r.json();
    return d.ok?d.predictions:[];
  }catch{ return []; }
}

async function getUserSummary(){
  if(!isLoggedIn()) return null;
  try{
    const r=await fetch(API+"/api/user/summary",{headers:authHeader()});
    const d=await r.json();
    return d.ok?d:null;
  }catch{ return null; }
}

// ── Global hooks ──
window._authShowLogin = showLoginModal;
window._authShowSignup = showSignupModal;
window._authDoLogin = doLogin;
window._authDoSignup = doSignup;
window._authClose = closeModal;

// ── Init on DOM ready ──
function initAuth(){
  injectCSS();
  renderAuthBar();
  // Verify token on load
  if(isLoggedIn()){
    fetch(API+"/api/auth/me",{headers:authHeader()}).then(r=>{
      if(!r.ok){ clearSession(); renderAuthBar(); }
    }).catch(()=>{});
  }
}

if(document.readyState==="loading"){
  document.addEventListener("DOMContentLoaded",initAuth);
} else {
  initAuth();
}

})();
