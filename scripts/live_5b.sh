#!/usr/bin/env bash
# heain-console live test 5b: people administer a real heain-core tree through heain-gateway and heain-console.
#   G (18000, root) <- Z (18001). On G: heain-database, heain-gateway (people on 127.0.0.1:18443), heain-console,
#   heain-report. ops.c1 is an app client certificate (report admin); admin / approver-1 are certificate identities.
#  - core: gateway.apps, console.apps, roles.admins {user:anna}, roles.approvers + user:boss, the exposures (P5);
#  - the screens load anonymously with a strict CSP; people sign in at the gateway (password + TOTP);
#  - anna (MFA) acts in core as user:anna: whoami, a 2a change, a 2b proposal; boss (an Approver only) approves it;
#  - refused: a password-only sign-in (MFA), a person with no admin role, an app calling the console, an app calling
#    core's relay; a client certificate whose CN is "user:anna" holds none of anna's roles;
#  - remote admin to Z through the console; a heain-report dashboard through the gateway;
#  - core's audit: the relays (assertion ids), the changes as user:anna, the approval as user:boss; the chain verifies.
# Needs ~/heain-core, ~/heain-sdk, ~/heain-gateway, ~/heain-database, ~/heain-report. ~3 min.
# Run from ~/heain-console:  bash scripts/live_5b.sh
set -uo pipefail
CO=$(cd "$(dirname "$0")/.." && pwd)
GWD=${HEAIN_GW_DIR:-$HOME/heain-gateway}; DBDIR=${HEAIN_DB_DIR:-$HOME/heain-database}; RPD=${HEAIN_REPORT_DIR:-$HOME/heain-report}
cd ~/heain-core || { echo "needs ~/heain-core"; exit 1; }
H=./test_1_2_live.sh
T=$HOME/heain-core/.test-1.2
C=$T/certs; L=$T/logs; P=$T/pids; BIN=$T/node; W=$T/console-5b
URL=https://127.0.0.1:18000; ZURL=https://127.0.0.1:18001
PUB=https://127.0.0.1:18443
PASS=0; FAIL=0
ok()  { echo "  PASS: $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $*"; FAIL=$((FAIL+1)); }
as() { local who=$1; shift; curl -sk --noproxy '*' --cert "$C/$who.pem" --key "$C/$who.key" --cacert "$C/ca.pem" "$@"; }
code() { local who=$1; shift; as "$who" -o /dev/null -w "%{http_code}" "$@"; }
cl() { local who=$1; shift; curl -sk --noproxy '*' --cert "$W/$who.pem" --key "$W/$who.key" --cacert "$C/ca.pem" -H 'Content-Type: application/json' "$@"; }
j() { python3 -c "import json,sys;d=json.load(sys.stdin);print($1)" 2>/dev/null; }
mkcert() { [ -f "$C/$1.pem" ] && return; openssl genrsa -out "$C/$1.key" 2048 >/dev/null 2>&1
  openssl req -new -key "$C/$1.key" -subj "/CN=$1" -out "$C/$1.csr" >/dev/null 2>&1
  openssl x509 -req -in "$C/$1.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -out "$C/$1.pem" \
    -days 825 -sha256 -extfile <(printf "subjectAltName=DNS:%s" "$(echo "$1" | tr -c 'a-z0-9.\n-' '-')") >/dev/null 2>&1; }
runapp() { local inst=$1 man=$2 port=$3 st=$4; shift 4; mkdir -p "$st"
  HEAIN_MANIFEST=$man HEAIN_INSTANCE=$inst HEAIN_CORE_URL=$URL HEAIN_CORE_ID=G HEAIN_CA=$C/ca.pem HEAIN_CHAIN=$W/prov.pem \
  HEAIN_STATE_DIR=$st HEAIN_ENROLL_TOKEN=$W/$inst.tok HEAIN_ENDPOINT_BASE=https://127.0.0.1:$port HEAIN_LISTEN=127.0.0.1:$port \
    nohup "$@" >> "$W/$inst.log" 2>&1 &
  echo $! > "$P/$inst.pid"; }
token() { as admin -X POST -H 'Content-Type: application/json' -d "{\"label\":\"$1\"}" $URL/provision/token > "$W/$2.tok"; }
pending() { as approver-1 $URL/v1/admin/policy/pending | j "' '.join(x['ID'] for x in d['actions'] if x['Type']=='$1')"; }
approve() { code approver-1 -X POST "$URL/v1/admin/policy/$1/approve"; }
setpol() { local id; id=$(as admin -X POST -d "{\"value\":$2}" $URL/v1/admin/config/policy/$1 | j "d['action_id']"); [ -n "$id" ] && [ "$(approve $id)" = 200 ]; }
f() { as admin $1/v1/admin/config | j "[x for x in d['fields'] if x['key']=='$2'][0]$3"; }
audit() { as admin "$URL/v1/admin/audit?limit=5000&from=1"; }
client() { as admin -X POST -H 'Content-Type: application/json' -d "{\"label\":\"$1\"}" $URL/provision/token > "$W/$1.json"
  python3 - "$W" "$1" <<'PY'
import json,sys; w,l=sys.argv[1],sys.argv[2]; d=json.load(open(f"{w}/{l}.json"))
open(f"{w}/{l}.boot.pem","w").write(d["bootstrap_cert_pem"]+open(w+"/prov.pem").read()); open(f"{w}/{l}.boot.key","w").write(d["bootstrap_key_pem"]); open(f"{w}/{l}.token","w").write(d["token"])
PY
  openssl genrsa -out "$W/$1.key" 2048 >/dev/null 2>&1; openssl req -new -key "$W/$1.key" -subj "/CN=$1" -out "$W/$1.csr" >/dev/null 2>&1
  python3 -c "import json;print(json.dumps({'token':open('$W/$1.token').read(),'csr_pem':open('$W/$1.csr').read()}))" > "$W/$1.req"
  curl -sk --noproxy '*' --cert "$W/$1.boot.pem" --key "$W/$1.boot.key" --cacert "$C/ca.pem" -X POST -H 'Content-Type: application/json' -d @"$W/$1.req" $URL/provision/csr \
    | python3 -c "import json,sys;open('$W/$1.pem','w').write(json.load(sys.stdin)['cert_pem']+open('$W/prov.pem').read())"; }
# a person's browser: cookie jar + CSRF token
pub() { local who=$1; shift; curl -sk --noproxy '*' -b "$W/$who.jar" -c "$W/$who.jar" "$@"; }
pcode() { local who=$1; shift; pub "$who" -o /dev/null -w "%{http_code}" "$@"; }
csrf() { cat "$W/$1.csrf" 2>/dev/null; }
login() { local out; out=$(pub "$1" -X POST -H 'Content-Type: application/json' -d "{\"username\":\"$2\",\"password\":\"$3\",\"client\":\"web\"${4:+,$4}}" $PUB/auth/login)
  echo "$out" | j "d.get('csrf_token','')" > "$W/$1.csrf"; echo "$out"; }
totpcode() { python3 - "$1" "${2:-0}" <<'PY'
import base64,hmac,hashlib,struct,sys,time
s=sys.argv[1]; k=base64.b32decode(s+"="*((8-len(s)%8)%8)); c=int(time.time())//30+int(sys.argv[2])
h=hmac.new(k,struct.pack(">Q",c),hashlib.sha1).digest(); o=h[-1]&15
print("%06d"%((struct.unpack(">I",h[o:o+4])[0]&0x7fffffff)%1000000))
PY
}
# person <user> <password> [totp]: signs in; with totp, sets up an authenticator and signs in again with it
PW=Blue-Harbor-2026-x1
person() { login "$1" "$1" "$2" >/dev/null
  [ "${3:-}" = totp ] || return 0
  local sec; sec=$(pub "$1" -X POST -H "X-CSRF-Token: $(csrf "$1")" -H 'Content-Type: application/json' -d "{\"password\":\"$2\"}" $PUB/auth/totp/setup | j "d['secret']")
  pub "$1" -X POST -H "X-CSRF-Token: $(csrf "$1")" -H 'Content-Type: application/json' -d "{\"code\":\"$(totpcode "$sec")\"}" $PUB/auth/totp/confirm >/dev/null
  login "$1" "$1" "$2" "\"totp\":\"$(totpcode "$sec" 1)\"" >/dev/null; }
# as a signed-in person, through the gateway: cget <who> <path>, csend <who> <method> <path> <json>
CP=$PUB/api/heain-console/v1/core
cget() { pub "$1" "$CP/$2"; }
csend() { pub "$1" -X "$2" -H "X-CSRF-Token: $(csrf "$1")" -H 'Content-Type: application/json' -d "$4" "$CP/$3"; }

echo "== 0. G <- Z; build"
$H clean >/dev/null; $H build >/dev/null || { echo "core build failed"; exit 1; }; $H certs >/dev/null
mkdir -p "$L" "$P" "$T/data-G" "$T/data-Z" "$W"; for c in admin approver-1 "user:anna"; do mkcert "$c"; done
cp "$C/user:anna.pem" "$C/fake-anna.pem"; cp "$C/user:anna.key" "$C/fake-anna.key"   # curl reads ":" in --cert as a password separator
openssl genrsa -out "$W/prov.key" 2048 >/dev/null 2>&1
openssl req -new -key "$W/prov.key" -subj "/CN=heain-test-provisioning-ca" -out "$W/prov.csr" >/dev/null 2>&1
openssl x509 -req -in "$W/prov.csr" -CA "$C/ca.pem" -CAkey "$C/ca.key" -CAcreateserial -out "$W/prov.pem" -days 30 -sha256 \
  -extfile <(printf "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign") >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/public.key" -out "$W/public.pem" -days 2 -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1
: > "$L/G.log"; : > "$L/Z.log"
COMMON="-ca=$C/ca.pem -admin-node-id=admin -approver-ids=approver-1 -bootstrap=true"
nohup "$BIN" -node-id=G -tier=GLOBAL_PRIMARY -raft-addr=127.0.0.1:19000 -data-dir="$T/data-G" -http-addr=127.0.0.1:18000 -cert="$C/G.pem" -key="$C/G.key" $COMMON \
  -approval-store-path="$T/data-G/approvals.db" -ingest-queue-path="$T/data-G/queue.db" -provision-ca-cert="$W/prov.pem" -provision-ca-key="$W/prov.key" >> "$L/G.log" 2>&1 &
echo $! > "$P/G.pid"; sleep 4
nohup "$BIN" -node-id=Z -tier=SECONDARY -raft-addr=127.0.0.1:19001 -data-dir="$T/data-Z" -http-addr=127.0.0.1:18001 -cert="$C/Z.pem" -key="$C/Z.key" $COMMON \
  -approval-store-path="$T/data-Z/approvals.db" -ingest-queue-path="$T/data-Z/queue.db" -parent-addr=https://127.0.0.1:18000/health -parent-node-id=G \
  -promote-raft-addr=127.0.0.1:19101 -promote-data-dir=$T/promote-Z -farm-registry-ttl=30s >> "$L/Z.log" 2>&1 &
echo $! > "$P/Z.pid"; sleep 4
[ "$(code admin -X PUT -d '{"value":"2s"}' $URL/v1/admin/config/system/config.sync_interval)" = 200 ] || bad "sync interval"
B="GOFLAGS= GOWORK=${SDK_GOWORK:-}"
( cd "$CO" && eval "$B go build -o $W/heain-console ./cmd/heain-console" ) && ( cd "$GWD" && eval "$B go build -o $W/heain-gateway ./cmd/heain-gateway" ) \
  && ( cd "$RPD" && eval "$B go build -o $W/heain-report ./cmd/heain-report" ) && ok "heain-console, heain-gateway and heain-report build" || { bad "build"; exit 1; }
if [ -n "${HEAIN_DB_BIN:-}" ]; then cp "$HEAIN_DB_BIN" "$W/heain-database"; else ( cd "$DBDIR" && GOFLAGS= go build -o "$W/heain-database" ./cmd/heain-database ); fi
for k in $(seq 1 15); do [ "$(code admin -X POST -H 'Content-Type: application/json' -d '{"label":"probe.x"}' $URL/provision/token)" = 200 ] && break; sleep 1; done
client ops.c1

echo "== 1. the apps start and are admitted"
for t in "heain-database.db1 db1" "heain-gateway.g1 g1" "heain-console.c1 c1" "heain-report.r1 r1"; do token $t; done
runapp db1 "$DBDIR/heain-app.yaml" 19460 "$W/state-db1" "$W/heain-database" -external-dialect sqlite
runapp g1 "$GWD/heain-app.yaml" 19500 "$W/state-g1" "$W/heain-gateway" -public-listen 127.0.0.1:18443 -public-cert "$W/public.pem" -public-key "$W/public.key" -bootstrap-admin root -routes-refresh 1s
runapp c1 "$CO/heain-app.yaml" 19590 "$W/state-c1" "$W/heain-console"
runapp r1 "$RPD/heain-app.yaml" 19580 "$W/state-r1" "$W/heain-report" -admin-callers ops -poll 1s
for k in $(seq 1 60); do for a in $(pending app.register); do approve $a >/dev/null; done
  n=$(grep -l ": active" "$W"/db1.log "$W"/g1.log "$W"/c1.log "$W"/r1.log 2>/dev/null | wc -l); [ "$n" = 4 ] && break; sleep 1; done
[ "$n" = 4 ] && ok "heain-database, heain-gateway, heain-console and heain-report admitted" || { bad "start: $(tail -2 "$W/c1.log")"; $H stop-all >/dev/null 2>&1; exit 1; }

echo "== 2. core trusts the gateway and the console; who is who (all through P5)"
setpol gateway.apps '["heain-gateway"]' && setpol console.apps '["heain-console"]' && ok "gateway.apps [heain-gateway], console.apps [heain-console]" || bad "apps"
setpol roles.admins '{"user:anna":["operator","policy-admin"]}' && setpol roles.approvers '["approver-1","user:boss"]' && ok "roles.admins {user:anna: operator, policy-admin}; roles.approvers + user:boss" || bad "roles"
setpol audit.readers '["heain-report"]' || bad "audit.readers"
setpol gateway.exposures '[{"app":"heain-console","method":"GET","path":"/ui/{path...}","auth":"anonymous","rate_per_min":600},
 {"app":"heain-console","method":"GET","path":"/v1/core/{path...}","roles":["console"]},
 {"app":"heain-console","method":"POST","path":"/v1/core/{path...}","roles":["console"]},
 {"app":"heain-console","method":"PUT","path":"/v1/core/{path...}","roles":["console"]},
 {"app":"heain-console","method":"DELETE","path":"/v1/core/{path...}","roles":["console"]},
 {"app":"heain-report","method":"GET","path":"/v1/reports","roles":["console"]},
 {"app":"heain-report","method":"GET","path":"/v1/dashboards/{id}","roles":["console"]}]' && ok "the console's and heain-report's routes exposed (role console)" || bad "exposures"
for k in $(seq 1 20); do [ "$(cl ops.c1 https://127.0.0.1:19500/v1/gateway/routes | j "len([r for r in d['routes'] if r['status']=='ok'])")" = 7 ] && break; sleep 1; done
[ "$(cl ops.c1 https://127.0.0.1:19500/v1/gateway/routes | j "len([r for r in d['routes'] if r['status']=='ok'])")" = 7 ] && ok "the gateway sees the 7 routes" || bad "routes: $(cl ops.c1 https://127.0.0.1:19500/v1/gateway/routes | head -c 300)"

echo "== 3. the screens; people"
h=$(curl -sk --noproxy '*' -D - -o "$W/index.html" $PUB/api/heain-console/ui/)
echo "$h" | grep -qi "^content-security-policy: default-src 'none'; script-src 'self'" && echo "$h" | grep -qi "^x-frame-options: DENY" && grep -q '<script src="app.js" defer>' "$W/index.html" \
  && [ "$(curl -sk --noproxy '*' -o /dev/null -w '%{http_code}' $PUB/api/heain-console/ui/app.js)" = 200 ] && ok "the screens load before sign-in, with the console's CSP and X-Frame-Options (passed by the gateway)" || bad "ui: $h"
read -r _ BOOT < "$W/state-g1/bootstrap-admin.txt"
r=$(login adm root "$BOOT" '"new_password":"Green-Lantern-77-q"'); [ -n "$(csrf adm)" ] && ok "root (the gateway's bootstrap admin) signed in with a new password" || bad "root: $r"
for u in anna boss pim; do pub adm -X POST -H "X-CSRF-Token: $(csrf adm)" -H 'Content-Type: application/json' -d "{\"id\":\"$u\",\"name\":\"$u\",\"roles\":[\"console\"],\"password\":\"$PW\"}" $PUB/admin/users >/dev/null; done
person anna $PW totp; person boss $PW totp; person pim $PW
[ "$(pub anna $PUB/auth/me | j "d['amr']")$(pub boss $PUB/auth/me | j "d['amr']")$(pub pim $PUB/auth/me | j "d['amr']")" = "pwd+totppwd+totppwd" ] && ok "anna and boss signed in with password + TOTP, pim with a password only" || bad "people"

echo "== 4. anna in core, through the console"
r=$(cget anna whoami); [ "$(echo "$r" | j "(d['node'], d['identity'], sorted(d['roles']), d['via_console'])")" = "('G', 'user:anna', ['operator', 'policy-admin', 'viewer'], 'heain-console.c1')" ] \
  && ok "whoami: user:anna on G, operator + policy-admin, relayed by heain-console.c1" || bad "whoami: $r"
[ "$(csend anna PUT config/system/apps.heartbeat_interval '{"value":"9s"}' | j "d['status']")" = applied ] && [ "$(f $URL apps.heartbeat_interval "['value']")" = 9s ] && ok "anna set a 2a key (applied at once)" || bad "2a"
[ "$(pub anna -o /dev/null -w '%{http_code}' -X PUT -H 'Content-Type: application/json' -d '{"value":"8s"}' $CP/config/system/apps.heartbeat_interval)" = 403 ] && ok "without the CSRF token the gateway refuses the change" || bad "csrf"
A=$(csend anna POST config/policy/audit.readers '{"value":["heain-report","heain-audit"],"reason":"add the auditor"}' | j "d['action_id']")
[ -n "$A" ] && [ "$(cget anna policy/pending | j "[a['ProposedBy'] for a in d['actions'] if a['ID']=='$A'][0]")" = user:anna ] && ok "anna proposed a 2b key: P5 $A, proposed by user:anna" || bad "2b: $A"
[ "$(csend anna POST policy/$A/approve '{}' | j "d['error']['code']")" != "" ] && ok "anna cannot approve (not an Approver; never her own)" || bad "anna approve"

echo "== 5. boss approves; refusals"
r=$(csend boss POST policy/$A/approve '{}'); [ "$(echo "$r" | j "d['approver']")" = user:boss ] && [ "$(f $URL audit.readers "['value']")" = "['heain-report', 'heain-audit']" ] && ok "boss (an Approver) approved it in the console; applied" || bad "boss: $r"
[ "$(csend boss PUT config/system/apps.heartbeat_interval '{"value":"5s"}' | j "d['error']['code']")" != "" ] && [ "$(f $URL apps.heartbeat_interval "['value']")" = 9s ] && ok "boss holds no admin role: his change is refused" || bad "boss change"
r=$(cget pim whoami); [ "$(echo "$r" | j "(d['error']['code'], 'sign-in method' in d['error']['message'])")" = "('user_assertion_invalid', True)" ] && ok "pim signed in without TOTP: core refuses the admin plane (MFA)" || bad "pim: $r"
[ "$(as fake-anna $URL/v1/admin/whoami | j "(d['identity'], len(d['roles']))")" = "('user:anna', 0)" ] && [ "$(code fake-anna -X PUT -d '{"value":"1s"}' $URL/v1/admin/config/system/apps.heartbeat_interval)" = 403 ] \
  && ok "a client certificate with CN user:anna holds none of anna's roles" || bad "cert user:anna: $(as fake-anna $URL/v1/admin/whoami)"
[ "$(cl ops.c1 -o /dev/null -w '%{http_code}' https://127.0.0.1:19590/v1/core/whoami)" = 401 ] && ok "an app calling the console directly is refused (only people)" || bad "app -> console"
[ "$(cl ops.c1 -o /dev/null -w '%{http_code}' $URL/v1/app/admin/admin/whoami)" = 403 ] && ok "an app outside console.apps cannot use core's relay" || bad "app -> relay"

echo "== 6. remote admin; a report"
for k in $(seq 1 30); do [ "$(cget anna nodes/Z/admin/whoami | j "','.join(sorted(d['roles']))")" = "operator,policy-admin,viewer" ] && break; sleep 2; done
r=$(cget anna nodes/Z/admin/whoami); [ "$(echo "$r" | j "(d['node'], d['identity'], d['forwarded_by'])")" = "('Z', 'user:anna', 'G')" ] && ok "anna on Z through the console and G (roles inherited)" || bad "remote: $r"
csend anna PUT nodes/Z/admin/config/system/apps.heartbeat_interval '{"value":"7s"}' >/dev/null
[ "$(f $ZURL apps.heartbeat_interval "['value']")$(f $URL apps.heartbeat_interval "['value']")" = 7s9s ] && ok "her change through G landed on Z only" || bad "remote change"
cl ops.c1 -X PUT -d '{"title":"Activity","sources":[{"name":"a","app":"core.audit","dataset":"events","group_by":["action"]}],"min_group":2,"viewers":{"roles":["console"]}}' https://127.0.0.1:19580/v1/reports/activity > "$W/rep.json"
approve "$(j "d['action_id']" < "$W/rep.json")" >/dev/null; sleep 3
RUN=$(cl ops.c1 -X POST -d "{\"from\":\"$(date -u -d yesterday +%Y-%m-%d)T00:00:00Z\",\"to\":\"$(date -u -d tomorrow +%Y-%m-%d)T00:00:00Z\"}" https://127.0.0.1:19580/v1/reports/activity/runs | j "d['id']")
for k in $(seq 1 20); do [ "$(pub anna $PUB/api/heain-report/v1/dashboards/activity | j "d['run']['state']")" = done ] && break; sleep 1; done
[ "$(pub anna $PUB/api/heain-report/v1/dashboards/activity | j "(d['run']['id']=='$RUN', len(d['snapshot']['sources'][0]['groups'])>0)")" = "(True, True)" ] && ok "anna reads a heain-report dashboard through the gateway (the Reports screen)" || bad "report: $(cat "$W/rep.json") / $RUN / $(pub anna $PUB/api/heain-report/v1/dashboards/activity | head -c 300)"

echo "== 7. core's audit"
a=$(audit)
[ "$(echo "$a" | j "len([x for x in d['records'] if x['event']['Action']=='admin.console' and x['event']['Result']=='relayed' and x['event']['Actor']=='user:anna' and x['event']['Detail'].get('assertion_id')])>=5")" = True ] \
  && ok "every relay is audited as user:anna with its assertion id and gateway" || bad "relay audit"
[ "$(echo "$a" | j "len([x for x in d['records'] if x['event']['Action']=='admin.console' and x['event']['Result']=='refused'])>=1")" = True ] && ok "the refused relay (pim, MFA) is audited" || bad "refused audit"
[ "$(echo "$a" | j "sorted(set(x['event']['Actor'] for x in d['records'] if x['event']['Category'].startswith('CONFIG') and 'heartbeat_interval' in json.dumps(x['event']['Detail'])))")" = "['user:anna']" ] \
  && ok "the config change is recorded as user:anna" || bad "change actor: $(echo "$a" | j "sorted(set(x['event']['Actor'] for x in d['records'] if 'heartbeat_interval' in json.dumps(x['event']['Detail'])))")"
[ "$(as admin $URL/v1/admin/audit/verify | j "d['ok']")" = True ] && ok "audit chain verifies" || bad "verify"

echo "== cleanup"
$H stop-all >/dev/null 2>&1
for f in db1 g1 c1 r1; do [ -f "$P/$f.pid" ] && kill "$(cat "$P/$f.pid")" 2>/dev/null; done
echo
echo "RESULT: $PASS passed, $FAIL failed"
echo "(logs: $W)"
