# Codex handoff — Branchcodex two workflows

## Objetivo da missão

Deixar verdes localmente, antes de qualquer push, os workflows relacionados a:

- `.github/workflows/interop-hardening.yml`
- workflow `heavy-test`
- foco atual: `components / production-native-claim`
- cenário crítico atual: `native_real_daemon_two_claims_survive_original_store_reopen_v23`

O usuário pediu explicitamente para **não mandar para GitHub antes de rodar no ambiente local até ficar verde**. Também pediu para **não aumentar timeout/tempo como solução**. O objetivo técnico é corrigir o protocolo para concluir mais rápido e corretamente, não mascarar falhas com espera maior.

## Preferências e regras do usuário

- Responder em português.
- Atualizar com detalhes a cada ~30 segundos quando testes longos estiverem rodando.
- Não parar só porque um teste demora; continuar até entregar verde.
- Se um teste falhar, **não rodar de novo às cegas**.
- Antes de novo teste após falha, fazer leitura estática profunda do fluxo inteiro do erro até o verde esperado.
- O usuário quer acompanhar a fase: informar se está no início, meio, rev17/18, rev32, final claims etc.
- Evitar regressão: não quebrar o que já passou verde.
- Só depois de local verde deve preparar push em branch separada.

## Regras globais do ambiente

Arquivo `$HOME/AGENTS.md` diz:

- Não parar missão multi sessão até completar, salvo blocker real.
- Editar só arquivos relacionados ao pedido.
- Rodar testes/checks no final.
- Commits/publicações devem usar somente:
  `Soren Planck <sorenplanck@tutamail.com>`
- Não adicionar coautores.

## Repositório e branch atual

Repositório local:

```bash
$REPO
```

Antes de qualquer push/commit, verificar:

```bash
git status --short
git branch --show-current
git log -1 --format='%H %an <%ae> %cn <%ce> %s'
```

## Problema original observado

O teste falhava perto do fim em `native_real_daemon_two_claims_survive_original_store_reopen_v23` com:

```text
real daemon exited unsuccessfully before final claims
```

O fixture anterior mostrou que o protocolo não estava quebrando no início; ele chegava perto do fim. O gargalo original era:

- `bob/downstream` estava em `rev19 TemplatesCommitted`
- `alice/downstream` estava em `rev18 TemplatesCommitted`
- havia envelope `kind24` (`0x18`) correto na fila central de Bob para Alice, mas ele não era entregue antes da saída do daemon
- `route_id`, `session_id`, `recipient_id` e escopo de entrega batiam
- a causa era o processo sair antes de drenar mais uma rodada de relay após terminal

## Correções já aplicadas

### 1. `crates/relay/src/production.rs`

Adicionado método read-only:

```rust
pub fn pending_canonical_envelopes_for_session(
    &self,
    session_id: &Digest32,
) -> Result<Vec<Vec<u8>>, ProductionRelayError>
```

Uso: permitir que Stage12 veja envelopes pendentes por sessão sem mutar estado de entrega.

### 2. `crates/dom-interopd/src/production_relay_stage12.rs`

Principais alterações já aplicadas:

- Campo novo:

```rust
xmr_graph_signing_admission_deferred_v23: [bool; 2],
```

- Inicialização `[false, false]`.
- `bootstrap_ready_v16()` mudou `GraphLifecycleV23::Signing(_) => false` para não declarar pronto só porque signing owner existe.
- Helper novo:

```rust
fn pending_xmr_graph_commit_relay_envelope_v23(
    &self,
    session_id: [u8; 32],
) -> Result<bool, crate::production_contracts::ProductionBootstrapRuntimeErrorV16>
```

- `step_xmr_recovery_signing_v23` agora adia criação de signing quando existe envelope `0x18` pendente no relay, e faz um defer adicional.
- Isso evitou a admissão prematura de signing antes de o commit gráfico chegar ao peer.

### 3. `crates/dom-interopd/src/production_composite_loop.rs`

Adicionado método:

```rust
pub(crate) fn step_terminal_relay_drain_v24(
    &mut self,
    leg: LegIdV1,
) -> Result<bool, ProductionCompositeLoopErrorV1>
```

Ele chama `step_leg` e tolera os mesmos erros retry/awaiting usados pelo runtime normal:

- final claim awaiting
- template construction awaiting
- peer temporariamente indisponível

### 4. `crates/dom-interopd/src/production_run_universal.rs`

Adicionado macro de drain curto após terminal:

```rust
drain_terminal_relay_v24!();
```

Ele roda até 16 rodadas curtas de relay normal depois de `Terminal`, parando após 2 rodadas sem tráfego. O objetivo é drenar envelopes autenticados já produzidos na rodada terminal, sem aumentar timeout global.

### 5. `crates/dom-interopd/src/production_noise_relay.rs`

Correção importante encontrada por leitura durante o último run:

Antes:

```rust
if self.graph_v22.is_some() && self.exchange_recovery_scopes_v23(&mut transport)? {
```

Depois:

```rust
if self.recovery_v23.is_some() && self.exchange_recovery_scopes_v23(&mut transport)? {
```

Motivo: no run anterior, as sessões principais chegaram em rev32, mas havia 4 envelopes auxiliares `kind13` (`0x0d`, `SigNonceReveal`) pendentes em Alice. O `graph_v22` já não estava mais presente, então os recovery child scopes não eram trocados, embora `recovery_v23` ainda existisse e precisasse drenar.

### 6. `crates/dom-interopd/src/production_noise_recovery_v23.rs`

Relaxado o requisito em `with_xmr_recovery_v23`: não exigir `graph_v22.is_some()` para anexar recovery children. Recovery scopes são autoridade própria derivada dos owners auxiliares retidos, e precisam continuar servíveis depois do graph offer deixar de ser ativo.

## Checks já rodados e verdes

Após as correções acima:

```bash
cargo check -p dom-interopd --no-default-features --features production
```

Passou.

Build release também passou duas vezes. Último hash BLAKE2b-256 usado no teste atual:

```text
70913b2b9ff7dc7ee12e044efa4bf0b40c3e8c9070a7dbaa3911e097901c1fbb
```

## Comando padrão para rodar o cenário real

Sempre usar BLAKE2b-256, não SHA-256.

```bash
source /tmp/branchcodex-local-xmr-env.vars
export DOM_INTEROP_REAL_BINARY_V23=$REPO/target/release/dom-interopd
export DOM_INTEROP_REAL_BINARY_BLAKE2B256_V23=<hash_blake2b_256>
export CARGO_BUILD_JOBS=2
export RUST_TEST_THREADS=1
export RUST_BACKTRACE=1
python3 scripts/run_native_daemon_scenario_v23.py \
  --evidence-dir /tmp/dom-xmr-real-evidence-claims-reopen-<label> \
  --scenario native_real_daemon_two_claims_survive_original_store_reopen_v23
```

Calcular hash:

```bash
python3 - <<'PY'
import hashlib
p='target/release/dom-interopd'
h=hashlib.blake2b(digest_size=32)
with open(p,'rb') as f:
    for chunk in iter(lambda:f.read(1024*1024), b''):
        h.update(chunk)
print(h.hexdigest())
PY
```

Depois de build release:

```bash
chmod 755 target/release/dom-interopd
```

O runner recusa binário com permissões inadequadas.

## Teste atual em andamento no momento deste handoff

Comando em execução:

```bash
python3 scripts/run_native_daemon_scenario_v23.py \
  --evidence-dir /tmp/dom-xmr-real-evidence-claims-reopen-recovery-scope-gate \
  --scenario native_real_daemon_two_claims_survive_original_store_reopen_v23
```

Hash do binário:

```text
70913b2b9ff7dc7ee12e044efa4bf0b40c3e8c9070a7dbaa3911e097901c1fbb
```

Session id do comando no Codex no momento da escrita: `88265`.

Último estado reportado antes deste documento:

- `cold_swap_preparation` concluída em ~172s.
- `export_and_launch` concluída em ~12.5s.
- Daemon normal rodando.
- Aos ~240-300s estava aguardando duas final claims.
- Leitura não invasiva do fixture ativo:

Fixture ativo provável:

```text
$HOME/.dx-v23/dx-38sp644z/.tmpXToTCS
```

Estado lido aos ~240s:

- `alice`:
  - `cancelled-contracts-1`: rev23
  - `cancelled-contracts-3`: rev23
  - `daemon-downstream_contracts d1...`: rev5
  - `daemon-upstream_contracts a1...`: rev5
  - relay pending: 1 envelope, sessão `af3523241986...`, seq7, kind9
- `bob`:
  - `cancelled-contracts-0`: rev23
  - `cancelled-contracts-2`: rev23
  - `daemon-downstream_contracts d1...`: rev5
  - `daemon-upstream_contracts a1...`: rev5
  - relay pending: 0

Interpretação: o run atual ainda estava antes do antigo ponto rev17/18; sem regressão observada. Cancelled auxiliaries já completaram rev23; main sessions estavam em rev5.

## Como ler progresso ativo sem parar o teste

Localizar fixture ativo:

```bash
python3 - <<'PY'
from pathlib import Path
import time
base=Path('$HOME/.dx-v23')
cands=sorted([p for p in base.iterdir() if p.is_dir()], key=lambda p:p.stat().st_mtime, reverse=True)[:5]
for p in cands:
    print(p, time.strftime('%H:%M:%S', time.localtime(p.stat().st_mtime)))
    for sub in p.iterdir():
        if sub.is_dir() and sub.name.startswith('.tmp'):
            print(' tmp', sub)
PY
```

Ler revisões e filas:

```bash
python3 - <<'PY'
import sqlite3
from pathlib import Path
root=Path('$HOME/.dx-v23/<dx-dir>/<tmp-dir>')
for who in ['alice','bob']:
    print('\n',who)
    actor=root/who
    for d in sorted(actor.glob('*contracts*')):
        rec=d/'session-records'
        if rec.exists():
            bysess={}
            for f in rec.glob('*.session'):
                parts=f.name.split('-')
                sid='-'.join(parts[:-1])
                try: rev=int(parts[-1].split('.')[0],16)
                except: rev=-1
                bysess.setdefault(sid,[]).append(rev)
            print(d.name, [(k[:12], max(v), len(v)) for k,v in bysess.items()])
    db=actor/'daemon-relay_queue'/'relay-v1.sqlite3'
    if db.exists():
        con=sqlite3.connect(db)
        n=con.execute('select count(*) from relay_envelopes').fetchone()[0]
        print('pending',n)
        for ord,sess,seq,blob in con.execute('select ordinal,session_id,sequence_be,canonical_bytes from relay_envelopes order by ordinal'):
            i=blob.find(b'DSC1')
            kind=int.from_bytes(blob[i+6:i+8],'little') if i>=0 else None
            print(' ',ord,sess.hex()[:12],int.from_bytes(seq,'big'),kind)
        con.close()
PY
```

Checar processos vivos:

```bash
ps -eo pid,ppid,stat,etime,cmd | rg 'run_native_daemon|cargo test|dom_interopd|/proc/self/fd/3'
```

## Leitura estática obrigatória se falhar de novo

Se o teste falhar, não rerodar imediatamente. Fazer:

1. Ler `test.log`, `result.json`, `campaign.json` no evidence dir.
2. Extrair ou localizar `failed-fixture-path.txt`.
3. Ler stores do fixture:
   - `daemon-upstream_contracts/session-records`
   - `daemon-downstream_contracts/session-records`
   - `cancelled-contracts-*`
   - `daemon-relay_queue/relay-v1.sqlite3`
   - inbox/sender dirs se necessário
4. Identificar:
   - maior revisão de cada sessão (`a1...`, `d1...`, auxiliaries)
   - envelopes pendentes por actor, session, seq, kind
   - se o envelope pendente tem escopo em `relay_delivery_scopes_v3`
   - cursor correspondente em `relay_delivery_state`
5. Só depois ler o fluxo de código responsável pelo próximo passo esperado.

Arquivos-chave para leitura:

- `crates/dom-interopd/src/production_composite_loop.rs`
- `crates/dom-interopd/src/production_noise_relay.rs`
- `crates/dom-interopd/src/production_noise_recovery_v23.rs`
- `crates/dom-interopd/src/production_composite_noise_recovery_v23.rs`
- `crates/dom-interopd/src/production_relay_stage12.rs`
- `crates/dom-interopd/src/production_relay_xmr_signing_v23.rs`
- `crates/dom-interopd/src/production_xmr_graph_commit_runtime_v23.rs`
- `crates/dom-scriptless-store/src/runtime/linux/session_store.rs`
- `crates/relay/src/production.rs`

## Interpretação dos message kinds vistos

- `kind24` = DSC1 `0x18`, graph commit. Foi o gargalo antigo: envelope correto pendente no relay, não drenado antes de terminal.
- `kind13` = DSC1 `0x0d`, `SigNonceReveal`. Foi o segundo gargalo: recovery child scopes não eram trocados após `graph_v22` sumir.
- `kind9` = DSC1 `0x09`, parte anterior do signing/cancelled auxiliary. No run atual aos ~240s havia 1 `kind9` pendente em Alice, mas as cancelled sessions estavam rev23 dos dois lados; observar antes de concluir se é gargalo.

## Evidences úteis anteriores

Último run antes da correção do recovery gate:

```text
/tmp/dom-xmr-real-evidence-claims-reopen-terminal-relay-drain
```

Fixture ativo lido naquele run:

```text
$HOME/.dx-v23/dx-8wkcb0jp/.tmpZu72S7
```

Ele mostrou progresso até rev32 nos principais, com 4 `kind13` pendentes em Alice.

Run anterior ao drain terminal:

```text
/tmp/dom-xmr-real-evidence-claims-reopen-after-relay-pending-gate
```

Fixture extraído/lido:

```text
/tmp/dom-xmr-real-fixture-after-relay-pending-gate/.tmpUqH1Kr
```

Ele mostrou o gargalo `kind24` em Bob para Alice.

## O que fazer quando o teste ficar verde

1. Rodar checks necessários dos workflows locais:
   - cenário atual production-native-claim
   - depois workflow/session e `heavy-test`, conforme escopo original
2. Não otimizar tempo antes de verde estável. O usuário pediu: primeiro verde, depois otimização de tempo.
3. Depois de verde, avaliar tempo real de transação e procurar reduzir sem quebrar teste.
4. Preparar branch separada e push só após teste local verde.
5. Antes de commit/push, configurar/verificar author/committer:

```bash
git config user.name 'Soren Planck'
git config user.email 'sorenplanck@tutamail.com'
```

E usar env se necessário:

```bash
GIT_AUTHOR_NAME='Soren Planck' \
GIT_AUTHOR_EMAIL='sorenplanck@tutamail.com' \
GIT_COMMITTER_NAME='Soren Planck' \
GIT_COMMITTER_EMAIL='sorenplanck@tutamail.com' \
git commit ...
```

## Observação sobre sandbox

O sandbox comum frequentemente falha com:

```text
bwrap: Can't mkdir $HOME/.codex/visualizations/.../.git: Read-only file system
```

Quando isso acontecer em comandos necessários, rodar com escalated. Isso tem sido necessário até para leituras simples.

## Atualização pós-compactação — 2026-09-16 18:5x America/Sao_Paulo

O documento foi confirmado e atualizado após compactação de contexto.

### Estado do teste ativo

Session id do Codex: `88265`.

Último output direto do runner:

```text
native real daemon: awaiting two final economic claims after 450s
native real daemon: awaiting two final economic claims after 480s
native real daemon: awaiting two final economic claims after 510s
native real daemon: awaiting two final economic claims after 540s
native real daemon: awaiting two final economic claims after 570s
```

Fixture ativo lido sem modificar estado:

```text
$HOME/.dx-v23/dx-38sp644z/.tmpXToTCS
```

Estado por ator:

```text
alice:
  cancelled-contracts-1: session 650498a4127d..., max rev23, 18 records
  cancelled-contracts-3: session af3523241986..., max rev23, 18 records
  daemon-downstream_contracts: session d1d1d1d1d1d1..., max rev24, 19 records
  daemon-upstream_contracts:
    session a1a1a1a1a1a1..., max rev25, 20 records
    session 6e708cc6953c..., max rev0, 1 record
    session 0e172c94b40f..., max rev0, 1 record
  relay pending: 1 envelope
    ordinal 32, session af3523241986..., seq 7, DSC1 kind 9

bob:
  cancelled-contracts-0: session 650498a4127d..., max rev23, 18 records
  cancelled-contracts-2: session af3523241986..., max rev23, 18 records
  daemon-downstream_contracts: session d1d1d1d1d1d1..., max rev25, 20 records
  daemon-upstream_contracts:
    session a1a1a1a1a1a1..., max rev32, 21 records
    session 6e708cc6953c..., max rev1, 2 records
    session 0e172c94b40f..., max rev0, 1 record
  relay pending: 0 envelopes
```

### Interpretação atual

Não há regressão para o começo do protocolo. O teste já passou do ponto antigo em que travava nos rev17/18/19 e também passou do erro anterior de `kind13` auxiliar pendente.

O gargalo atual está no final: Alice ainda tem um envelope `kind9` pendente na sessão auxiliar `af3523241986...`, enquanto Bob não tem fila pendente. Se o run falhar, a próxima leitura estática deve começar pelo fluxo de entrega/consumo de `kind9` em sessão auxiliar cancelada/recovery e seguir até a produção das duas final economic claims.

### Regra antes de qualquer novo rerun

Se este teste falhar, não iniciar nova compilação nem novo run imediatamente. Primeiro:

1. Ler o log final do evidence dir.
2. Ler o estado final do fixture ativo.
3. Mapear o significado do `DSC1 kind 9` no código.
4. Seguir todos os callers do produtor e consumidor desse kind na sessão auxiliar `af3523241986...`.
5. Verificar se o escopo relay permite Bob consumir/receber ou se o envelope ficou preso por owner/session mismatch.
6. Só depois alterar código e rodar `cargo check`/build/test.

## Atualização — falha pós-run recovery-scope-gate

O teste `native_real_daemon_two_claims_survive_original_store_reopen_v23` falhou perto do fim, não no início.

Evidence dir:

```text
/tmp/dom-xmr-real-evidence-claims-reopen-recovery-scope-gate/native_real_daemon_two_claims_survive_original_store_reopen_v23
```

Resultado:

```text
DOM_NATIVE_EXIT_DIAGNOSTIC_V24 code=dom_actuator
phase=launch_to_two_claims_and_natural_exit
elapsed_ms=642855
Error: "real daemon exited unsuccessfully before final claims"
```

O fixture foi limpo do diretório vivo, mas ficou arquivado em:

```text
synthetic-fixtures.tar.gz
```

Ele foi extraído para diagnóstico em:

```text
/tmp/codex-fixture-recovery-scope-gate/.tmpXToTCS
```

### Estado final real do fixture arquivado

Sessões principais:

```text
alice daemon-downstream d1... rev24
bob   daemon-downstream d1... rev25
alice daemon-upstream   a1... rev25
bob   daemon-upstream   a1... rev32
```

Sessões canceladas/auxiliares:

```text
alice cancelled-contracts-1 650498... rev23
bob   cancelled-contracts-0 650498... rev23
alice cancelled-contracts-3 af3523... rev23
bob   cancelled-contracts-2 af3523... rev23
```

Filas finais no archive:

```text
alice daemon-relay_queue:
  ordinal 32
  DSC1 kind 0x09 (BpRound2)
  session af35232419860d9c...
  sender 75dc76ec256e9f6b...
  sequence 7

bob daemon-relay_queue:
  ordinal 72
  DSC1 kind 0x18 (XmrGraphCommitV23)
  session d1d1d1d1d1d1...
  sender 3983cc90c3b8738b...
  sequence 8
```

### Diagnóstico estático novo

`kind 0x09` não é final claim; é `BpRound2`, definido em `dom-scriptless-transport::MessageTypeV1`.

O drain terminal anterior chamava `step_leg`, que executa:

1. `step_local_bootstrap_v23`
2. `step_exchange_and_poll_v23`

Se o bootstrap local retornasse apenas um estado retry/awaiting (`AwaitingFinalClaimObservationV16`, `AwaitingTemplateConstructionV17`, `AwaitingBootstrapRefundHandoffV18` ou `AwaitingNativeXmrRefundTransportV23`), o terminal drain convertia em `Ok(false)` e parava sem executar a troca Noise. Isso deixava tráfego já retido nas filas após o terminal.

Correção aplicada em `crates/dom-interopd/src/production_composite_loop.rs`:

- `step_terminal_relay_drain_v24` agora valida o escopo, tenta bootstrap local, mas se ele estiver apenas em awaiting permitido, continua para exchange/poll.
- O caminho terminal usa `step_exchange_and_poll_terminal_relay_v24`.
- O poll terminal também tolera awaiting no bootstrap pós-exchange e continua a drenar inboxes já autenticadas.
- Erros reais continuam propagando; só os awaiting explícitos são tratados como retry/continuação.

Check após a correção:

```text
cargo check -p dom-interopd --no-default-features --features production
```

Passou.

## Atualização recente — continuação terminal v24

Depois do fix do terminal relay drain, o cenário avançou além do ponto anterior: ambos os atores chegaram com as sessões principais em rev32, e os pendings `0x18`/`0x09` que travavam antes não ficaram presos. O teste, porém, continuou aguardando as claims finais por mais de 20 minutos.

Diagnóstico estático: o loop universal chama os pumps F7/native claim no topo do loop, mas quando `run_production_composite_runtime_bounded_v1` retorna `Terminal`, o código drenava refund/relay e fazia `break`. Assim, depois que a rota chegava em terminal, não havia nova volta do loop para materializar `SettlementActionV1::Claim` / `BroadcastClaim` e expor/adaptar a final claim.

Correção aplicada em `crates/dom-interopd/src/production_run_universal.rs`: o ramo `Terminal` agora drena terminal refund/relay e continua por até 16 rodadas terminais antes de sair. Isso é um limite pequeno e explícito; não aumenta timeout e permite que os pumps do topo do loop rodem após o estado terminal. `cargo fmt` e `cargo check -p dom-interopd --no-default-features --features production` passaram.

## Atualização de diagnóstico — medir fase por DSC1, não só route snapshot

Na execução com hash `6c0c23fe9102fe05031c699cd33bc7a1100fe6ca0d55225bf8109345e6d6443c`, o teste entrou em `wait_claims` e foi interrompido manualmente após ~360s porque `daemon-route_store` permanecia em `revision=1`. Leitura posterior mostrou que esse dado isolado não prova regressão: enquanto a route snapshot pode ficar inicial, os stores de contrato continuam a cerimônia DSC1.

Fixture vivo dessa execução: `$HOME/.dx-v23/dx-cjp3jxm0/.tmpwG1ciz`. O pending observado era em `bob/daemon-relay_queue`, sessão `FEA323AB...`, sequência `4`, `DSC1 kind 0x06`. Essa sessão mapeou para `cancelled-contracts-2/3`, ou seja, o caminho original/cancelled, não os stores principais.

Leitura do Store: `0x06` é `OperationalBpCommonReveal`, fase `BpCommonEstablished`. A sequência operacional esperada é `0x05`, `0x06`, `0x07`, `0x08`, `0x09`, `0x0a`, depois template/signing/final. Portanto, para acompanhar progresso use:

1. maior revision/arquivo em `session-records` por session id;
2. maior DSC1 kind em `session-messages`/relay pending;
3. pending relay por actor;
4. route snapshot apenas quando o route runtime começar a materializar ações econômicas.

Não concluir regressão só porque `route_store` está em revision 1 durante BP/DSC1.

## Atualização — gate de `0x18` antes dos pumps F7/funding

Falha da rodada `terminal-continuation-v24-rerun2`: `DOM_NATIVE_EXIT_DIAGNOSTIC_V24 code=dom_actuator`, fase normal incompleta em ~583s. Fixture arquivado em `/tmp/dom-xmr-real-evidence-claims-reopen-terminal-continuation-v24-rerun2/.../synthetic-fixtures.tar.gz`. Estado final extraído:

- Alice: `daemon-downstream_contracts d1...` rev18; `daemon-upstream_contracts a1...` rev19; auxiliares `5b91c130`/`8ce44c98` rev0; relay pending 0.
- Bob: `daemon-downstream_contracts d1...` rev19; `daemon-upstream_contracts a1...` rev20; auxiliares rev1; relay pending 1: session `d1...`, seq8, DSC1 kind `0x18`.

Diagnóstico estático: os pumps do topo do loop (`step_f7_funding_v20`, `step_native_xmr_f7_claim_v23`) rodam antes do próximo exchange normal. Bob podia entrar em funding/claim/recovery enquanto ainda retinha localmente o `0x18` final de graph agreement que Alice precisava aceitar para sair de rev18. Correção aplicada em `production_relay_stage12.rs`: antes de ativar funding/recovery ou claim nativa XMR, se o relay local ainda retém `0x18` para a sessão do graph setup, o pump retorna `Ok(())` e deixa o composite exchange drenar. `cargo check -p dom-interopd --no-default-features --features production` passou.


## Estado atual de continuidade

Último ponto de trabalho antes desta atualização:

- Um build release de `dom-interopd` estava rodando após a correção do gate de envelope `0x18`.
- O último cenário completo antes da correção passou da fase crítica `17/18` e falhou depois, já perto de final claims, com `dom_actuator`.
- A leitura estática indicou que Bob ainda tinha um envelope DSC1 `0x18` local retido no relay para a sessão downstream enquanto os pumps de funding/claim rodavam antes da troca composta.
- Correção aplicada: `step_native_xmr_f7_claim_v23` e `step_f7_funding_v20` retornam cedo quando existe envelope XMR graph commit `0x18` pendente no relay local da sessão.
- Intenção: impedir ativação prematura de recovery/custody/funding/claim antes de o peer receber o acordo gráfico.

Regra para continuação:

1. Se o build release terminar verde, calcular o hash BLAKE2b do binário e rodar o cenário `native_real_daemon_two_claims_survive_original_store_reopen_v23` localmente com evidence dir novo.
2. Durante o teste, acompanhar as revisões das sessões e a fila `daemon-relay_queue/relay-v1.sqlite3`; reportar se passou de `17/18`.
3. Se falhar, não rerodar imediatamente. Ler o fluxo completo a partir do erro, incluindo chamadas seguintes até o verde esperado, e só então corrigir.
4. Não aumentar timeout como solução. O protocolo deve concluir em minutos, com drenagem correta de relay e sem espera artificial.


## Último build local conhecido

- Comando: `cargo build --release -p dom-interopd --no-default-features --features production`
- Status: verde em `release` profile.
- Hash BLAKE2b-256 do binário `target/release/dom-interopd`:
  `2124aa8223320dfb0b5b97c36b9d4875c98a0bdf5261b2000dab1ba123eb4e77`
- Próximo teste local deve usar esse hash em `DOM_INTEROP_REAL_BINARY_BLAKE2B256_V23`.

## Atualização — 2026-09-18: deadlock de criação em `bootstrap_ready_v16` (corrigido)

Origem: documento de auditoria estática do usuário (`dom-v25-static-full.zip`,
SHA-256 `ce684c6eb48cffe9239c094568e91fa29da2e7b87538e77c4075b0480d8b1e97`),
conclusão 1 (itens A1–A5). Os SHA-256 de todos os arquivos citados foram
conferidos contra o working tree e batem: as citações valem para o código vivo.

### Ciclo confirmado por leitura

1. `production_xmr_graph_setup_v22.rs:100` — setup nasce com `claim_context: None`.
2. `install_xmr_claim_context_v23` tem **um único caller**:
   `production_run_universal.rs:975`, executado **depois** do loop de ativação
   (linhas 781–815).
3. `production_relay_stage12.rs:305` — a conclusão do signing retorna cedo sem
   claim context; `bind_xmr_graph_custody_role_v23`
   (`production_xmr_graph_role_v23.rs:16`) exige o contexto com `.ok_or(Refused)`.
   Logo `Produced` é inalcançável antes da ativação.
4. `bootstrap_ready_v16` (stage12:755) tratava `Signing(_) => false`.
5. `production_composite_loop.rs:875-907` só sai `Ready` com
   `bootstrap_ready_v16()` verdadeiro.

Resultado: `Signing` → precisa de claim context → precisa de `Ready` → precisa de
`Produced` → deadlock. O único escape é `resume_ready_graph_for_activation_v23`,
que só existe na reabertura, não na criação.

Isso explica a falha de 16/09 (`code=composite_loop stage=local_bootstrap
cause=expired` após 62 min): o loop de ativação gira até o lease expirar. Também
explica a rodada de 17/09 chegar a rev37 com filas limpas sem concluir: as
revisões de sessão avançam dentro de `step_activation_leg`, enquanto a ativação
nunca completa. O deadlock foi introduzido pela própria correção de 16/09
(`Signing => false`), feita para não declarar pronto com `0x18` pendente.

`RecoveryVerifiedV25`, citado no documento, de fato não existe no enum — e não é
necessário: o desbloqueio não exige estado novo.

### Correção aplicada

`crates/dom-interopd/src/production_relay_stage12.rs`, `bootstrap_ready_v16`:
`Signing(_)` passa a contar como pronto-para-ativação **somente quando não há
envelope `0x18` pendente** no relay da sessão
(`pending_xmr_graph_commit_relay_envelope_v23`). Preserva a intenção da correção
de 16/09 (esperar a troca bilateral do graph commit) sem exigir `Produced`, que é
estruturalmente impossível antes da ativação. Erro na consulta → `false`
(conservador). Os pumps de funding/claim mantêm seus próprios gates de `0x18`.

`cargo fmt` e `cargo check -p dom-interopd --no-default-features --features
production` passaram. **Ainda não rodado o cenário real.**

### Conclusão 3 do documento (fencing H1–H5/C5) — NÃO implementada, com motivo

O mecanismo existe: dois contadores independentes — lease de rota
(`route-executor/src/store.rs:670-731`) e lease DOM (`dom-actuator/src/store.rs:1865`,
`renew_lease:1942` nunca muda epoch) — comparados por **igualdade numérica** em
três pontos, não só no citado: `production_child_dom.rs:1958` (materialize),
`:2400` (`validate_static`, usado por dispatch e observação) e `:2439` (retained,
esse com `>`). O child XMR não faz essa comparação cruzada.

Mas **não é alcançável neste cenário**: ambas as leases usam o mesmo
`pins.process_owner_id` e o cenário configura `lease_duration_ms = 120_000` e
`actuator_lease_ms = 120_000` (iguais). Com mesma duração e mesmo owner, as duas
expiram ou sobrevivem juntas e os epochs andam travados. A divergência exige
`min(duração) < T <= max(duração)`, impossível com durações iguais.

Continua sendo fragilidade latente: `ProductionRuntimeBoundsV1::validate`
(`production_config.rs:764-785`) **permite** durações diferentes, e nesse caso a
reabertura quebraria em `Conflict` permanente e silencioso. Corrigir exige
escolha de desenho — (a) vincular explicitamente o epoch de rota ao child DOM
depois da aquisição do supervisor (a composição em `production_run_universal.rs:1117`
acontece antes da aquisição em `:1342`, então o child não conhece o epoch de rota
no momento da composição), ou (b) exigir no validador que as durações coincidam.
Não implementado sem decisão e sem evidência de que seja o bloqueio atual.

### Próximo passo

Build release, hash BLAKE2b-256, e rodar
`native_real_daemon_two_claims_survive_original_store_reopen_v23` com evidence dir
novo. Acompanhar se a ativação agora conclui (a assinatura da falha antiga é
girar em `local_bootstrap` com filas limpas e revisões subindo).

## Atualização — 2026-09-18 (sessão Claude): ordem do claim context corrigida

### Regra reforçada pelo usuário

**Nunca afrouxar o código para um teste passar.** Um swap deve fechar em minutos,
não horas. Primeiro verde sem afrouxar; otimização depois.

Uma correção anterior desta sessão violou isso (relaxou `Signing(_) => false` em
`bootstrap_ready_v16`) e **foi revertida**. O gate está na severidade original.

### Correção aplicada (real, não afrouxamento)

Problema, confirmado com dado de runtime — é a conclusão 1 do documento
`dom-v25-static-full.zip` (itens A1–A5):

```
readiness exige grafo Produced
  └─ Produced exige claim_context (prepare_xmr_graph_completion_v23 recusa sem ele)
       └─ claim_context exige native_refund_binding das duas pernas
            └─ era instalado só DEPOIS da ativação terminar
                 └─ e a ativação esperava a readiness
```

Mudança (ordem, não rigor):

1. `production_composite_loop.rs`: novo acessor
   `ProductionCompositeActivationV1::stage12_owner_mut_v25()`, expondo o owner
   Stage-12 entre rodadas bounded de ativação (o tipo retomável já o carregava).
2. `production_run_universal.rs`: a materialização do `role_plan` e o
   `install_xmr_claim_context_v23` saíram de "depois da ativação" para **dentro
   do laço** de ativação, tentados a cada rodada. `f6_final_claim_plan` virou um
   slot `Option` devolvido quando ainda não é possível; as partes seguem para o
   resto do run via `claim_context_parts_v25`.

Nenhuma validação foi removida: mesma `materialize_native`, mesmo
`install_xmr_claim_context_v23`, e o teste de prontidão é o próprio
`bound_xmr_setup_v23`, que recusa enquanto os bindings não forem duráveis.

**Comprovação em execução:** `CTX>> native=true up=ok down=ok ready=true` —
a condição passou e o contexto foi instalado durante a ativação, o que a
circularidade impedia.

### Hipóteses derrubadas com dado (não repetir)

- **Conclusão 3 do documento (fencing route vs DOM):** não é alcançável. Medido
  `route_epoch=1` e `dom_epoch=1` nos dois atores; o cenário configura
  `lease_duration_ms = actuator_lease_ms = 120_000`, logo os contadores andam
  travados. Só divergiriam com durações diferentes (que o validador permite).
- **`dom_actuator` / `LeaseExpired` como doença:** é **consequência**. A ativação
  gira ~12 min e o lease de 120s estoura dentro de uma chamada de
  `activate_bounded`. Sintoma do protocolo não fechar em minutos.
- **Refund binding quebrado num participante:** falso. As quatro combinações
  (2 daemons × 2 pernas) acabam vinculando; são escalonadas no tempo.
- **Grafo nunca chega a `Signing`:** falso. Chega, por volta de rev24-25.

### Bloqueio remanescente (alvo atual)

Mesmo com o contexto instalado num daemon, **`Produced` nunca aparece**
(0 ocorrências) e a rota fica em `revision=1`, `outbox=0`.

- Um daemon: `up=ok down=ok ready=true` (instalou)
- O outro: `up=ok down=Binding ready=false` — a perna **downstream** recusa

`prepare_xmr_graph_completion_v23` exige as três arestas de assinatura
reauditadas, o que depende do peer. Logo resta uma dependência mútua: um não
completa o grafo porque o outro não fecha a perna downstream.

`bound_xmr_setup_v23` (`production_relay_xmr_enrollment_v23.rs`) tem três pontos
de recusa após o setup existir:
1. `native_refund_binding_v23()`
2. `authority.trusted_chain_id() != owner.trusted_chain_id`
3. `revalidate_xmr_refund_template_binding_v23(authority)`

Instrumentação temporária `stop=claim_ctx bound_setup=stepN` os separa. Esse é
o próximo dado a colher.

### Instrumentação temporária no working tree (REMOVER antes de commit)

- `production_relay_stage12.rs`: `DOM_READY_DIAG_V25` em `bootstrap_ready_v16`
  (a lógica foi extraída para `bootstrap_ready_inner_v16`)
- `production_relay_xmr_graph_v23.rs`: `graph_diag_v25` + `DOM_GRAPH_DIAG_V25`
  nos early-returns e no poll do refund
- `production_relay_xmr_enrollment_v23.rs`: `bound_setup=stepN`
- `production_run_universal.rs`: `stop=claim_ctx` na condição do fix

Todas gravam em `/tmp/dom-ready-diag.log` — **de propósito**: o stderr dos
daemons é `Stdio::piped()` e, na saída, filtrado por uma **allowlist** em
`production_xmr_native_binary_v23_tests/process.rs` que só deixa passar
`DOM_LEASE_DIAG_V25`, `DOM_ACTUATOR_OPEN_DIAG_V25` e mais quatro strings.
Diagnóstico novo via `eprintln!` **não aparece**, nem ao vivo nem na saída.

Lição de projeto: throttle **por tempo** (5s), nunca teto por contagem — um
ponto que dispara a cada rodada esgota o teto antes do estado de interesse.

### Ambiente (importante)

Máquina com 7,7 GB e ~2,7 GB livres. O guard de memória do harness mata builds
em background. Receita que funciona:

1. `CARGO_BUILD_JOBS=1 cargo build --release -j 1 ...` em **foreground** (~4 min)
2. `cargo test ... --no-run -j 1` em **foreground** (~4 min) — evita que o runner
   compile
3. lançar o cenário **destacado**: `setsid nohup python3 scripts/... &`
4. ler progresso por arquivo; nunca rodar dois cenários em paralelo

Cuidado: `pkill -f run_native_daemon_scenario` mata o runner mas **não** os
daemons (chamam-se `3`, via `/proc/self/fd/3`). Matar com
`ps -eo pid,comm | awk '$2=="3"{print $1}' | xargs -r kill -9`, senão eles
continuam escrevendo no log de diagnóstico e contaminam a leitura seguinte.

### Correções ao diagnóstico desta sessão (erros meus, não do sistema)

Três vezes o instrumento limitou a leitura e custou um ciclo (~16 min cada):

1. **Teto por contagem compartilhado** — um único contador de 60 linhas para
   todos os pontos; o ponto ruidoso da fase inicial (`parent_c_output_absent`)
   esgotou o teto antes de a execução chegar ao poll.
2. **Teto por tipo ainda pequeno** — 40 linhas por tipo também esgotaram, porque
   `claim_ctx` dispara a cada rodada de ativação.
3. **Throttle temporal compartilhado** — `claim_ctx` e `refund_poll` roteados ao
   mesmo contador de 5s: o primeiro vence quase sempre e as linhas de poll saem
   defasadas, o que me levou a interpretar `head_revision=18` como estado atual
   quando as sessões já estavam em rev24/25.

**Regra para a próxima instrumentação:** um throttle temporal **independente por
tipo de mensagem** (nunca compartilhado), e sempre imprimir junto o dado que
permite datar a linha (revisão, timestamp).

### Estado real do refund binding (suspeita descartada)

`poll_xmr_refund_template_binding_v23` funciona corretamente:

```
pid=848543 leg=0 outcome=some head_revision=19   <- vincula exatamente em 19
pid=848539 leg=0 outcome=none head_revision=18   <- ainda não chegou ao limiar
```

`none` abaixo de 19 é o comportamento especificado. O binding **não** é o defeito.

### Alvo único remanescente

Com o claim context instalado durante a ativação (`ready=true` observado), o
grafo ainda **não chega a `Produced`**: `prepare_xmr_graph_completion_v23`
retorna `None`. Ele exige as três arestas nativas (Cancel, Compensation,
RefundAdaptor) reauditadas. Próximo passo: instrumentar essa função para saber
qual das três auditorias falha — com throttle independente, conforme a regra
acima.

## CAUSA RAIZ IDENTIFICADA — as três arestas de signing nunca completam

Medição final (`DOM_GRAPH_DIAG_V25 stop=completion`, instrumentando
`prepare_xmr_graph_completion_v23` em `production_relay_xmr_signing_v23.rs:111`):

```
refund_complete=false aux0=false aux1=false
```

**As três** arestas de recovery signing (RefundAdaptor, Cancel, Compensation)
ficam incompletas durante toda a ativação — não uma, todas.

### Cadeia causal completa (cada elo medido, não deduzido)

```
3 arestas de signing nunca completam
  └─ prepare_xmr_graph_completion_v23 devolve None      (linha 111-113)
       └─ grafo nunca sai de Signing para Produced
            └─ bootstrap_ready_v16 permanece false      (Signing => false)
                 └─ ativação gira indefinidamente
                      └─ lease do actuator (120s) estoura dentro de
                         activate_bounded
                           └─ DOM_NATIVE_EXIT_DIAGNOSTIC code=dom_actuator
                              + DOM_LEASE_DIAG error=LeaseExpired
                                └─ "real daemon exited unsuccessfully"
```

Isso explica também a queixa de tempo: o swap não "demora", ele **nunca avança**
além da ativação e só morre quando o lease expira (~12 min).

### Por que o fix de ordem era necessário mas não suficiente

O fix (claim context instalado durante a ativação) é pré-requisito: sem ele,
`prepare_xmr_graph_completion_v23` nem chega a ser chamado, pois
`step_xmr_recovery_signing_v23` retorna antes quando `claim_context_v23()` é
`None`. Comprovado em execução: `CTX>> up=ok down=ok ready=true`.

Com o contexto instalado, a função passa a ser chamada — e aí revela que as três
arestas estão incompletas. Ou seja, o fix destravou o diagnóstico do defeito
seguinte; ambos precisam ser resolvidos.

### Próximo passo objetivo

Investigar por que `ProductionXmrRecoverySigningOwnerV23` nunca marca
`refund_complete` nem `auxiliary_complete`. Esses flags avançam em
`step_xmr_recovery_signing_v23` / `step_xmr_auxiliary_signing_v23`
(`production_relay_stage12.rs:223-344`), que dependem de troca com o peer.

Contexto observado: as sessões auxiliares existem e trocam mensagens (6 por
sessão, isto é, a rodada de 6 mensagens completa), mas os flags do owner não são
marcados. Suspeita: o marcador de conclusão exige algo além das 6 mensagens — a
aceitação do `0x0f` / pré-assinatura, por exemplo — que não é produzido durante
a ativação.

Instrumentar `step_xmr_auxiliary_signing_v23` e o ponto que marca
`auxiliary_complete` é a continuação natural. O helper `graph_diag_v25` já tem
throttle independente por tipo (EARLY / POLL / CTX / BOUND); adicionar um novo
tipo para o signing.

## Refinamento da causa raiz — o fix instala, mas tarde demais

Medição (run `v25-gate`, hash `34b72c4d`), contagens de diagnóstico:

```
refund_gate : 0     <- o gate revisao/fase/funding_authorized NUNCA bloqueou
bound_setup : 0     <- bound_xmr_setup_v23 nunca falhou nos 3 passos instrumentados
completion  : 0     <- prepare_xmr_graph_completion_v23 nunca foi chamado
claim_ctx   : 147   -> 73x "up=Binding down=Binding ready=false"
                       1x "up=ok down=ok ready=true"
```

Leitura:

- As 73 recusas vinham da **primeira** linha de `bound_xmr_setup_v23`
  (`xmr_custody_setup_v23`, setup do grafo ainda inexistente) — fase inicial
  normal, não defeito.
- O claim context **é instalado corretamente** (`ready=true`), mas apenas **uma
  vez e já perto do fim** do run.
- Como a instalação exige as duas pernas em rev>=19, e isso só ocorre por volta
  dos 11 min, sobra pouco tempo antes de o lease de 120s expirar.

### O gargalo é a velocidade da cerimônia

Cronometragem observada de forma consistente em todos os runs:

```
0:00 - 3:20  preparacao (cold swap)
3:20 - 7:00  sessoes auxiliares canceladas ate rev23
7:00 - 11:00 sessoes principais de rev0 a rev19+   (~12 s por revisao)
~12:00       lease do actuator expira -> dom_actuator
```

**~12 segundos por revisão DSC1** num ledger loopback local é ordens de grandeza
acima do esperado. Os backoffs configurados são de 100 ms e são pulados quando há
tráfego (`activation_backoff` só se aplica em rodada ociosa), logo não explicam o
número.

### Suspeita ambiental (verificar antes de mais mudanças de código)

`dom-node` está a **91% de CPU** de forma contínua, com **3 dias e 14 horas** de
uptime — muito anterior a qualquer execução de teste, portanto um processo
pré-existente e provavelmente travado. A máquina tem 7,7 GB com ~645 MB livres e
zram em uso.

Um core saturado permanentemente mais pressão de memória degrada toda interação
de cadeia e pode ser responsável por boa parte dos 12 s/revisão.

**Antes de continuar caçando defeito de protocolo, vale:**
1. Verificar se esse `dom-node` (PID 1817 na sessão observada) é legítimo ou
   resíduo travado; reiniciá-lo se for resíduo.
2. Rerodar o cenário com a máquina descarregada e recronometrar as revisões.
3. Se a cerimônia cair para segundos, a ativação conclui bem antes do lease e o
   fix de ordem passa a ser suficiente para esta etapa.

Isso é consistente com a exigência do usuário ("um swap deve fechar em minutos"):
o protocolo não está apenas lento, ele não chega a materializar ação econômica
nenhuma antes de o lease morrer.

## Hipótese ambiental TESTADA E DESCARTADA

O usuário autorizou encerrar o `dom-node` (PID 1817, de `$HOME/dom-release/`,
91% de CPU por 3d14h, minerando; **não** é usado por este cenário — o teste não o
referencia em lugar nenhum). Encerrado e não religado.

Ganho de recursos: 727 MB de RAM liberados (2,7 GB -> 3,5 GB disponíveis), core livre.

### Resultado: NÃO acelerou. Ficou igual ou mais lento.

| marco | máquina carregada | máquina limpa |
|---|---|---|
| `cold_swap_preparation` | ~168 s | **195,9 s** |
| `export_and_launch` | ~12 s | **16,8 s** |
| auxiliares até rev23 | ~180-210 s | **~300 s** |

**Conclusão: a lentidão é do protocolo, não da máquina.** Não adianta culpar o
ambiente nem mexer em recursos — o gargalo está no código.

### Ritmo real das revisões DSC1 (máquina limpa)

Não é uniforme. Amostras medidas de 30 em 30 s:

```
rev2  -> rev5/6    (~7,5 s por revisão)
rev8  -> rev17     (~3,3 s por revisão)   <- trecho rápido
rev17 -> rev20     (~10  s por revisão)
rev20 -> rev23     (~10  s por revisão)
```

A variação (3 s a 10+ s) é a assinatura de **espera por mensagem que já chegou**,
colhida só na rodada seguinte — não de custo de CPU, que seria uniforme.

### Suspeito no código

`production_run_universal.rs:763`:

```rust
let composite_call_bound = external_call_bound.min(Duration::from_secs(15));
```

Esse teto de **15 s** governa connect/accept/exchange de cada rodada de ativação,
enquanto o backoff ocioso é de apenas 100 ms
(`relay_poll_backoff_ms`). O laço avança ~uma mensagem DSC1 por rodada.

Se a troca Noise bloqueia até perto do teto em vez de retornar assim que o peer
responde, cada revisão custa segundos em vez de milissegundos. Num ledger
loopback local isso deveria ser sub-segundo.

**Direção da correção (NÃO é aumentar timeout):** fazer a troca retornar tão logo
haja dado do peer, em vez de esperar o limite. Investigar
`step_exchange_and_poll_v23` / `step_leg` e a camada Noise
(`production_noise_relay.rs`) para ver se há espera cega por deadline em vez de
sinalização por chegada.

Isso é o que separa "swap em minutos" de "swap que morre no lease": com ~10 s por
revisão e ~45 revisões só até a ativação, gastam-se >7 min antes de qualquer ação
econômica — e o lease do actuator é de 120 s por rodada.

### Confirmacao final: padrao identico com a maquina limpa

Com o minerador encerrado e 3,5 GB livres, o cenario reproduz **exatamente** o
mesmo padrao:

- `Signing` alcancado, `claim_ctx` avaliado ~140 vezes
- assimetria de sempre: um daemon com `needs_refund_binding=false`, o outro `true`
- `ready=true` = 0, `completion` = 0, `Produced` = 0
- rota parada em `revision=1`, `outbox=0`

A hipotese ambiental esta **definitivamente descartada**. O bloqueio e estrutural.

### Suspeito eliminado: espera cega por deadline

`DeadlineTcpStreamV1::read` (`production_noise_relay.rs:918`) ajusta o timeout
restante e chama `stream.read()`, que **retorna assim que o dado chega**. Nao ha
espera cega pelo teto de 15 s. A implementacao esta correta; o teto nao e a causa
da lentidao.

### O ponto exato que falta resolver

A instalacao do claim context exige as **duas** pernas do **mesmo** daemon com o
refund binding concluido (`bound_xmr_setup_v23` ok em Upstream e Downstream).
Na pratica um daemon fica com uma perna vinculada e a outra nao, de forma
persistente, e por isso `ready=true` nunca dispara nos dois lados.

Como o grafo so completa com as tres arestas reauditadas -- e isso depende do
peer -- basta um dos lados nao instalar para travar ambos.

**Proxima investigacao:** por que uma das pernas de um daemon nunca conclui o
refund binding enquanto a outra conclui. Medir, por perna e por daemon, a
revisao da sessao no momento do poll (o diagnostico `head_revision=` ja existe) e
verificar se a perna travada simplesmente nao alcanca rev19 -- e, se nao alcanca,
por que a cerimonia daquela sessao especifica estagna.

## DEFEITO LOCALIZADO: escopo de entrega não cobre as sessões auxiliares

### Evidência de execução (run `v25-split`, hash `fba29ed3`, 19m08s)

Estado congelado por 4+ minutos antes do fim:

```
alice: main=r33 arestas=r2  fila=3 envelopes PRESOS
bob:   main=r32 arestas=r1  fila=0

envelopes presos em alice:
  ord=76 sess=3e74bedf de=31f0712c para=0385ff25   (aresta Cancel/Compensation)
  ord=77 sess=07ddd3a0 de=31f0712c para=0385ff25   (aresta Cancel/Compensation)
  ord=78 sess=a1a1a1a1 de=31f0712c para=0385ff25   (sessao principal)

escopos de entrega registrados em alice (relay_delivery_scopes_v3):
  sess=246554e7 para=0385ff25    <- cancelada, DOIS escopos
  sess=246554e7 para=31f0712c
  sess=b2815675 para=0385ff25    <- cancelada, DOIS escopos
  sess=b2815675 para=31f0712c
  sess=a1a1a1a1 para=0385ff25    <- principal, DOIS escopos
  sess=a1a1a1a1 para=31f0712c
  sess=d1d1d1d1 para=0385ff25    <- principal, DOIS escopos
  sess=d1d1d1d1 para=31f0712c
  sess=3e74bedf para=31f0712c    <- ARESTA, UM SO escopo (falta para bob)
  sess=07ddd3a0 para=31f0712c    <- ARESTA, UM SO escopo (falta para bob)
```

### Causa no código

`production_noise_relay.rs:419`, em `send_direction`:

```rust
let scope = DeliveryScopeV3::new(recipient, self.route_id, self.session_id)
```

O escopo usa `self.session_id` — a sessão **daquele owner Noise**. As sessões
auxiliares de assinatura (Cancel/Compensation) têm owners próprios, mas seus
envelopes vão para a **fila central**, e o owner da sessão principal só entrega o
escopo da sessão principal. Logo ninguém pede página para `3e74bedf`/`07ddd3a0`
na direção do peer, e o escopo correspondente nunca é criado
(`validate_or_persist_delivery_scope_v3` só grava quando uma página é pedida,
`production.rs:2771`).

### Consequência (cadeia completa)

```
envelopes das arestas nunca entregues
  -> arestas nao completam (auxiliary_complete = false)
     -> prepare_xmr_graph_completion_v23 devolve None
        -> grafo nunca vira Produced
           -> bootstrap_ready_v16 nunca libera
              -> ativacao gira ate o lease expirar
```

### Provável regressão

Branch `codex/scoped-durable-inbox-v3`, commit *"Scope durable inbox delivery by
route session"*. O escopo por sessão foi introduzido e as sessões auxiliares de
assinatura ficaram de fora da enumeracao.

### Correção a avaliar

Fazer a troca enumerar tambem os escopos das sessoes auxiliares retidas em
`xmr_auxiliary_relays_v23`, ou dar a cada owner auxiliar sua propria direcao de
envio. NAO relaxar o escopo (ele existe por seguranca): incluir as sessoes que
legitimamente pertencem aquela rota.

---

## Atualização — sessão Claude (2026-09-18/19): rodadas 5–15

### Estado
- Os 3 cenários continuam vermelhos. Nada commitado nem enviado (regra: só depois do verde local).
- Rodada 15 (cenário 1) foi a mais longe da história do teste: **grafo de recuperação `Produced` nas duas pernas**
  (pai rev 25; arestas Cancel/Compensation com as 6 DSC1; refund_complete e aux_complete verdadeiros).
- Bloqueio atual: **F6 nunca ativa porque nenhum RFQ é emitido em produção** (ver abaixo).

### Correções aplicadas (todas compilam; unitários dos crates tocados verdes)
1. Lease do atuador DOM: renovação levada para dentro das fases do bootstrap, por aresta auxiliar, no bootstrap
   pós-troca, no resume, no runtime pós-ativação (step_leg, dreno terminal, laço intercalado, antes do route.step)
   e recarga cheia antes da exposição da claim (`production_child_dom.rs`). Reabertura renova o lease herdado.
2. Quadro `RecoveryScopesV23` simétrico no fio (`production_noise_relay.rs`).
3. Variantes de erro distintas: `actuator_lease_renewal`, `activation_stalled`, causas de rede separadas
   (identity/protocol/peer) + tabela `permitted` do classificador corrigida + testes.
4. Listener TCP retido entre rodadas (fim do livelock de encontro) + drenagem de conexões abandonadas pós-handshake.
5. Falha de E/S no handshake deixa de virar "identidade recusada" (`IdentityStoreError::TransportUnavailable`).
6. Prazo da troca Noise por escopo autenticado (`begin_scope_v25`), mesmos 15s por escopo; contrato do
   `blocking_bound` atualizado para 5 escopos.
7. Bootstrap redundante removido da ativação (3→2 por perna por rodada).
8. Envelopes auxiliares recusados deixam de ir para quarentena em silêncio (`inbox_refused`).
9. Erros de staging/assinatura: transitório vs permanente (`TransportRefused`).
10. Janela de funding renovada entre as metades da rodada (relay / route.step).
11. Pump de compensação reobserva prova vencida antes de usar; corrida de frescor no registro vira retry.
12. Recusa permanente de filho no coordenador (`ChildAuthorityRejected`) + testes.
13. Reaposentadoria do segredo idempotente por revisão (`route-secret-vault`) + teste.
14. Funding observado como Final no ramo `RecoveryOnly` (driver.rs; só observação, nunca despacho).
15. Reconstrução do dono da assinatura também em `RefundSigning`.
16. Retry limitado da observação de funding na reabertura (só `Unavailable`).
17. Watchdog de vivacidade da ativação por PROGRESSO (snapshot idêntico por 600s) com relatório
    `DOM_ACTIVATION_STALL_V25` (lifecycle, flags, revisões) liberado na allowlist do harness.
18. Pré-existente corrigido: `route-time-anchor/tests/common/mod.rs` `authority_set` público.

### Bloqueio atual: emissão de RFQ (F6)
- `take_ready()` só libera quando os dois RFQs (Upstream/Downstream) chegam autenticados pelo relay.
- `relay_worker::prepare_f6` não tem chamador em produção; `production_f6/initiator_v25.rs` nunca é construído.
- O desenho já prevê o daemon local como iniciador: `production_relay_stage12.rs:1570`
  (`initiator = local` quando o papel local no roster é Initiator) — o iniciador recebe o próprio RFQ de volta
  pela caixa de entrada.
- Pós-ativação, NÃO enviar Quote/Selection/Acceptance (o solver os trata com erros não-permanentes fatais).
  Emitir os dois RFQs juntos (RFQ sem par bloqueia o dispatch DSC1 da perna).
- Falta decidir a origem do CONTEÚDO econômico do RFQ (mode ExactIn input/minimum, fee_limit, quote_deadline,
  assurance_policy_ref, negotiation_clock): não existe em nenhum insumo autenticado de produção.
  Proposta: derivar deterministicamente da composição/termos autenticados. Decisão pendente do usuário.
- Guarda de idempotência já escrita: `DurableRelaySenderV1::kind_ever_prepared_v25` (route-transport).

### Pendências conhecidas
- F11 (publicação do dono no cenário 3, orçamento finito de 180s por projeto): observar na execução.
- Otimização de CPU por rodada (~75–90s dominados por re-verificação local): depois do verde.
- Caminho legado V3 (BTC/EVM) não verificado quanto ao lease.

## Atualização — forense da rodada 40 (stores retidos, sem rodada nova)

A rodada 40 foi a primeira em que os dois daemons sobreviveram as 2 h inteiras sem
nenhuma recusa, nenhum crash e nenhum diagnóstico. Ela ainda falhou, por deadline.
Toda a análise abaixo veio do tarball retido em
`<evidence>/native_real_daemon_two_claims_survive_original_store_reopen_v23/synthetic-fixtures.tar.gz`,
não de uma execução nova.

Medições:

- `daemon-route_store` → `route_journal` tem **exatamente 2 eventos**: `FreezeTermsV2`
  (tag `0x0E`, 05:05:59) e **`ArmRefunds`** (tag `0x01`, 05:28:21). Nenhum evento depois,
  por 1h40. O `route_leases` continuou sendo renovado até 07:06 — daemon vivo.
- `daemon-relay_queue/relay-v1.sqlite3` → `relay_delivery_flows`: nas sessões `A1A1…`
  e `D1D1…`, alice→bob em `0x0F` e bob→alice em `0x0E`, com os dois lados idênticos.
  Alice retém 2 `relay_envelopes` de seq `0x10`, relay `message_type=0x0005`
  (ROUTE_TRANSPORT), payload DSC1 `0x0D` = `SigNonceReveal`.
- `daemon-dom_actuator_store`: nenhuma escrita depois do setup, nos dois lados.

Conclusões que isso fixa:

1. O `ArmRefunds` gravado **prova** que os dois lados chegaram a
   `GraphLifecycleV23::Custodied` e instalaram o driver de recuperação: a face DOM do
   arming exige `xmr_refund_readiness_v23`, instalado só em
   `production_xmr_graph_custody_v23.rs::activate_recovery_v23`.
2. Nenhum deadline de altura venceu: um deadline devido chamaria
   `record_height_deadline_recovery_v23` (`runtime.rs:395`), que grava `set_health`
   → seria um terceiro evento no journal.
3. Sobra uma parede só: **a janela de funding nunca abre**, `FundingGuardV23` recusa
   `Funding` com `Unavailable` e o driver espera para sempre. Nenhum diagnóstico
   existente cobre `Unavailable`.

Dois defeitos reais do harness, corrigidos:

- O caminho de deadline de `wait_claims` deixava os daemons vivos, então o stderr
  nunca chegava a EOF e **nenhuma** linha era drenada. Agora `report_stall_v25`
  termina os daemons antes de falhar.
- `process.rs::drain` devolvia `Err` ao passar de 256 KiB, descartando **toda** a
  captura. Agora retém os primeiros bytes e segue lendo, sem bloquear o daemon.

Tempo: os 22 min entre `FreezeTermsV2` e `ArmRefunds` são a cerimônia bilateral do
grafo XMR, com um envelope por escopo por rodada e janelas de socket de 10 s por
perna/escopo (`production_composite_loop.rs:601-629`, `production_run_universal.rs:767-795`).
Isso é um problema de velocidade por si só e continua aberto.

## Atualização — rodada 41: o harness estrangulava o daemon

Causa real do silêncio de 2 h da rodada 40: `production_xmr_native_binary_v23_tests/process.rs::drain`
devolvia `Err("daemon output exceeded bound")` ao passar de 256 KiB e **encerrava a thread
leitora**. O daemon imprime `DOM_NATIVE_F7_FUNDING_V24` a cada rodada e por perna; o pipe
de stderr enchia e o daemon ficava preso no `write`. Resultado: nenhum progresso durável,
nenhuma linha de log, CPU alta — exatamente a assinatura que parecia ser do protocolo.

Corrigido: o `drain` retém os primeiros `MAX_CAPTURE` bytes e **continua lendo** o excedente
para um buffer fixo que é descartado, de modo que o daemon nunca bloqueia no pipe.

Com isso a rodada 41 avançou muito além da parede, em 41 min em vez de 2 h:

```
DOM_FUNDING_WINDOW_V25 open=true observers= open open open
DOM_F7_FUNDING_GATE_V25 leg=Upstream gate=produced → custodied
DOM_NATIVE_F7_FUNDING_V24 leg=Upstream step=AwaitingPeer → Staged → Committed
DOM_NATIVE_F7_FUNDING_V24 leg=Downstream step=Staged
DOM_CHILD_CONFLICT_V25 file=production_child_dom.rs line=2428
```

Defeito seguinte, confirmado por leitura: `ExpectedDomBindingsV1::validate_static` comparava
`binding.profile_digest()` (digest **bruto** de regras de consenso, `dom-actuator/src/model.rs:388`)
com `self.profile_digest` (hash de perfil do adaptador, que **contém** aquele digest). Comparação
estruturalmente impossível — a mesma classe de defeito já corrigida em `materialize`. Corrigido
fixando o binding contra `dom_consensus_rules_digest`, sua própria fonte.

## Atualização — rodadas 44/45: a parede agora é UM envelope

Com o `drain` corrigido e o digest de perfil fixado contra a própria fonte, a cerimônia
vai muito mais longe. Rodada 45 (idêntica à 44), medida na fixture retida:

- `route_journal` = 4 eventos nos dois lados: `FreezeTermsV2`, `ArmRefunds`,
  `CommitAction`, `CustodyProgressRecorded`.
- Sessão DOM **upstream**: `stage_tag=6` (`STAGE_FUNDING_BROADCAST`) nos dois lados,
  `dom_operations` com `action_tag=6` (`BroadcastFunding`). A cadeia DOM local subiu de
  1004 para 1006 blocos — funding incluído e confirmado.
- Sessão DOM **downstream**: Alice em `STAGE_OUTPUTS_RESERVED`, Bob em `STAGE_BOUND`.
- `DOM_NATIVE_F7_FUNDING_V24 leg=Downstream step=AwaitingPeer`, repetido para sempre.

`AwaitingPeer` vem de `production_funding_runtime_v20.rs:88-94`: faltam votos `0x17`
(`f7_ready_count_v12` < 2). Rastreando até o transporte:

- Registros de sessão downstream: Alice na revisão **33**, Bob na **32**.
- Inbox durável do Bob (downstream): 16 entradas, sequências `0x00..0x0F`, todas
  `delivery_state=1`. A última que ele recebeu da Alice é `0x0D` (`SigNonceReveal`).
- Fila do relay da Alice: **exatamente um** envelope pendente, ordinal 125, sessão
  `D1D1`, sequência `0x10`, payload DSC1 **`0x0E` (`PartialSignature`)**.

Ou seja: **a perna downstream inteira está bloqueada por um único envelope que não é
entregue.** Não é perda de mensagem (revisei essa leitura: nada foi descartado) nem
quarentena (`relay_conflicts` e `inbox_quarantine` vazios nos dois lados).

Cursores de entrega da Alice (`relay_delivery_scopes_v3` × `relay_delivery_state`):

```
D1D1D1D1 -> 6FAD6E (Bob)  cursor=121
A1A1A1A1 -> 6FAD6E (Bob)  cursor=122
envelope pendente: ordinal 125, sessao D1D1
```

A consulta de entrega é `ordinal > cursor` (`crates/relay/src/production.rs:2702`), não
exige contiguidade, então o cursor atrasado **não** explica sozinho. O ramo de página
pendente (`delivery_page_from_pending_v3`, `production.rs:2539`) também não explica: se
os envelopes de uma página pendente tivessem sido apagados ele devolveria
`CorruptState`, um erro duro, e o daemon teria falhado — não falhou.

Conclusão honesta do estado: a parede está **acima** da consulta do relay. O envelope 125
é candidato válido para o escopo `D1D1 -> Bob` e mesmo assim nunca é oferecido, o que
aponta para o exchange da perna downstream não estar sendo exercitado para esse escopo
(ou para o lado do Bob não o buscar). O próximo ponto a instrumentar é
`step_exchange_and_poll_renewing_v25` (`production_composite_loop.rs:595`) e
`exchange_configured_link_retained_v25`, contando ofertas e aceites por escopo — os
contadores `EXCHANGE_DIAG_V25` já existem em `production_relay_network_runtime.rs` e só
precisam ser impressos e postos no allowlist.

Descartado por medição, para não ser reinvestigado: não há mensagem perdida, não há
quarentena (`relay_conflicts` e `inbox_quarantine` vazios), não há divergência de
transcript entre os dois lados, e o cursor por escopo não bloqueia a seleção.

## Atualização — rodada 46: relay inocentado, e um defeito novo nomeado

A rodada 46 não travou em silêncio: o daemon saiu com código 1 e
`DOM_NATIVE_EXIT_DIAGNOSTIC_V24 code=composite_loop stage=post_exchange_bootstrap cause=expired`
(`production composite relay loop failed: post_exchange_bootstrap/expired`). O lease do
atuador expirou na costura entre o exchange e o passo de bootstrap seguinte, com
`DOM_PHASE_SLOW_V25 leg=1 phase=handoff_recovery_signing held_ms=53757`.

Dois fatos que a instrumentação `DOM_EXCHANGE_SHAPE_V25` fixou, em 80 observações:

1. **`out_backlog=false` em todas as 80.** O relay nunca termina um exchange com
   backlog de saída. Isso **inocenta a camada de relay** na parede das rodadas 44/45: o
   envelope 125 não ficou parado porque o relay se recusasse a ofertá-lo; ele ficou
   porque nenhum exchange daquele escopo voltou a rodar depois de ele ser estagiado.
   Não é preciso reinvestigar `delivery_page_v3`, cursores por escopo nem quarentena.

2. **A cerimônia anda estritamente um envelope por rodada por perna** — as formas
   observadas alternam `sent=1 recv=0` e `sent=0 recv=1` (33 e 32 ocorrências), com
   picos raros de 2 ou 3. Com ~35 mensagens DSC1 por perna e janelas de socket de 10 s,
   isso é a razão estrutural de uma cerimônia levar ~50 minutos. É exatamente o
   problema de velocidade ("um protocolo de swap não deve demorar horas e sim alguns
   minutos") e agora está medido, não suposto.

Próximo ponto: `post_exchange_bootstrap/expired` em
`production_composite_loop.rs::poll_retained_inbound_renewing_v25`. O lease é renovado
imediatamente antes de `mark_lease_phase_v25("post_exchange_bootstrap")`, e mesmo assim
o passo seguinte o encontra expirado — ou seja, `step_bootstrap_with_renewal_v25` não
está renovando dentro de si como o nome promete. **Aumentar a duração do lease não é
correção** e está proibido; a correção é o passo renovar durante o próprio trabalho.

## Atualização — o teto real: a cerimônia tem um orçamento fixo de 1 hora

`ProductionBootstrapLegV16::expiry` (`production_bootstrap_runtime_v16.rs:825-845`):

```rust
let value = if let Some(bytes) = material.runtime_public_record_v16(b"relay-expiry-v16")? {
    u64::from_le_bytes(...)          // valor gravado UMA vez
} else {
    let value = now + ENVELOPE_LIFETIME_SECONDS;   // 3600 s
    material.retain_runtime_public_v16(b"relay-expiry-v16", &value.to_le_bytes())?;
    value
};
if now > value {
    return Err(Error::Expired);      // fatal, para sempre
}
```

O valor é cunhado na **primeira** chamada e reusado em todas as seguintes. A partir daí
ele deixa de ser o tempo de vida de *um envelope* e passa a ser o **prazo de validade da
cerimônia inteira**: passou de 3600 s desde o primeiro envelope, o daemon morre com
`Expired`, sem recuperação.

Confirmação pela rodada 46: daemons no ar às 10:46:17, teste encerrado em 4002 s com
startup de ~190 s, ou seja **~63 min de daemon**, e a saída foi exatamente
`code=composite_loop stage=post_exchange_bootstrap cause=expired`. 63 min > 60 min.

Isso se combina com o custo de transporte medido (`DOM_EXCHANGE_SHAPE_V25`, 80
observações): a cerimônia anda **um envelope por rodada por perna**, e cada rodada gasta
até 60 s por perna em janelas de socket (`composite_call_bound` = `min(30 s, 15 s,
lease/6)` = 10 s, × `EXCHANGE_SCOPES_PER_CONNECTION_V25` = 5, mais o próprio bound).
Com ~35 mensagens DSC1 por perna, a cerimônia precisa de 50–70 min de relógio.

**Conclusão: o swap não pode terminar. Ele precisa de mais tempo de parede do que o seu
próprio orçamento permite.** As duas metades do problema são:

1. Um tempo de vida por envelope sendo usado como prazo da cerimônia
   (`relay-expiry-v16` gravado uma vez e nunca renovado).
2. Rodadas caras demais: janelas de socket queimadas quando os dois lados não estão
   alinhados na mesma fase do laço.

Aumentar `ENVELOPE_LIFETIME_SECONDS` **não** é correção e está proibido — é um constante
de protocolo e esconderia (2). A correção de (1) é cada envelope novo receber seu próprio
tempo de vida, mantendo o valor gravado apenas para replay byte-idêntico de um envelope
já assinado. A correção de (2) é não queimar a janela inteira de accept/connect quando
não há nada a trocar.

## Atualização — rodada 47: onde o tempo vai, medido

Contadores por perna (`DOM_EXCHANGE_SHAPE_V25`, 87 observações, ~31 min de daemon):

```
leg=Upstream   calls=55 conn_ok=0 conn_fail=0 acc_ok=50 acc_deadline=5 yield=8 sess_err=0
leg=Downstream calls=53 conn_ok=0 conn_fail=0 acc_ok=48 acc_deadline=4 yield=4 sess_err=0
```

O que isso fixa:

- **Não há patologia de rede.** `sess_err=0`, `conn_fail=0`, e os accepts sucedem em
  50 de 55 tentativas. As 5 janelas estouradas não explicam nada.
- **Este daemon nunca disca** (`conn_ok=0`): ele é sempre o lado que escuta, nas duas
  pernas. O par disca praticamente toda rodada.
- **~34 s por exchange** (55 exchanges em ~1860 s), e **uma fração grande deles carrega
  zero envelopes** — `sent=0 recv=0` aparece repetidamente, inclusive três vezes
  seguidas na perna downstream enquanto a upstream movia 3.

Ou seja: o laço faz um exchange autenticado completo por perna por rodada mesmo quando
nenhum dos dois lados tem o que enviar. Com ~35 idas e voltas DSC1 sequenciais por
perna a cerimônia custa 30–60 min de relógio, e é por isso que ela estoura o orçamento
de 3600 s de `ENVELOPE_LIFETIME_SECONDS`.

**Correção pendente (não improvisar):** o custo tem de cair, não o orçamento subir. As
duas direções possíveis são (a) o lado que disca não abrir conexão para uma perna sem
nada estagiado, usando o hello para anunciar "tenho N envelopes para você" e encerrar
cedo um par vazio-vazio, ou (b) trocar o polling por rodada por um exchange dirigido a
evento. Ambas mexem no laço de protocolo e precisam de desenho, não de remendo.

## Resultado negativo — não fechar a janela de funding antes do arming (revertido)

Tentativa: pular o refresh da janela de funding enquanto `snapshot.refunds.is_none()`,
com o raciocínio de que o driver não alcança nenhuma ação de funding antes do arming
(`driver.rs:369-378`) e portanto a observação de altura — que custa 60 s por observador
XMR, `production_height_timer_v23.rs:384-392` — seria desperdício puro nessa fase.

**Medição (rodada 48): não funcionou e piorou.**

- `ArmRefunds` chegou aos 30 min, exatamente como nas rodadas 44/45. A observação XMR
  **não** domina a fase de bootstrap: a janela dura 60 s e a macro só reobserva quando
  ela caduca, então o custo real era ~12 observações, não uma por rodada.
- Aos 62 min a rota continuava em `rev=2`, enquanto a rodada 45 já estava em `rev=4`
  com o upstream em `FUNDING_BROADCAST`.
- Diagnóstico final: **as duas pernas** presas em `step=AwaitingPeer`, não só a
  downstream.

Causa do dano: `step_f7_funding_v20` é um *pump* do laço composto, independente do
driver. Fechar a janela antes do arming faz o `contracts.step_f7_funding_v20` interno
devolver `WindowClosed` e o aperto de mão de readiness (`0x17`) nunca progride. O
raciocínio "o driver não chega no funding" era verdadeiro para o driver e falso para o
pump.

**Revertido.** Não repetir. A lição: a janela de funding não é só um portão do driver,
ela também governa o pump de readiness.

## Rodada 50 — a parede downstream é inanição da janela de funding

Primeira rodada com os **dois** daemons relatando (correção: `report_diagnostics_v25`
agora termina o que ainda estiver vivo antes de ler o stderr — um daemon vivo nunca
chega a EOF e metade da evidência sumia a cada rodada).

Estado alcançado, o melhor até aqui e mais cedo (41 min): rota em `rev=4`
(`FreezeTermsV2, ArmRefunds, CommitAction, CustodyProgressRecorded`) e **upstream em
`stage_tag=6` (`FUNDING_BROADCAST`) nos dois lados**.

Quórum de readiness (`DOM_READY_QUORUM_V25`):

```
3x accepted=0 bound_rev=25 cur_rev=25 next=76d02f
3x accepted=1 bound_rev=25 cur_rev=26 next=08d044
```

O quórum **avança**: o primeiro voto `0x17` entra (`cur_rev` 25 -> 26) e o segundo não.
Ou seja, não é um lado mudo — é o segundo voto que não fecha.

Passos de funding (`DOM_NATIVE_F7_FUNDING_V24`):

```
Upstream    12 AwaitingPeer | 12 Staged | 16 Committed |  0 WindowClosed
Downstream  10 AwaitingPeer | 10 Staged |  0 Committed | 15 WindowClosed
```

**A assimetria é o achado.** O upstream nunca vê `WindowClosed` e compromete 16 vezes.
O downstream chega a `Staged` mas **nunca** a `Committed`, e bate em `WindowClosed` 15
vezes — o maior resultado isolado dessa perna.

Mecanismo: `refresh_funding_window_v23!` é chamado no início da iteração de cada perna,
mas `retry_height_observation_v23` é **uma única bandeira compartilhada pelas duas**.
Ela é posta em `true` no topo da rodada e, ao fim do refresh, recebe
`funding_window_v23.available()`. Quando a observação da primeira perna falha, a
bandeira vira `false` e a **segunda perna não tem direito a tentar** — roda a rodada
inteira com a janela fechada. O upstream não sofre porque, quando não tem o quórum, ele
retorna `AwaitingPeer` **antes** de qualquer checagem de janela
(`production_funding_runtime_v20.rs:88-94`); só a perna que chega a `Staged` precisa da
janela e é justamente a que a encontra fechada.

Isto é inanição, não uma recusa de segurança: a janela existe para garantir observação
de altura fresca antes de autorizar funding, e negá-la à segunda perna por causa da
primeira não serve a essa garantia. A correção tem de dar a cada perna seu próprio
direito de observação na rodada, sem afrouxar o que a janela verifica.

## Rodada 51 — a inanição da janela não era o bloqueio (revertido)

Tentativa: dar a cada perna sua própria tentativa de observação por rodada
(`retry_height_observation_v23 = true` antes do refresh de cada perna), para acabar com
a inanição medida na rodada 50.

**Resultado: a correção fez o que prometia e ainda assim a rodada piorou.**

- `WindowClosed` **desapareceu por completo** — o objetivo declarado foi atingido.
- Mas as duas pernas ficaram só em `AwaitingPeer` (29 cada), nenhuma chegou a `Staged`,
  e o Bob nem armou os refunds em 52 min (a rodada 50 estava em `rev=4` aos 41 min).
- Custo causal plausível: a segunda perna passa a pagar mais uma observação de até 60 s
  por rodada, desacelerando a cerimônia inteira.

**Revertido.**

### O invariante que sobrou, e é o alvo real

Em **três rodadas seguidas** (49, 50, 51) o quórum de readiness tem exatamente a mesma
forma:

```
accepted=0 bound_rev=25 cur_rev=25 next=<par A>
accepted=1 bound_rev=25 cur_rev=26 next=<par B>
```

O **primeiro** voto `0x17` entra e move a sessão de 25 para 26. O **segundo nunca
chega**. Isso é independente da janela de funding, independente do relay (inocentado na
rodada 47) e independente do ciclo de vida do grafo (`custodied` nas duas pernas, zero
`GateAbsent` em ~250 observações).

Próximo alvo, sem ambiguidade: por que o participante `next=<par B>` não produz seu
`0x17` depois que o primeiro voto foi aceito. O caminho é
`step_f7_readiness_v19` -> `recovery_mounted_for_readiness_v23` ->
`prepare_xmr_ready_to_fund_dsc1_signing_request_v12`, que devolve `Ok(None)` em silêncio
quando `signer.participant_id != vote.participant_id`. Instrumentar esse `Ok(None)` é o
que falta.

## Rodada 52 — a causa: um dos pares nunca recebe o setup do grafo XMR

Instrumentado o último ponto mudo do caminho de readiness
(`prepare_xmr_ready_to_fund_dsc1_signing_request_v12`, o `Ok(None)` de
`signer.participant_id != vote.participant_id`).

```
SIGNER:  1x signer=d6050f expected=d6050f match=true
QUORUM:  2x accepted=0 bound_rev=25 cur_rev=25 next=d6050f
         2x accepted=1 bound_rev=25 cur_rev=26 next=d5f889
STEPS:   20x leg=Upstream step=AwaitingPeer | 20x leg=Downstream step=AwaitingPeer
GATE:    1x Upstream produced | 1x Upstream custodied
         1x Downstream produced | 1x Downstream custodied     <- so 4 linhas, de UM daemon
```

Leitura:

1. O primeiro par (`d6050f`) **se reconhece** (`match=true`), assina, e o quórum vai de
   `accepted=0` para `accepted=1`. Esse lado está correto.
2. O segundo par (`d5f889`) **nunca imprime uma linha de assinante**. Não é que ele tome
   a saída muda — ele nunca chega a `prepare_xmr_ready_to_fund_dsc1_signing_request_v12`.
3. Os dois daemons relataram, mas os tokens de portão aparecem só **4 vezes** (um
   daemon, duas pernas, dois estados). O segundo daemon não emite **nenhum** token de
   portão e ainda assim alcança o fim de `step_f7_funding_v20` (20 `AwaitingPeer` por
   perna). O único caminho da função que não emite token é o ramo **`else`**, alcançado
   quando `self.xmr_graph_setup_v22[index]` é `None` e o `bootstrap_v16[index]` está
   completo (`production_relay_stage12.rs:810-820`).

**Conclusão: um dos dois pares nunca recebe o setup do grafo XMR.** Sem ele
`activate_recovery_v23` nunca roda desse lado, `xmr_refund_readiness_v23` nunca é
instalado, `step_f7_readiness_v19` nunca produz o `0x17` — e por isso o quórum trava
eternamente em `accepted=1`. Também explica por que esse mesmo lado nunca arma os
refunds (`rev=1` enquanto o par está em `rev=2`): o arming exige a mesma prontidão
nativa.

Alvo seguinte, sem ambiguidade: por que `xmr_graph_setup_v22[leg]` fica `None` em um dos
pares. Ver `production_relay_xmr_graph_v23.rs` (`xmr_custody_setup_v23`,
`mount_xmr_custody_resources_v23`) e o caminho de enrollment nativo que o popula.
