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

## Rodadas 53–54 — readiness corrigida; gargalo posterior medido

O fluxo de readiness foi corrigido por leitura e por execução real:

- o driver de recovery é ativado antes da leitura de prontidão;
- a troca bilateral `0x17` recebe até duas Relay halves adjacentes, com releitura
  durável depois de cada uma;
- o helper de pending exato não aceita envelope de outro `application_id`;
- a espera pelo handoff de funding nativo é retryable e nunca recebe ACK falso.

No `run10` (`dom-xmr-evidence-claims-reopen-20260921-run10`), as quatro sessões
chegaram a `27/27/27/27`. Isso prova que os dois votos `0x17` foram aceitos em ambas as
pernas. O processo não caiu, mas o teto de 30 minutos encontrou:

```
alice upstream=30 downstream=27
bob   upstream=30 downstream=27
```

O upstream iniciou e concluiu o vault de funding; o downstream ainda não tinha criado
os artefatos de funding. A leitura do root loop mostrou sete Relay halves completas
por volta após readiness: uma inicial, quatro depois dos dois pumps de recovery e duas
depois das fases nativas.

Os pumps não produzem Relay:

- `tick_remote_refund_v24` usa o transporte lateral XMR e retém a resposta no driver;
- `tick()` produz no máximo um relatório de compensação gravado diretamente no
  `ProductionRouteRuntimeV1`.

Portanto as quatro Relay halves depois desses pumps eram espera vazia. Elas foram
removidas. Os limites de chain/RPC, as autoridades e o transporte de refund não foram
alterados.

## Run11 — tentativa de flush unilateral rejeitada por evidência

Foi tentado trocar o flush completo posterior à fase nativa por um flush apenas da
perna corrente. Os testes curtos passaram, mas a execução real mostrou faseamento
incorreto:

```
tempo de daemon ~991 s:  alice=26/26 bob=27/27
tempo de daemon ~1051 s: alice=26/26 bob=29/27
tempo de daemon ~1111 s: alice=26/26 bob=29/27
```

Bob entrou no funding upstream antes de Alice persistir o segundo voto de readiness.
O flush unilateral não atendia a outra perna necessária para o rendezvous. A execução
foi interrompida deliberadamente, a evidência ficou em
`dom-xmr-evidence-claims-reopen-20260921-run11`, e o runner confirmou
`cleanup_verified=true` e `fixture_cleanup_verified=true`.

**Não restaurar o flush unilateral.** Ele foi removido do código.

## Estado atual após o run11

A versão corrente mantém:

1. uma Relay half completa no início da volta;
2. até duas halves completas somente enquanto os dois votos `0x17` não estão duráveis;
3. zero Relay half depois dos pumps laterais de recovery;
4. uma Relay half completa depois da fase nativa upstream;
5. uma Relay half completa depois da fase nativa downstream.

Depois de readiness, isso reduz o custo ordinário de sete para três Relay halves por
volta (57%), preservando o serviço bilateral que a execução real provou necessário.

Validações curtas da versão corrente:

- `cargo fmt --all -- --check`: verde;
- `git diff --check`: verde;
- `production_composite_loop::tests`: 25/25 verdes;
- `production_run::universal::native_phase_ownership_v24::tests`: 5/5 verdes.

Próximo passo: build release, calcular BLAKE2b-256, então repetir somente
`native_real_daemon_two_claims_survive_original_store_reopen_v23` com teto local. Não
executar GitHub Actions nem fazer push antes de o cenário local ficar verde.

## Run12 — readiness verde; gargalo isolado na cerimônia de Funding

O `run12` usou o binário release com BLAKE2b-256
`b8d42d3a823a9ef0b1ff449163af698d15ddffd8fd985605cf8d91fb6b460b13` e evidência em
`/home/leonardov/dom-xmr-evidence-claims-reopen-20260921-run12`.

O fluxo passou, nas quatro sessões, por `17/17`, `25/25`, `26/26` e `27/27`. Depois da
readiness, as revisões chegaram a:

```
alice upstream=29 downstream=29
bob   upstream=30 downstream=28
```

Não houve `SIGBUS`, crash ou erro de aplicação. O runner encerrou pelo teto global de
1800 segundos, com `cleanup_verified=true` e `fixture_cleanup_verified=true`. Portanto
esse resultado não é verde, mas comprova que a correção de readiness não regrediu.

A inspeção estática e dos Stores arquivados mostrou:

- o início retido de Funding está na revisão 28;
- as seis mensagens alternadas levam o Store à revisão 34;
- o commit de Funding é persistido na revisão 35;
- no timeout, as quatro sessões tinham aceitado respectivamente 1, 2, 1 e 0 mensagens;
- nenhum arquivo `.f7-v12-funding` existia ainda, apenas
  `.f7-v12-funding-signing-v20` e os vaults XMR;
- os Stores de rota continuavam na revisão 2, sem outbox econômico: o Funding ainda
  não tinha chegado ao runtime de rota.

Assim, o gargalo não era confirmação de chain. O scheduler avançava no máximo um
envelope de Funding por volta externa e colocava observação de altura, recovery e route
half entre cada mensagem. A mesma demora voltaria na cerimônia de Claim, que também usa
seis mensagens.

## Otimização posterior ao run12 — burst nativo limitado

Dentro do bloco já autorizado por `f7_readiness_complete_v25`, cada perna agora recebe
um burst de até oito passes. Cada passe mantém, na mesma ordem, as operações de
Funding, Claim, Claim receiver e uma Relay half bilateral completa. O loop termina após
dois passes consecutivos sem tráfego.

Os limites têm função protocolar precisa:

- oito passes cobrem a transição local de início, seis envelopes e a agregação terminal;
- dois passes ociosos permitem uma transição local sem tráfego e depois comprovam que
  não existe envelope imediatamente acionável;
- toda iteração relê janela, Store, scanner e ownership; nenhum timeout, margem de
  finality ou confirmação foi reduzido;
- o flush continua bilateral. Não reintroduzir o flush unilateral rejeitado no run11.

Validações curtas já verdes nesta versão:

- `production_run::universal::native_phase_ownership_v24::tests`: 5/5;
- `production_composite_loop::tests`: 25/25;
- `xmr_funding_window_v23_tests`: 3/3;
- `v18_refund_handoff_wait_does_not_accept_or_hide_invalid_messages`: 1/1;
- `dom-wallet-crypto --test policy_and_lensb`: 6/6, com 2 casos históricos `ignored`;
- `cargo fmt --all -- --check`: verde;
- `git diff --check`: verde.

O teste `f7_v20_native_reopen_recovers_every_signing_staging_cut_without_authorizing_funding`
foi interrompido depois de vários minutos sem conclusão nem falha; ele percorre cortes
de processo e não pertence ao ciclo rápido. Não tratá-lo como verde nem como vermelho.
O próximo passo é fazer o build release e repetir somente o cenário de
claims/original-store reopen. Não iniciar os workflows completos nem publicar antes de
esse cenário local ficar verde.

## Runs 14–15 — burst preserva readiness; timeout isolado na perna Relay ociosa

O `run14` consumiu a primeira compilação de `crypto-test` e atingiu o teto global. O
`run15`, já com cache, confirmou o comportamento do burst nativo sem regressão:

- `crypto-test`: cerca de 27 s;
- preparação fria: cerca de 159 s;
- quatro sessões em `17/17` por volta de 300 s;
- quatro sessões em `25/25` por volta de 1081 s;
- quatro sessões em `26/26` por volta de 1382 s;
- Funding iniciado em `27/27`–`28/27` por volta de 1412 s;
- todas em upstream `29`, downstream `27` por volta de 1562 s.

O teto de 1800 s terminou com `cleanup_verified=true` e
`fixture_cleanup_verified=true`. A evidência está em
`/home/leonardov/dom-xmr-evidence-claims-reopen-20260921-run15`. Não houve crash nem
erro de protocolo; o estado final continha apenas staging de signing, antes do commit
de Funding.

A leitura do scheduler mostrou o custo residual: cada passe do burst chamava uma Relay
half bilateral. Depois que uma perna produzia uma mensagem, a outra perna sem trabalho
consumia seu timeout completo. Isso acrescentava aproximadamente 30–60 s por envelope.

## Otimização após run15 — sincronização inicial bilateral e bordas focadas

Cada perna do burst mantém uma primeira Relay half bilateral. Ela é necessária para
sincronizar o voto de readiness que evitou a regressão observada no run11. Nos passes
seguintes, o scheduler chama `run_production_composite_relay_leg_v25` somente para a
perna que acabou de executar uma fase nativa. O helper:

- relê o bloco de rota e renova a lease antes da chamada;
- usa `step_relay_leg_renewing_v25` para não aguardar a perna ociosa;
- repete uma vez a mesma perna quando há peer pending;
- respeita shutdown antes de qualquer trabalho.

Validações curtas verdes desta mudança:

- teste funcional do relay focado: 1/1;
- teste estrutural da ordem bilateral → focada: 1/1;
- `cargo fmt --all -- --check`: verde;
- `git diff --check`: verde.

Próximo passo: build release, registrar novo BLAKE2b-256 e repetir somente
`native_real_daemon_two_claims_survive_original_store_reopen_v23`. O critério desta
rodada é ultrapassar rapidamente as revisões 29 e concluir Funding/Claim/reopen. Se
falhar, preservar a evidência e voltar à leitura estática antes de nova execução.

## Continuação — evidência de custódia e execução integral autorizada

O teste focado `native_real_daemon_bilateral_xmr_graph_custody_ready_v25`
observou os quatro Started/Ready em execuções anteriores (1202 s e 1701 s).
A última linha e o exit code do segundo processo NÃO foram recuperados: o
handle 90221 já não existia. Portanto, não registrar essa execução como teste
comprovadamente verde. A primeira execução atingiu Ready mas falhou na limpeza
por SIGTERM; a limpeza do teste focado foi trocada pelo crash controlado depois
de observar Ready. Isso NÃO comprova claims/reopen nem os outros cenários.

Nesta continuação, o observador passou a ler tamanho, magic, estado, papel,
identidade da sessão, comprimento e checksum dos registros e a exigir igualdade
do vínculo Started/Ready. A leitura de Started por caminho exato quando Ready
aparece evita depender de uma enumeração de diretório atomicamente congelada.
São verificações estruturais; a autenticação do grafo continua a cargo do Store.
Dois testes curtos exercitam corrupção e mistura de grafos com checksum válido.

`DOM_RECOVERY_PHASE_V25` separa tempos locais de parent_signing, abertura e
assinatura Cancel/Compensation, completion_audit e custody_mount. Os antigos
47–68 s do timer externo NÃO provam sozinhos gargalo de rede nem ausência de
renovação interna de lease. Nenhum prazo de protocolo foi alterado aqui.

Ordem mais recente do usuário: deixar o teste avançar até o fim, sem interrupção
voluntária pela demora. Próxima execução é o cenário real completo de
claims/original-store reopen, com o runner e teto de 9000 s já usados pelo
heavy-tests.yml (não repetir o corte local de 1800 s). Compilar e conferir hash
do release antes. Evidência prevista: dom-xmr-evidence-claims-reopen-20260921-run18.
Não confundir Ready, saída planejada do teste focado, ou checagens curtas com o
verde integral do cenário. Não publicar antes da validação solicitada.

### Estado da execução integral atual

- Observador: 2/2 testes passaram; runner de evidência: 8/8 passaram.
- `cargo fmt --all -- --check` e `git diff --check`: passaram.
- Release terminou com exit 0 em 4m48s. Hash BLAKE2b-256:
  `213f3c363faf0e1bf981132e1177e663a78771cb529c3a1ab2dedfc44c216b1a`.
  `/tmp/branchcodex-local-xmr-env.vars` foi atualizado.
- run18 foi recusado ANTES de lançar qualquer daemon: o build emitira o
  executável com modo 775. Corrigido para 755. Próximos builds devem usar
  `umask 077` (ou verificar explicitamente o modo antes do runner).
- run19 iniciado pelo runner com limite 9000 s do workflow. Handle de terminal:
  `72975`. Evidência:
  `/home/leonardov/dom-xmr-evidence-claims-reopen-20260921-run19`.
  Polling do handle confirmou processo ainda aberto; ainda sem resultado final.
  NÃO reiniciar só porque a observação expirou; consultar esse processo e log.
  Ordem do usuário: deixar o cenário completar, sem interrupção por demora.

### run19 — acompanhamento após início real

A compilação crypto-test terminou em 4m43s, e a preparação fria em 184463 ms.
Os dois daemons foram lançados (export_and_launch: 11301 ms).
Aos 360 s de espera dos claims, observação dos arquivos originais mostrou:
Alice upstream/downstream = 18/18; Bob upstream/downstream = 18/17.
Os quatro pares de custódia ainda eram Started=0/Ready=0. Nenhum resultado
final: processo 72975 continuava ativo. Frozen consensus guard passou.
Raiz original de observação desta execução:
`/home/leonardov/.dx-v23/dx-57w9ql34/.tmpq8MtbE`.
Revisões observadas apenas por nomes `<session>-<20 digits>.session` em
`alice|bob/daemon-upstream_contracts|daemon-downstream_contracts/session-records`.
Sessão upstream: a1 repetido 32 vezes; downstream: d1 repetido 32 vezes.
Não abrir SQLite mutável ou duplicar proprietários para obter progresso.

### run19 — custódia bilateral observada, Funding ainda pendente

Aos 901 s, upstream de Alice/Bob tinha Started=1/Ready=1. Aos 931 s,
os QUATRO pares tinham Started=1/Ready=1, validados pelo observador reforçado.
Aos 961 s, todas as sessões estavam na revisão26; aos 1021 s, revisão27.
Aos 1081–1141 s, Alice e Bob estavam em upstream29/downstream27.
Ainda SEM claims finalizados e SEM resultado de teste: não declarar cenário verde.
Handle 72975 confirmado ativo. Manter o mesmo processo até o fim conforme ordem.

### run19 — avanço posterior ao corte antigo

Mesmo processo 72975, sem interrupção voluntária. Ambos chegaram a upstream30
por volta de 1382 s, upstream31 em 1652 s, upstream32 em 1983 s, upstream33 em
2313 s. Downstream permanece em 27. Os quatro Started/Ready continuam 1/1.
Funding, claims e reopen ainda não aprovados; esperar o desfecho atual.

PIDs dos daemons 1989798 e 1989802, filhos do test harness 1988308, foram
verificados contra device/inode do release em /proc/PID/exe; start_ticks
59913265 e 59913268. Ambos em estado R ao consultar; CPU média perto de 55%.
Isso não identifica sozinho a função custosa. Tentativa opcional de perf a
19 Hz por 10 s foi recusada pelo kernel (perf_event_paranoid=4) antes de
coletar amostras. Nenhuma configuração de kernel foi alterada. Não repetir
esse diagnóstico sem mudança de condição; não tratar arquivo perf como
evidência coletada. Continuar pelos logs e código, sem parar o teste.

### run19 — funding upstream publicado em ambos os atores

Mesmo handle 72975 ativo aos 3095 s de espera dos claims; não interromper.
Alice upstream/downstream = 35/28; Bob = 35/27 aos 3035 s.
Confirmada a existência de `session-artifacts/<session>.f7-v12-funding`
na perna upstream de Alice E Bob, ausente nas pernas downstream.
Atenção: esses artefatos ficam em session-artifacts, não session-rosters.
`complete_f7_funding_signing_v20` publica os bytes da transação assinada e
persiste o sucessor; existência do artefato NÃO comprova confirmação na rede.
Quatro custódias Started/Ready = 1/1; claims finais e reopen ainda pendentes.
Nenhum código, timeout ou processo do teste foi alterado nesta observação.

### run19 — downstream em revisão29 bilateral

Handle 72975 continuou ativo aos 3726 s (1h02min06s de wait_claims).
Bob downstream chegou a29 por volta de3275 s; Alice downstream a29 em3726 s.
Ambos upstream35/downstream29. Quatro custódias1/1. Ainda sem conclusão
dos claims, saída natural, auditoria ou reopen. Nenhuma interrupção/alteração.
Consulta de ps precisa require_escalated: sandbox tem namespace diferente
e pode omitir os PIDs. Fora dele, PIDs1989798/1989802 estavam vivos em3515 s,
CPU acumulada43m15/41m50. Não interpretar ausência no ps sandbox como término.

### run19 — leitura de custo durante espera, sem mudança de código

Handle72975 vivo aos4177 s; ambos35/29 e custódias1/1.
Candidato estático, NÃO gargalo medido: authenticate_xmr_bounded_f7_ancestry_v23
(f7_xmr_bounded_v23.rs:170) chama reconstruct_completed_xmr_graph_v23,
que chama diretamente reconstruct_xmr_graph_evidence_verified_v24, sem
passar pelo cache de reconstruct_xmr_graph_evidence_core_v23. Comentário
explica que complete consome templates e a reconstrução é owned/uncached.
Há caches internos de provas e semântica pública; não assumir que todas as
provas caras são refeitas. Três rounds são reconstituídos e auditados; a
autenticação de ancestry ainda audita cancel/compensation depois. Medir
os custos antes de escolher otimização; não relaxar autenticação/linearidade.
Não aplicar mudanças ou recompilar enquanto esta execução vai até o fim.

### run19 — espera verificada até4958 s

Handle72975 continua ativo. Ambos35/29, quatro custódias1/1; desde3726 s
nenhum novo avanço de revisão observado. Claims finais ainda pendentes.
Em4327 s ps fora do sandbox confirmou os dois daemons em Rl, CPU acumulada
54m43/52m07; isso prova atividade, não identifica loop ou função custosa.
Não interromper a execução atual, conforme última instrução explícita.

### run19 — espera verificada até6040 s

Mesma sessão72975 viva aos6040 s (1h40min40s de wait_claims). Ambos35/29
e custódias1/1; nenhum novo avanço de revisão desde3726 s. Em5439 s,
ps fora do sandbox confirmou ambos em Rl, CPU1h10m05/1h06m03.
Ainda não há claims finais completos, auditoria de saída ou reopen.
Manter este teste até seu desfecho. Nenhum código ou timeout foi alterado.

### run19 TERMINAL — falhou por deadline dos claims; investigar antes de novo teste

Sessão72975 terminou: runner exit1, cargo return101; result.json status failed.
Erro: real daemon claim observation reached its explicit deadline (7200 s).
Tempo libtest7438.84 s, runner7733.907 s. Sem interrupção manual. Os dois
exit status0 foram coletados na rotina report_stall/encerramento do teste;
NÃO comprovam sucesso econômico. Nenhum claim final/reopen aprovado.
Evidências: /home/leonardov/dom-xmr-evidence-claims-reopen-20260921-run19/
native_real_daemon_two_claims_survive_original_store_reopen_v23/.
result.json confirma dependencies_unchanged, cleanup_verified e
fixture_cleanup_verified=true; fixture_archive=synthetic-fixtures.tar.gz.
A raiz .dx original foi limpa pelo runner; usar arquivo arquivado se preciso.
Log SHA256 f117ddff7f310229fa883a00585706ed6633e0495df90d254332d0da5fde5f50.

Contagens dos dois daemons no test.log: downstream WindowClosed69, Staged2,
AwaitingPeer2; upstream Committed53, WindowClosed14, Staged12, AwaitingPeer8.
Janela:37 linhas open=true observers=open/open/open e37 open=false com
DOM=open, XMR=unavailable/unavailable. Causa específica de unavailable ainda
NÃO localizada: ProductionXmrDeadlineSourceV23::observe e observer_error em
production_height_timer_v23.rs são os próximos pontos. Não aumentar prazo.
refresh_funding_window_v23 em production_run_universal.rs fecha funding por
resto da rodada após falha; upstream é sempre atendido antes de downstream.

Custody profiling: leg0 custody_mount352 chamadas/3061.2s acumulados;
leg1 custody_mount324/1529.0s, total676/4590.2s entre ambos os processos.
ATENÇÃO nome do diagnóstico: quando já Custodied, step_xmr_graph_custody_v23
(production_relay_xmr_graph_v23.rs:229) chama custody.revalidate(), NÃO monta
novamente. Seguir XmrRecoveryCustodyV11::revalidate em
crates/dom-scriptless-store/src/runtime/linux/xmr_recovery.rs:274.
Outras phases são muito menores (parent_signing~210s acumulados etc).
Reconstrução sem cache identificada antes permanece hipótese secundária.
Nenhuma mudança de código aplicada desde início run19. Diagnóstico estático
segue antes de escolher correção e teste curto; não disparar outra sessão longa.

### RPC idle-close reproduzido em teste curto; correção em validação

Novo teste production_timer::height_v23::tests::
xmr_deadline_observer_survives_server_idle_connection_close_v25, em
production_height_timer_v23_tests.rs. Servidor HTTP keep-alive fecha socket
ocioso após300ms (fixture real usa5s); channel confirma fechamento antes da
segunda source.observe(). Cliente/observador real; cadeia inalterada.
ANTES da correção: 1failed em0.43s; primeira Ok(CanonicalTip1), segunda
Err(Unavailable). Compilação crypto-test4m10; sessão26286 terminou101.

Correção em production_height_timer_v23.rs: Source retém URLs/network/quorum;
cria pool HTTP dentro de cada observe() sob timeout60s. Reutiliza conexões
só dentro da observação; não carrega pool entre pausas de current-thread
runtime. Mantém checks genesis/quorum/tip. Sem mudança de prazo ou fixture.
Teste usa campos URLs/network/quorum atualizados. Não mudou release ainda.

VALIDAÇÃO EM ANDAMENTO: sessão94557, log /tmp/branchcodex-height-observer-v25.log.
Comando cargo test --locked -p dom-interopd --no-default-features --features
production --lib --profile crypto-test production_timer::height_v23::tests
-- --nocapture --test-threads=1; umask077 TMPDIR=/home/leonardov/.dx-v23,
require_escalated para sockets. Até última consulta ainda compilava.
Poll94557; não iniciar nova cópia. Nenhum full swap reiniciado.

Correção de referência do diagnóstico: custody do Relay é
ProductionXmrGraphCustodyV23::revalidate (production_xmr_graph_custody_v23.rs:142),
que chama XmrRecoveryCustodyV11::revalidate (barato), require_ready (reconstrói
grafo) e revalidate_xmr_ordinary_recovery_rounds_v11 (reconstrói novamente).
O custo medido676/4590s é desses wrappers, não só leitura do arquivo selado.

VALIDAÇÃO RPC CONCLUÍDA: sessão94557 exit0. 12 testes do módulo height_v23
passaram,0falhas, em4.92s de execução. Inclui idle-close antes vermelho.
Log /tmp/branchcodex-height-observer-v25.log. git diff --check passou.
Release ainda não recompilado, full swap ainda não reexecutado/não verde.
Próximo: custo de revalidação da custódia, com preservação de checks.

### Otimização local de reconstrução de custódia — validação em andamento

xmr_graph_custody_provisioning_v23.rs: graph_custody_record_v23 agora retorna
(scope, bytes, produced). require_ready_locked e prepare_provisioning usam
esse grafo recém-reconstruído em require_same_graph em vez de reconstruir
novamente logo depois. Auditoria de provisioning ignora terceiro campo.
Mesma operation_lock, sem cache entre chamadas, todas as comparações e
leituras Started/Ready mantidas. Nenhuma promessa de ganho total ainda.

TESTE ATIVO sessão6108: cargo test --locked -p dom-interopd
--no-default-features --features production --lib --profile crypto-test
v23_native_two_leg_templates_custody_ready_and_bounded_funding -- --nocapture
--test-threads=1. Log /tmp/branchcodex-custody-reconstruction-v25.log.
Umask077 TMPDIR=/home/leonardov/.dx-v23, require_escalated. Poll6108, não duplicar.
Teste existente cobre ciclo nativo, Ready/reopen e recusas de autorização;
não é o full daemon claims/reopen nem comprova o workflow inteiro verde.
Até último poll compilava. rustfmt do arquivo e git diff --check passaram.

Sessão6108: compilação terminou em5m36s; teste de componente começou
e segue ativo, ainda sem primeiro marco interno no último tail.
Guard scripts/check-consensus-unchanged.sh passou na base congelada
37d9da730b1a765671d2500fed940aeb2ecb5edd. Não confundir esta validação
de componente com o full swap, ainda não reexecutado após correções.

Sessão6108 ativa: fixture80.47s; C leg1=211.06s, D leg1=328.98s,
C leg0=539.52s, D leg0=718.87s. Depois: graph formation complete;
graph commitment position=0 accepted by both stores. Ainda sem resultado.
Tempos de proof fixture_restart_only=true não são latência real de daemon.

### Componente de custódia/funding APROVADO após otimização

Sessão6108 exit0: 1passed0failed,1441.42s de teste, compilação5m36s.
Log /tmp/branchcodex-custody-reconstruction-v25.log.
18 mensagens do grafo auditadas, dois grafos/reopen verificados; duas
custódiasReady e recusas aprovadas; seis envelopes funding, bytes idênticos,
reopen independente/custody loss/six replays passaram para ambos atores.
Funding subfase395.519s. Não é full daemon claims/reopen nem broadcast.
Correção RPC validada antes por12 testes. Próximo: build release atualizado,
confirmar modo seguro/hash no env, depois nova execução local claims/reopen
com runner e evidências novas. Não declarar os workflows verdes nem publicar
até a validação no escopo completo. Nenhuma mudança de timeout.

Release build ATIVO sessão37766, log /tmp/branchcodex-release-run20-build.log.
Comando umask077; cargo build --locked -p dom-interopd --no-default-features
--features production --release --bin dom-interopd. Poll37766; após sucesso
confirmar mode755 e recalcular BLAKE2b256 de target/release/dom-interopd e
atualizar hash correspondente no /tmp/branchcodex-local-xmr-env.vars sem
imprimir segredos. cargo fmt --all -- --check e git diff --check passaram.
Run20 completo ainda NÃO foi lançado.

### Run20 completo INICIADO — nova execução após correções

Buildrelease37766 terminou0 em5m01s. Binário mode755, BLAKE2b256
1f589e5ad4f45cdfe02e251e4ff323829062978107dde185df979e4263a5fbbc.
Hash atualizado em /tmp/branchcodex-local-xmr-env.vars.

RUN20 ATIVO sessão88403, result.json status running confirmado.
Evidências /home/leonardov/dom-xmr-evidence-claims-reopen-20260922-run20/
native_real_daemon_two_claims_survive_original_store_reopen_v23/.
synthetic_tmp /home/leonardov/.dx-v23/dx-0faj5boe (root interno ainda descobrir).
Comando runner mesmo run19: --timeout-seconds9000, scenario
native_real_daemon_two_claims_survive_original_store_reopen_v23, umask077,
source env com set-a; require_escalated. Não duplicar/reiniciar por silêncio.
Último poll88403 ativo, sem stdout novo ainda. Acompanhar até o desfecho.
Comparar downstream com run19, que parou em29 após upstream35. Nenhum
full swap verde comprovado ainda. Não editar/recompilar enquanto roda.

### Run20 em andamento: downstream ultrapassou o ponto da run19

Sessao88403 continua ATIVA, nao reiniciar/interromper. Root confirmado
/home/leonardov/.dx-v23/dx-0faj5boe/.tmpNIu9wN. Dois daemons PIDs2282773/2282777
(aparecem como comm=3); teste PID2281428. Preparacao168.025s, export/launch11.086s.
Custodia: Bob upstreamReady961s, Bob downstreamReady991s; quatro pares
Started=1 Ready=1 confirmados1082s. Aos2194s: Alice upstream35/downstream31,
Bob upstream34/downstream30. Ambos ultrapassaram downstream29 onde run19
ficou parada. Ultimo poll2254s, ainda aguardando claims, nenhum full green.
Nao concluir performance nem sucesso economico apenas por revisoes/Ready.
Monitoramento somente nomes de session-records, log do runner e ps; nenhum
store vivo aberto por segundo owner, nenhuma alteracao de codigo nesta espera.
Comando filename-only salvo functions.store(run20_progress_cmd).
Continuar poll88403 ate resultado e verificar result.json/cleanup/reopen.

Run20 checkpoint5139s (~85min30s da fase claims), sessao88403 ATIVA.
Alice upstream funding committed observado2279481ms; Bob2675784ms.
Downstream ambos ultrapassaram29; Bob35 aos3395s, Alice35 aos3546s.
Desde3546s ambos upstream35/downstream35, sem novas revisoes ate5139s.
Quatro custody Started/Ready1/1. Nenhum claim/funding downstream committed
reportado pelo observador ate ultimo poll. Em leitura SOMENTE nomes/mtimes,
quatro session-artifacts/*.f7-v12-funding existem, inclusive downstream
(Alice mtime01:46:17 e Bob01:43:53 em22set2026 no clock local da ferramenta).
Isso nao prova broadcast nem claims. Aos75min PIDs2282773/2282777 vivos,
CPU acumulada54:46/52:00. Logs de daemon ainda buffers internos do teste,
nao ler pipes ou bancos vivos. Instrucao usuario: NAO INTERROMPER; esperar
resultado terminal, sem rebuild/codigo alterado. Apenas handoff atualizado.

### Run20 TERMINAL: falha de deadline, nao foi interrompida manualmente

Sessao88403 terminou exit1; cargo101, 0passed1failed, libtest7451.67s,
runner7496.419s (~125min). Erro: real daemon claim observation reached its
explicit deadline. Fase launch_to_two_claims_and_natural_exit incomplete
elapsed7275263ms inclui fechamento diagnostico apos deadline7200s.
Result.json statusfailed, dependencies_unchanged/cleanup_verified/
fixture_cleanup_verified=true. Fixture preservada em synthetic-fixtures.tar.gz
no diretorio de evidencias run20; raiz temporaria removida pelo runner.
SHA256test.log b46bef9f091f96f905b2ab9c1f825b398c2452a54f711f2564bc9f6fd25aeb58.
Log final confirma fundingCommitted nas DUAS pernas: upstream65 ocorrencias,
downstream49; Staged12 cada; WindowClosed4/3, AwaitingPeer4/5.
Ultimas revisoes35/35 ambos, quatrocustodiasReady1/1. Ainda nao claims ou
reopen; nenhum full scenario verde. DOM_NATIVE_EXIT_DIAGNOSTIC code=unknown
para ambos no fechamento; nao interpretar como saida natural bem-sucedida.
Log tem sess_err acumulado relay e repetidas custody_mount ~7-10s; causas
atuais nao diagnosticadas ainda. Proximo passo deve ser leitura estatica
do caminho apos fundingCommitted ate claims/reopen, correlacionada ao log,
ANTES de qualquer novo teste longo. Nao repetir run20 cegamente nem aumentar
timeouts. Nenhum push nem execucao GitHub neste acompanhamento.

### Diagnostico run20 e correcao de reconciliacao XMR local

Run20 foi terminal (nao processo ativo). Leitura dos headers no arquivo
synthetic-fixtures.tar.gz: todas as quatro revisoes35 tem phase140
(FundingBroadcast). Copias SOMENTE DB route/coordinator e WAL/SHM foram
extraidas em /tmp/run20-route-inspection/{alice,bob}; originais intocados.
Route snapshots revision4/eventseq4 ambos. Outbox unico upstreamFunding
source_sequence3 status0 attempts14. Evento4 CustodyProgressRecorded.
Coordinator child0 DOM stage3 Externalized, child1 XMR stage2 CallPending
ambos; reconciliations child1 outcome3 Unknown11Alice/12Bob.

Erro de fluxo identificado por leitura: production_child_xmr::reconcile
tratava TODO funding como externo, consultando inclusao e retornando
Unknown para sempre. Funding LOCAL pode falhar em prerequisite/deadline
antes de broadcast e ficar CallPending; nao havia caminho de retomar envio.
Nao esta comprovado qual prerequisite da primeira tentativa falhou.

Mudancas novas: production_child_xmr.rs usa helper privado novo
production_xmr_funding_reconciliation_v25.rs. Se inclusaoausente e driver
recoverylocal autentico existe, chama externalize do MESMO dispatch.
Mesmo candidato privado, guards de collateral/window/lease e escopo.
Inclusao presente NAO reabre driver nem retransmite. Legacyexternal apenas
observa. RetryableBeforeExternalization apos ambiguidade vira Unknown,
NUNCA prova ausencia da tentativa anterior. Nao reduz finality/timeouts.

Primeira compilacao apontou tipo bool ausente no teste; corrigido.
Sessao86677 final0,13passed0failed em0.50s,build5m18. Log
/tmp/branchcodex-funding-reconciliation-v25.log. Ajuste final short-circuit
inclusion.is_none() feito durante build, requer validacao atual: sessao17506
ATIVA cargo test filtro production_child_xmr::, log
/tmp/branchcodex-funding-reconciliation-v25-final.log. Poll17506, nao duplicar.
Cargo fmt check sessao72416 passou; gitdiffcheck passou antes ultimahandoff.
Nenhum release rebuild apos essa correcao; release/env ainda hash run20.
Nenhum fullcenario verde e nenhum push/CI. Proximos: concluir testes atuais,
revisar necessidade de diagnosticos precisos no funding antes proxima longa,
release rebuild e somente entao validarcenario completo se necessario.

Validacao final17506 terminou0:13passed0failed em2.07s. Log
/tmp/branchcodex-funding-reconciliation-v25-final.log. Arquivo tar run20
nao contem xmr-funding-attempt-v12.bin (0 entradas): envio local nao chegou
ao marcador anterior a submit_exact. Ainda nao sabemos a primeira recusa
(window/deadline/collateral). Acrescentado diagnostico fechado
DOM_XMR_FUNDING_REFUSAL_V25 em window/deadline/collateral/broadcast/
observation/recovery, capturado pelo process.rs. Apenas stage constante
e enumChildAuthorityRefusalV1 sem payload/URL/segredo. Sem mudar retornos.
Build RELEASE run21 ATIVO sessao86497; log
/tmp/branchcodex-release-run21-build.log. Cargo build lockedproductionrelease
umask077. Poll86497; apos0 chmod755 e recalcular hash/atualizar env
DOM_INTEROP_REAL_BINARY_BLAKE2B256_V23 antes runner. Ainda NAO lancourun21.
Gitdiffcheck e consensusguard passaram aposdiagnosticos; rustfmt aplicado
nos3arquivos. Nao declarar fullverde: falta validar o fluxo real corrigido.

### Run21 completo INICIADO apos fix de funding local

Release86497 terminou0 em4m59. Binario mode755, hashBLAKE2b256
eb5fedbb7a3289328c1f937252c5cbd82e44f8f8cd8e051412ca9099a412bf79; env
DOM_INTEROP_REAL_BINARY_BLAKE2B256_V23 atualizado.
RUN21 ATIVO sessao41911, mesmo runner/scenario claimsreopen, timeout9000,
sem aumento de deadline. Evidencias /home/leonardov/dom-xmr-evidence-claims-
reopen-20260922-run21/native_real_daemon_two_claims_survive_original_store_reopen_v23/
(nome da pasta real sem quebra de linha). Ainda nao descoberto fixture interno.
Poll41911 atefim; nao interromper/reiniciar por silencio nem modificarbuild
emuso. Acompanha compilacao testbinary depois startup e faseclaims.
Correcaoretomadalocal13testspassed2.07s; novo diagnosticoguard compilou
emrelease e filtrostderr sera compilado pelo runner. Nao fullverde.

Run21 sessao41911 confirmadaATIVA. Compilacao testbinary terminou0
em5m46; running1test, fase cold_swap_preparation iniciou: preparing original
enrollment and funding owners. synthetic_tmp=/home/leonardov/.dx-v23/
dx-60yjbu_f (path sem quebra). Ainda sem lancamento dos daemons.
Continuar poll41911, nao reiniciar/interromper. Nenhum resultadoverde.

Run21 checkpoint1352s da fase claims: sessao41911 ATIVA. Preparacao
191.712s, export/launch11.836s. Root interno confirmado
/home/leonardov/.dx-v23/dx-60yjbu_f/.tmp8iIwWn. Teste PID2565946; daemons
PIDs2567750/2567754 (comm=3), vivos conferidos por ps. Inicio mais lento:
ainda rev0 aos240s, Alice9/9 Bob8/8 aos300s, Alice18/18 Bob18/17 aos390s.
Ambos25/25 aos1292s. Bob duasReady1262s; QUATROStarted/Ready1/1 aos1322s
e novamente1352s. Nenhum funding/claim final ainda. functions.store
run21_progress_cmd aponta root correto para nomes de session-records apenas.
Nao usar run20_progress_cmd. Sem alteracao de codigo/rebuild enquanto roda.
Poll41911 atefim, cumprir instrucoes de nao interromper.

Run21 checkpoint3666s: sessao41911 continua ATIVA; NAO interromper,
recompilar ou iniciar outro teste. Quatro custody Started/Ready1/1 mantidas.
Alice upstream33/downstream35; Bob35/35. Observer registrou actor1
upstream_funding committed em elapsed_ms3649727; nao implica claim final.
Nenhum claim final/reopen ou resultado terminal confirmado. Daemons
2567750/2567754 vivos e consumindo CPU na verificacao aos~54min.
Continuar acompanhando o mesmo handle ate desfecho. Nenhuma mudanca de
codigo/build/push neste acompanhamento; apenas leitura e este checkpoint.

### Run21 ENCERRADO SEM INTERRUPCAO: falha no prazo dos claims
Sessao41911 terminou exit1; cargo101. result.json statusfailed, libtest
0passed1failed812filtered,7465.61s; runner7823.143s (inclui build).
Erro: real daemon claim observation reached its explicit deadline.
Root de evidencias /home/leonardov/dom-xmr-evidence-claims-reopen-20260922-run21/native_real_daemon_two_claims_survive_original_store_reopen_v23/
synthetic-fixtures.tar.gz preservado; cleanup_verified,fixture_cleanup_verified
e dependencies_unchanged todos true. logSHA256
d65d5d63177ab10efbb074765b85857f963f5f9cb7c5aea9cc025af2a4a664c5.
QuatroStarted/Ready1/1 mantidas; quatro sessoes35 ao final. Bob funding
upstream committed elapsed_ms3649727, Alice4646154. Sem claims/reopenverde.
Diagnostico NOVO decisivo:14 linhas DOM_XMR_FUNDING_REFUSAL_V25, todas
stage=collateral refusal=Unavailable. Antes, aos~70min, zero arquivos
xmr-funding-attempt-v12.bin em ambaspartes (apenas glob,nunca DBvivo).
Um exitstatusSome0 signalNone observado; segundo unknown, nao interpretar
isoladamente como cenarioaprovado. Nenhum novo teste/rebuild/push iniciado.
Leitura iniciada production_child_xmr.rs1211 chama driver
verify_funding_prerequisite_bounded_v23(remaining), que driver.rs336 calcula
deadline,store.authorize_xmr_recovery_execution_v12,map_store, e
client.verify_funding_prerequisite(authority,custody,deadline).map_err(map_real).
PROXIMO: seguir essas chamadas/mapas de erro ate identificar origem exata
do Unavailable e ler restantefluxo antes nova compilacao/teste. Nao aumentar
prazo,nao relaxarcolateral. Objetivo geral continua ATIVO e nao verde.
Consulta ps escalada adicional expirou no autoreview; apenas monitoramento
adicional bloqueado, teste nao interrompido. Resultado do runner e logs
confirmaramfim. Nenhuma mudanca de codigo neste acompanhamento, sohandoff.

### Diagnostico Run21 e correcao de maturacao de colateral (2026-09-22)
PROGRESSO: leituracompleta child.externalize->driver.verify_funding_prerequisite
->Store.authorize->adapter.verify_xmr_funding_prerequisite->classify_graph.
Archivecopias publicas em /tmp/run21-collateral-inspection/ (history.sqlite e
DBcoordinator/routealicebob; originais nao abertosvivos). HistoriaDOM0..1005;
unica tx altura1004 coincide com DOMchild esperado nosDOIScoordinators.
Politica original xmr-policy-0.bin exige collateral_confirmations6 (decoder
crates/xmr-compensation-policy/src/lib.rs). Ledger confirma cadaadmissao so
deployment.finality.min_confirmations=2; cadeiafica1005 para sempre.
Logo InsufficientConfirmations eh bloqueioconcreto, independentemente de
outras possiveis recusas. XMRchildrenCallPending; reconciliacoesUnavailable
4Alice7Bob,maisumapendente cada. Novohelperreconciliation realmente tentou.

FIX somenteharness em4arquivos: production_xmr_native_mainnet_startup_v23_tests.rs
levalidapoliticas para termos deambaspernas; getter collateral_confirmations_v25.
production_xmr_native_daemon_scenario_v23_barrier.rs XmrLedgerPump guarda
depths e antespumpXMR usa NativeActionV23 DOMid apenasFundingparaconfirmar.
Snapshot.confirm_retained_funding_v25 lockledger, Evolving.funding_confirmation_target_v25
exigeledger.contains_transaction, buscaalturaoriginal nohistorydiskoumemory,
calcula targetincluded+depth-1 dentrobounds; appendcoinbases nativos.
Nao fabricatx/inclusao/finality; pending/ausente retornaNone; nao libera
barreira. Claim/refund/cancel seguemconfirmacoesoriginais. Novoalvo1009.
Nao alteroucodigoProductionbinario/timeout/politica/finalityconsenso.

Testes3novos passaram0.00s aposbuild4m03,sessao47274final0,log
/tmp/branchcodex-collateral-maturation-v25.log. Regressoes2->6,bounds,
fundingpendente/ausente nao avanca nemlibera,historycorruptrefusa.
Bateriaampliada32tests dom_snapshot:: e daemon_scenario_v23::barrier::
primeira sandbox26passed6failed: raiz / e /home uid65534 quebramguard
ancestry,e2socketsPermissionDenied. Semrelaxarguard,rerunrequire_escalated
sessao48616final0:32passed0failed6.86s. Log
/tmp/branchcodex-collateral-surrounding-v25-unrestricted.log.
Consensusguard congelado passou,gitdiffcheckpassou. Nenhumfullverde.
ProximoRun22mesmobinreleasehashrun21,fazsomente fixturetest recompilado.
Nao reexecutar componenteGPLpreexistente como prova de cenarioverde.

RUN22 ATIVO sessao58309. Runnerrequire_escalated autorizado, mesmo comando
com --evidence-dir /home/leonardov/dom-xmr-evidence-claims-reopen-20260922-run22
--timeout-seconds9000 --scenario native_real_daemon_two_claims_survive_original_store_reopen_v23.
Releasehash verificado pelo runner igualrun21. Cargo finished25.82s,
running1test, fasepreparacao iniciou. Synthetictemp /home/leonardov/.dx-v23/dx-grfegb8w.
PollMESMOhandle58309 atefim; nao interromper/reiniciar/compilarpor silencio.
Root interno ainda nao identificado. result.jsonrunning nao e prova de
processovivo sempoll. Ultimopollhandleconfirmadoativo. Nenhumfullverde.

Run22 checkpoint330s: sessao58309 ATIVA,pollconfirmadolive. Preparacao
186.259s,export/launch15.016s. Root /home/leonardov/.dx-v23/dx-grfegb8w/.tmpMT61IL.
functions.store run22_progress_cmd aponta esse root (somente filenames).
Rev0 ate180s;240sAlice5/4Bob4/4;270sAlice10/10Bob10/9;330sAlice16/15Bob15/15.
Custodystartedready0/0todas ainda. Nao entroufunding/claims/reopen.
Semmudancacodigo/build/push duranteexecucao. Mantermesmo58309atefim.

### Run22 TERMINAL: 0x17 chega antes do gate local (sem novo teste iniciado)
Sessao58309 terminouexit1,cargo101. libtest1285.42s runner1318.173s.
Falha realdaemonexitedunsuccessfullybeforefinalclaims; cleanup/fixturecleanuptrue.
Evidencias run22/native_real_daemon_two_claims_survive_original_store_reopen_v23/
na raiz /home/leonardov/dom-xmr-evidence-claims-reopen-20260922-run22.
Ultimo fluxo1090.824s(~18min),custodyAliceambasReady992s,BobupReady1052s,
BobdownsemReady. Alice26/26,Bob25/25. Bob saiu1code route_runtime,
site relay_half_before_observation -> inboundRelay -> Contracts Store
sessiontransitionrejected. Aliceexit0durantecleanup nao significaaprovado.
Mesmo releasehashrun21; fixcolateralnaoexercitado ainda(semfunding).

EVIDENCIAEXATA arquivocopiado em /tmp/run22-relay-inspection/: Bob
daemon-upstream_relay_inbox/route-inbox-v1.sqlite3 rowordinal15
relayseq14 delivery_state0, DSC1 nooffset294, kindbyteDSC+6 =0x17.
Rowanterior14seq13appliedkind0x0e. Downstreamultimarow14kind0x0eapplied.
Archiveinventario: Aliceambos .f7-v12-gate presentes; Bobnenhumgate;
Bobup custody-started+ready presentes; downnenhumcustodymarker.
Logo primeiroReadyToFundAlice chegouantesgateF7Bob e caiu no
accept_unseen com ingress antigoXmrGraphSigning -> StoreInvalidTransition.

LEITURA: relay_worker.rs accept_signed_dsc1 primeiroaccept_transport_message_derived;
InvalidTransition tenta waitsrefund/template/finalclaim/funding0x0c; nao
existewaitde0x17. accept_unseen usa autoridadeantiga.
production_composite_loop.rs step_local_bootstrap_with_renewal e
poll_retained_inbound_renewing: monta custody via step_bootstrap, sochama
step_f7_readiness se recovery_mounted_for_readiness=true. Runtime
production_run_universal.rs1845 service_relay vemANTES1853
activate_xmr_recovery_for_readiness_v25; gatecriado pelaativacao.
Mesmoordemlocalajustada,peerpodeantecipar0x17antescustody/gate,exigewait
autenticado estreito semaceitarvoto/ACK ou assinar. Ainda NAO implementado.

Proximoleitura/implementacao: predicateStore xmr_readiness_awaits_handoff_v25
(sugestao,naodecisaofinal) validar chain/session/firstroster.sender/seq/transcript
assinatura/payloadcanonical, faseRefundSigning e parentterminal
binding.start.rev+6, ancestry nativacompletada, gateausente,semfunding/abort.
Nao simplesmente converterInvalidTransition emretry. Se gateexistee
ingressinstaladodeveacceptnormal. Ready digest soaceito pelaautoridade
realposterior. Idealvalidardigestderivadoseviavelfuncoesexistentes.
Look f7_xmr_bounded_v23.rs prepare_or_resume_xmr_bounded_f7_gate_v23
e f7_v12.rs prepare_next_f7_ready_vote_locked_v12: voter roster.participants[0],
sequencenexttransport,transcriptahead25. ready_digestf7_v12.rs1285
excluicustodyidlocal, incluifamily,roledigest,bp,recovery,graph,cancel/comp
setupbinding/fundinghash,graphbinding/policy/refundbytes.
Novoerro ingress deve entrar classifier enum (production_composite_failure_v25.rs)
e retry classification production_composite_loop.rs1968, commensagenarrow
waiting, testesfocused. FundingHandoff existente cobre0x0c somente.
Nao rodoucompilacao/testenovo aposfalha. SemalteracaoProductionnesse
acompanhamento. Goalativo,nenhumfullverde,seguirleiturafluxoantescompilar.

### Implementacao da espera estreita Ready0x17; replaycurto compilando
NovoStoremethod xmr_readiness_awaits_gate_v25 em f7_xmr_funding_wait_v23.rs.
Recebe handlePreparedXmrGraphSigningIngressV23 antigo REAL: exigegateausente,
faseRefundSigning,semfunding/secret/abort; require_xmr_refund_ingress_terminal_v23
validaopening/store/edgeRefundAdaptor,start+6=currentrev,6msgsautenticadas.
Valida identidade/scope/primeirovotante roster,seq/transcript atuais e assinatura,
payload32nonzero. Naoaceitavoto,nemcriareceipt/gate. Digestreadiness deve
ser validado depois pelo gateautentico; essaesperanao concedeautoridade.
relay_worker.accept_unseen varianteXmrGraphSigning retorna novoerro
AwaitingNativeXmrReadinessGateV25. Classifierfailure tagreadinessgate,
compositeloop is_funding_handoff_awaiting inclui novoerro nas3 rotas;
testeclassifier positivo adicionado. Arq xmr_graph_signing_transport_v23.rs
foileitura e modificado temporariamente mas methodmovido,verdiffantespublicar.

Teste manualignored NOVO production_xmr_readiness_handoff_v25_tests.rs,
incluido via relay_worker mod readiness_gate_v25_tests. Naoexecutado
nosworkflowsregulares(exatoscenario,nenhumignoredalllibinterop). Exige
DOM_XMR_READINESS_REPLAY_V25 apontandocopiaprivada. Fixturepreparada
/home/leonardov/.dx-v23/run22-readiness-replay-v25: somenteBobupContracts
archivecopy,budget.bin(originalnative-contracts-budget),ready.dsc1(245bytes
DSCextraidodeinboxrow15),local-id.binpublico. NAOabriroriginaisvivos.
TesteabreStorecomTrustedChainMainnet+budgetoriginal,preparaingressREAL,
instalanoportREAL,accept_unseen votovalidodeveerroestreito;alteracoes
chain/session/sender/sequence/transcript/payload/signature devemfalhar;
comparastatebytesunchanged e gatecontinuaausente. Semclaimsfullproven.

Build11379 terminou101helperprivateload_f7_gate: methodmovido para
f7_xmr_funding_wait_v23.rs (descendantf7_v12),usando prepared.session_id().
Recompile/replay ATIVO sessao5697. log /tmp/branchcodex-readiness-replay-v25.log
Commandenvroot acima +TMPDIR.dx-v23 cargo test --locked --offline -pdom-interopd
--no-default-features --featuresproduction --lib --profilecrypto-test
relay_worker::readiness_gate_v25_tests::archived_first_readiness_waits_without_accepting_or_mutating
-- --ignored --exact --nocapture --test-threads=1 (flags separadosrealcmd).
Poll5697atefim,NAOrecompilarsimultaneo. Prodrelease AINDAhashrun21semfix0x17;
precisarebuild aposreplay e regressionscurtasantescenario.
Semnovo longrun aposrun22. Consensusguardpassou,gitdiffcheckpassou.

Recompile5697 final101 APOS compilacaobem-sucedida4m40: replay0.45s
Quarantined. CausaCOPIA incompleta:extracao manual sofilesomitiu
2emptydirs session-artifacts/session-consumptions. Restauradas da
listaarquivo(originalintacto),semalterarStorecode/testassertions.
RerunEXATObinariosemrebuildrequire_escalated67372 final0:1passed0failed
10.65s. /tmp/branchcodex-readiness-replay-v25-complete-copy.log.
AreadyvalidaficaerroAwaitingNativeXmrReadinessGateV25;7alteracoes
scopes/seq/transcript/payload/signature recusadas;sessionbytesunchanged;
gatecontinuaausente. Nenhumvoteaceito/capacidadefabricada.
Regressionscompositeloop+relay_worker91770 final0:38passed0failed1ignored
(manualarchivetestjafoirodadoseparado),6.60s. Log
/tmp/branchcodex-readiness-runtime-regressions-v25.log. Gitdiffcheckpassou.
ReleaseRUN23build iniciado(log /tmp/branchcodex-release-run23-build.log),
cargo build --locked --offline -pdom-interopd --no-default-features
--featuresproduction --release --bin dom-interopd. Obterhandleultimatool.
Aguardar0anteschmod755+hashBLAKE2b256+envupdate; nenhumRun23fulliniciado.
Naoalterarbinarioemuso(naoha testescenarioativoagora).

RUN23 release finished successfully 6m09s; blake2b256 df02e80444662bec6907c8f8a83e61b54388026dc8e9bd52e6c1bed4107dbceb. Private env hash updated. Full claims/reopen run23 STARTED, session 88086, evidence /home/leonardov/dom-xmr-evidence-claims-reopen-20260922-run23. User explicitly requests allow this test to finish; no interruption, unchanged timeout9000 runner/7200 claims. Poll88086; do not duplicate, mutate production binary or original stores.

RUN23 ACTIVE session88086, no interruption. Fixture /home/leonardov/.dx-v23/dx-bzryx7q7/.tmpbidyVL. Preparation232.684s export14.250s. At runtime2674s Alice revisions31/31 Bob32/32. All4custodyReady and all4F7gates reached ~1682s; beyond run22 failure. Funding signing records all4, no economic funding/claim completion yet. Monitor filenames session-records only, use harness log custody counts (custody markers nested, not direct artifacts). No live DB open, no code mutation/rebuild during test. Poll88086 until terminal, updates~30s userexplicit.

RUN23 stillACTIVE session88086 at~5400s. Allsessions35, all4custodyReady. BOTHupstreamfunding committed Alice3399062ms/Bob3438925ms -> BOTHexternalized4413s -> BOTHFINAL4995s. BOTHdownstreamfundingCOMMITTED5284s. No finalclaims yet, no naturalexits/reopen. Let currenttestfinish, userexplicit nointerruption. Lastprocprobe bothR CPU2648/2483s at~3900s. No source edits during test.

## RUN23 latency investigation while running — operator requested no interruption
Read-only diagnosis, NO production source edits, rebuild, new test, or daemon signal.
perf record 19Hz 8s attempted; kernel perf_event_paranoid=4 denied all events (session77301 exit255). No sysctl/capability changes. Empty /tmp/branchcodex-run23-perf.data, not a profile.
Measured /proc at~5900s: Alice CPU4554.33s read_calls90818155 physicalread2793472B; Bob CPU4429.59s read_calls85804536 physicalread8032256B. At~6040s Alice user3584.03s kernel1081.40s; Bob user3496.83s kernel1046.38s; bothR. ~23% kernel/~77%userspace CPU. Counters establish substantial CPU and cached I/O, NOT per-function timing.
Static confirmed chain: f7_v12.rs authorize_xmr_recovery_execution_v12:1744 -> authenticate_f7_gate_v12:581 -> authenticate_f7_gate_ancestry_v12 -> f7_xmr_bounded_v23.rs:170 authenticate_xmr_bounded_f7_ancestry_v23 -> reconstruct_completed_xmr_graph_v23 once -> require_xmr_graph_custody_ready_locked_v23:196 -> graph_custody_record_v23:346 -> reconstruct_completed again. Then authorize itself explicitly reconstructs a third time for bounded_refund_pre_signature (f7_v12.rs:1765). No count beyond this lower bound asserted.
Completed reconstruction xmr_graph_completed_reconstruction_v23.rs:14 directly invokes reconstruct_xmr_graph_evidence_verified_v24 bypassing core cache (ownership/consumption comment explicit; do NOT blindly clone linear objects/use stale authority). Reconstructs2publicoutputjournals+3signedrounds. Individual public proof checking ALREADY has exactbyte cache at xmr_graph_output_journal_v22.rs:318; do NOT claim every Bulletproof verification repeats.
load_session_locked session_store.rs:12404 reads ALL historical revisions + validates successor chain every call. audit_xmr_graph_signing_round_at_v23 scans/authenticates messages; authenticate_transport_record:14608 reloads roster+identity and signature per record; revisionfile separatelyread. read_bounded_file linux.rs:1149 opens/reads/identitychecks eachtime.
Normal root run_universal.rs:1825 serial relay/readiness,height,pumps(eachremote+normal),perleg up to8 funding+claim+receiver passes,thenroutehalf2083. funding_runtime_v20.rs:68 repeats retainedgate,readyvote,resumecommitted even terminalfunding. Each repeats gateancestry; graph result returned by ancestry is discarded by wrapper. Recovery driver:336 starts60sdeadline BEFORE Storeauthorize, then scanner; repeated expensive CPU can age evidence/deadlines; actual timeout attribution unproven until diagnostics.
Safe optimization candidates AFTER currenttest: reuse freshly authenticated producedgraph WITHIN exact same locked operation and thread its result into custody check + authority assembly; skip redundant public reverification only with exactbytes/scope and preservedguards; phase-aware suppression of completed work only after staticcallchain review. No deleting authentication or expanding deadlines.
Run23 at~6040s: BOTHupstreamfundingFINAL4995s; BOTHdownstreamCOMMITTED5284s; BobdownstreamEXTERNALIZED5879.525s. Alice externalized/finalclaims not observed yet. Session88086 active: continue until terminal.

RUN23 TERMINAL session88086 exit1, cargo101, FAILED deadline: "real daemon claim observation reached its explicit deadline". No manual interruption. Test7519.52s runner7605.822s, launch_to_claims incomplete7278.423s. Evidence result.json+test.log+synthetic-fixtures.tar.gz under /home/leonardov/dom-xmr-evidence-claims-reopen-20260922-run23/native_real_daemon_two_claims_survive_original_store_reopen_v23. cleanup_verified/fixture_cleanup_verified true; dependencies_unchanged checked result. logsha2565a88fee3ab5d180570a2d456ebb6ab59d283e4d811dd99166b5ed034d8084e5b.
Finalobservedupstream fundingFINAL both4995s; downstreamBobexternal5879.525s Aliceexternal6304.819s BobFINAL6757.457s, AliceFINALnotobserved; no claimcompletion or originalstore reopen. PriorRelayrace notreproduced:all4custody/gates andfundingsigned35 reached. No collateralUnavailable diagnostics;3observationUnavailable only. Do not claimallgreen.
FINALdaemonstderr timing evidence:537custody_mount entries>=1s (instrumentation threshold), sum4253.253s acrossbothparallelprocesses NOTwalltime. Block0 count268,sum2127.861s;Block1count269,sum2125.392s. Max14.840s. Parent signing176entries sum428.45s,completionaudit4sum12.88s. These measurednamedscopes do NOT cover entiretest, no perfunctionprofile.
Exact measuredpath relay_stage12.rs:371/517 -> relay_xmr_graph_v23.rs:229 Custodied fastbranch actuallycalls custody.revalidate -> production_xmr_graph_custody_v23.rs:142 custody.revalidate + Store.require_xmr_graph_custody_ready_v23 + Store.revalidate_xmr_ordinary_recovery_rounds_v11. Store ready path audit_transport then graph_custody_record -> fullgraphreconstruct. activate_recovery_v23:49 calls self.revalidate BEFORE funding_gate.is_some guard, hence repeats afteractivation too. This is confirmed unnecessary repetition candidate; removing anyguardblindly NOTauthorized optimizationstrategy.
Latestoperator requested investigate latency WITHOUTinterrupt. Fulfilledread-onlydiagnosis and monitoreduntilnaturaltestdeadline. No sourcecodeedits in this turn;onlyhandoff + earlier releasechmod/privatehash forrun23. No newlongrunstarted. Before any next test staticread remainingfailurepath; optimize measuredrevalidation via exactscopedreuse preservingallguards, shortadversarialtests first. Currentarchive is source ofpostmortem, no original/liveStore existsaftercleanup.

## Gate/recovery graph reuse after terminal run23
Currentgoalturnprogress: implementedsameoperationreconstructionreuse, nofullscenario since23.
1) custody_provisioning reconstruct_ready_xmr_graph_locked_v25 returns freshly reconstructed producedgraph AND checkedstarted/readyscope. Existing public require_ready stillcomparescallergraph. f7_xmr_bounded authenticateancestry callsnewmethod insteadof reconstruct+require_readyduplicate. NO crosscallcache/newauthority/guardsremoved.
Manualarchivedgate test copied Aliceupstream205files+emptydirs+budget fromrun23 into /home/leonardov/.dx-v23/run23-gate-replay-v25. Tests livegate, corrupt/missingstarted/readyrecusals, nofabricatedmarker, sessionunchanged. Firstversion session9902exit0 compile5m39,test1passed47.37s log/tmp/branchcodex-ready-gate-reuse-v25.log.
2) f7_v12 authenticate_f7_gate_with_graph_v25 helper returns gate+freshgraph. Oldauthenticatewrapper discardsgraph asbefore; authorize_xmr_recovery_execution reuses graph instead of reconstructingagain. Bounded gateancestry now1reconstruction instead2; recoveryauthgraph portion1 instead3. Preservecommit/custody/policy/finality checks.
Expanded sameignoredmanualtest with real copiedcustody and key32bytes fromarchivedAliceupstream. Private rootcustody/,key.bin NEVERprint. Test actualrecoveryauth scope/session/hash; nofreshXMRobservationmanufactured; corrupted/missingmarkers refuseauth too; restorecopy; samefundinghashafter. Productionkeymaterialneverchanged.
SECONDtest/build ACTIVE session80245 log/tmp/branchcodex-ready-authority-reuse-v25.log, command DOM_XMR_GATE_REPLAY_V25=root TMPDIR=.dx-v23 cargo test --locked --offline -pdom-interopd --no-default-features --featuresproduction --lib --profilecrypto-test relay_worker::readiness_gate_v25_tests::archived_ready_gate_revalidates_original_markers_after_every_read -- --ignored --exact --nocapture --test-threads=1. Requiressandboxescalation forancestry. Polluntilterminal; do NOTduplicatecompile.
Rustfmt4relatedfiles skip_children,gitdiffcheckpassed,consensusguardpassedafterchange1. NoReleasebuild/push/GitHub/run24 yet. Continue remainingbottlenecks and shortregressions beforeanotherfullrun. Goalnotgreen.

SECONDtest80245 terminal101 compiletestonlyerrorE0308 Arc<Dir> wherecustodyopenrequiresDir. Fixedparent.try_clone() preservesdircapability. Rerun23576exit0 compile5m13 actualtest48.03s1passed. Log/tmp/branchcodex-ready-authority-reuse-v25-fixed.log. 38runtimeRelayregressions26795exit0 7.44s log/tmp/branchcodex-gate-reuse-runtime-regressions-v25.log;7F7+fundingreconciliation3946exit0 4.29s log/tmp/branchcodex-gate-reuse-funding-regressions-v25.log. Consensusguardpassed.
NEXT thirdreuse IMPLEMENTED xmr_round_audit_v11.rs: bounded ordinary recovery audit first authenticates originalterminal, then if currentadvanced/fundingauthorized calls reconstruct_ready_xmr_graph_locked_v25 obtaining freshgraph+scope ONCE insteadreconstructthenrequireReadyreconstructagain. Original allgraph/policy/exactbytes/scope comparisons preserved. PrefundingatUterminal path stillreconstructsonly withoutreadyrequirement. Noaudittransportremoval, no crossoperationcache.
Manualarchivedgatetest expanded to retainedgraph+role, nativeordinaryaudit token,revalidateoriginal,and corrupted/missingmarkers refusalforordinaryrounds too. THIRDbuild/test ACTIVE21850 log/tmp/branchcodex-ready-rounds-reuse-v25.log command samearchivedgateexacttest. Polluntilterminal,donotduplicate. Firstapplypatch testhunk mismatchdueformat (noedit), correctedsecondpatch. Rustfmt+gitdiffcheckpassed. No fullrun/release/push.

THIRDtest21850 exit0 compile6m16s,1passed56.68s log/tmp/branchcodex-ready-rounds-reuse-v25.log. Final45regressions8098exit0 12.59s log/tmp/branchcodex-graph-reuse-final-regressions-v25.log (2ignoredmanualtests explicitlyrun). Original0x17archive replay49217exit0 1passed9.80s log/tmp/branchcodex-graph-reuse-original-readiness-v25.log. Gitdiffcheck+consensusguard63304exit0. Allshortchecks green,fullscenario stillunproven.
ReleaseRUN24 build JUSTSTARTED /tmp/branchcodex-release-run24-build.log getsessionfromlasttooloutput. No testscenarioactive. Waitbuildterminalsuccess beforechmod755/hashprivateenvupdate. Thenfullclaims/reopen run24 necessaryintegration of3hotpathoptimizations; unchangedtimeout9000runner/7200claims. NeverclaimnativeGPLasnewgreen. NoGitHubpush/actions.

RUN24 ACTIVE fullscenario session58364. Releasebuild18359 exit0 5m12s,hash ab50232675e2d691501b5e4a3507c47dced83bb6ed09c23f18eb1f2fbbdc9151;chmod755 andprivateenvhashupdated. Evidence /home/leonardov/dom-xmr-evidence-claims-reopen-20260922-run24. Same9000runner/7200claims deadline. Monitoruntilterminal,updates30s. NOsourceedits/rebuild/releasechanges whileinuse. Run23terminalfailed,doNOTpollold88086. Threeoptimizedreconstructionpaths testedactualarchive +45regressions +originalreadinessreplaygreen,butthisfullscenario NOTyetgreen. Other2realdaemonjobs/heavy/interopfull remainunproven. NoGitHubpush/actions.

RUN24 continuation latency read-only investigation: session58364 STILL ACTIVE, fixture /home/leonardov/.dx-v23/dx-1990uj4n/.tmpIFNcZX, daemon PIDs3189232/3189236. Preparation188.109s (run23 232.684s), export14.225s. At harness210s all4sessions revision0, custody0/0; no finalclaims or error. Do not treat initial timing gain as graph optimization proof. No source edits, rebuilds, interrupts, duplicate tests, or GitHub activity in this continuation.
Read-only /proc samples earlyrun24: Alice user8.32s kernel1.22s, Bob7.39s/1.14s; both physicalread0; writes~10MB each. Bob D/wchan jbd2_log_wait_commit, Alice S/hrtimer_nanosleep. Four further snapshots every5s (sampler4956 completed0) observed Alice journalcommitwait at samples0,2,3, Bob atsample1. Final CPUtotals14.53s/13.35s. This establishes disk journal durability waiting at observed instants in INITIAL phase, NOT a percentage/profile nor cause of entire run. Later run23 heavy CPU/graph checks remain separately established. No fsync/durability guard removed.
Static reread confirms custody revalidate before funding_gate.is_some, alreadyCustodied branch revalidates; production_funding_runtime_v20 step_f7 validates gate+readiness BEFORE committed-return, load_session_locked scans all revisionfiles and successorchain eachcall. Current3reusefixes address some reconstruction duplication; further phase-aware optimizations only after run24 terminal and complete failclosed analysis. Current mission active (get_goal), no green claims yet. Continue poll58364, monitorfiles/harness every~30s; do not poll ended4956 or oldrun23.

RUN24 verified-wait continuation: session58364 confirmedLIVE by poll at harness571s. Revisions progressed from0 ->8 ->12/13 ->17 ->19 -> now Alice21/19 Bob20/20 (upstream/downstream). Allcustodystarted/ready markers remain0. No reportedfailure, claims/funding unprepared. Do not restart/interrupt; fullscenario stillrunning. Reread full claims terminal assertions: bothnativeclaimsfinal+normalexit, stoppedcoordinatornativefinality/nonaliasidentity, originalStoresrestart and heartbeat/newexit, economicstate/secret/binding exactequality. These remainrequired, notyetproven. Process.rs drain_live continuouslydrains evenpast256KiBcapture limit, so fullstderrpipe duecapturelimit is not supported aslatencycause. Source unchanged, handoffonly. Continue same58364.

RUN24 IMPORTANT PROGRESS: session58364 STILL ACTIVE, lastpoll at harness1232s confirmsALL4custody started=1 ready=1. Timelinefromharness: Aliceupready1142s, Aliceboth1172s, Bobboth1232s. Run23all4ready1682s -> current1232s, observed450s(7m30)earlier; do not attributeentirevariation to3optimizations orclaimfullgreen. RevisionsAlice26/26 Bob25/25, all8auxsessions revision6. Mainpublicsession IDs upstreama1*32 downstreamd1*32; auxiliarysessionssharephysicalContractsStore; monitor per-session filenames only. Saved functions.store key run24monitor command printsperlegmain+aux+latestharnessline; safe readonly.
Sampler74664 completed0 (four5s /proc samples around11min): AliceCPU116.34->124.48s, syscr3.365m->3.632m,physicalreads528384->638976; BobCPU107.08->110.55s,syscr3.199m->3.333m,physicalreads200704->204800. AlternatingR/D/S states, __wait_on_buffer/wait_woken/nanosleep; notenoughforoverallphaseCPUpercent. Samplerdidnotsignal/attach/changeanything.
Source unchanged inthiscontinuation. Fullteststillneedsexactreadiness/funding/claims/naturalexit/reopen; no testpassyet. Continue58364 untilterminal, NOduplicate/interrupt/rebuild. Otherrealdaemoncases +fullworkflowrequiredscope remain.

RUN24 verified-wait at1803s(~30min), session58364 confirmedLIVE. Mainrevisions latestAlice33/29 Bob33/29; all4custodyReady remains1/1; all8aux6. Full log parsed economic progress events: none beyondnot_prepared. Nativefundingsigning progressing, nofundingcommit/publication/finality orclaims yet. No code changes/rebuild/tests/push during active scenario. Continue same58364.
AdditionalSTATIC latencyfinding: production_run_universal.rs:2098 terminal_continuation_rounds_v24 permits16extra FULLroute_runtime loops afterTerminal, each terminal branch also drain_terminal_relay_v24 (1589, up to16 rounds,breakafter2idle). Drain callsproduction_composite_loop.rs:497 step_terminal_relay_drain -> step_local_bootstrap_with_renewal so can repeatgraphcustodychecks. This is potentiallate latency; run24 hasNOTreachedTerminal, actualcostunmeasured. DoNOTremovecontinuation/ACKguards blindly; keepingpeerserved maybenecessary. Must measurecurrentrun throughendfirst.
Staticchecked nativeclaimstartup production_xmr_claim_bootstrap_v23: earlyreturn aftersecret/receiveracceptedfacts/finalprogress handlescompletedstates. A transientfreshanchorreturn beforetake_claim_share retainsvault; droppedconsumedauthorization releasesWeakprocessowner (session_store.rs11416), consume rereadsimmutableissuance andpublishesexactconsumption; boundedclaimbinding onlyaudits/publishesbinding andresumessession. No establishednewbug fromthisreview, no productionedits.

RUN24 verified-wait continuation at2434s(~40m34), session58364 confirmedLIVE. UpstreamBOTH35 reached~2283s, downstreamAlice34 Bob33now. AllcustodyReady,allaux6. StillNOeconomicprogress beyondnot_prepared (monitor nowparses allJSONeconomicphaseevents andprintslatestperactor/phase). No fundingcommit/publication/finalclaims yet. functions.store run24monitor updatedforJSONeconomicreading; samefixtureandPIDs.
Read-only /proc around32min: Aliceuser778.27s kernel257.46s readcalls23214369 physicalread3067904B D/jbd2_log_wait_commit. Bobuser727.96s kernel242.64s readcalls21792853 physicalread3268608B R. Observedheavycachedreads+CPU+durabilitywait, NOTperfunctionprofile. No source changes/interrupt/rebuild/newtests/GitHub duringthiscontinuation. Currenttestmustcontinueuntilterminal. Fullgoalnotgreen.

RUN24 verified-wait at3005s(~50min), session58364 confirmedLIVE. Firsteconomicprogress: upstreamFunding COMMITTED Bob2498.915s Alice2517.607s (~41m39/41m58), vsrun23 Bob3438.925s Alice3399.062s; ~15minearlier. COMMITTED meansdurablecandidate NOTexternalized/final. Noexternalized/finalorclaims yet. LatestmainAlice35/35 Bob35/33; all4custodyReady,all8aux6. Bobdown33 haspersistedwhileeconomicprocessing/CPUactive, doNOTinferdeadlockorfailurefromunchangedrevision; leavecurrenttestuntilterminal.
Read-only /proc ~45min: AliceR,user1271.45s kernel417.37s readcalls34899374 physicalread3555328B;BobR,user1199.52s kernel394.8s readcalls32985338 physicalread3846144B. ConfirmsCPU/cachedI/Ocontinues; notproofofproductiveprogress/noprofile. No interrupt, sourceedit/rebuild/newtest/GitHub. Handoffonly,gitdiffcheck. Continue58364+functions.store run24monitor (printsalllatestJSONeconomicprogress). Fullgoalstillunproven.

RUN24 verified-wait at3606s(~60min), session58364 confirmedLIVE. ALL4main35 by3095s(~51m35), allaux6/allcustodyReady. FIRSTpublication: AliceupstreamFundingEXTERNALIZED3516.878s(~58m37); BobstillCOMMITTED2498.915s atlastsnapshot. NOupstreamFINAL/downstreamcommit/claims yet. Run23Aliceexternal4413s vsrun24~3517s (~15minearlieroverall), BUTAlicecommitted->externalized999.271s(~16m39), similarold~1014s(~16m54): postcommitlatency NOTmateriallyimproved basedthismeasure. Do not attributealllatencygain tothreechanges orclaimfewminutes/fullgreen. Preservecurrenttestthroughterminal.
No sourcechanges/rebuild/newtests/interrupt/GitHub inthiscontinuation; onlyhandoff. Continue58364 and functions.store run24monitor, samefixture/PIDs. Goalactivefullscope.

RUN24 verified-wait at4237s(~70m37), session58364 confirmedLIVE. BobupstreamFunding EXTERNALIZED3813.170s(~63m33); AliceupstreamFunding FINAL4129.188s(~68m49). LatestBobupstillExternalized,AliceFinal. No downstreamcommit/claims yet. Allmain35/aux6/custodyReady. Preserveactivefullscenario; nointerrupt/newtest/sourceedit/GitHub.
Additionalstaticread claimordering: production_relay_downstream_claim_v23 observe_upstream_dom_revelation name misleading: only legUpstream consults downstreamgate; legDownstream returns true. production_xmr_downstream_claim_observation_v23 -> Store f7_downstream_claim_gate_v23 with_verified_downstream_dom_claim: absentclaimissuance/pre/facts/observation returnfalse; actualDOMscanner outsideoperationlock, exactsource/targetscopes and60sfreshness rechecked; no circularclaimdependency established inthispath. Do not callwholegoalgreen. Continue58364/run24monitor.

RUN24 verified-wait at4808s(~80m08), session58364 confirmedLIVE. BobupstreamFundingFINAL4426.289s(~73m46), so BOTHupstreamFINAL (Alice4129.188s). DownstreamFundingCOMMITTED Alice4442.102s(~74m02),Bob4727.079s(~78m47). BOTHdownstreamCOMMITTED; NOdownstreamexternalized/final/claims yet. Allmain35/aux6/custodyReady. No sourcechanges/rebuild/newtests/GitHub/interrupt inthiscontinuation. Samefixture/PIDs/58364; continueuntilterminal. Fulloriginalworkflowscopeunproven.

RUN24 verified-wait at~5379s(~89m39), session58364 confirmedLIVE thiscontinuation. AliceDOWNSTREAMFundingEXTERNALIZED5352.114s(~89m12), BobdownstillCOMMITTED4727.079s. BOTHupstreamFINAL. NOdownstreamFINAL/claims yet. Mainall35/aux6/custodyReady. Currenttestmustcontinueuntilterminal,doNOTinterrupt/restart.
Read-only buildcheck: Cargo.toml331release opt-level3,fatLTO,codegenunits1,overflowchecksTRUE; crypto-testopt2assertions+overflowTRUE. Run24releaselogexplicitFinishedreleaseprofileoptimized5m12. No debugprofilemisconfigurationfound; .cargo/config.toml path absent (rgreaderror, nochange). No code/build/test/GitHubmutation, handoffonly. Continue58364/run24monitor.

RUN24 verified-wait at6010s(~100m10), session58364 confirmedLIVE. BobDOWNSTREAMFundingEXTERNALIZED5914.767s(~98m35); Alice5352.114s, BOTHupstreamFINAL. StillNOdownstreamFINAL/routeclaimprogress. MainAlice35/38,Bob35/37. DownstreamCLAIM PREPARATION reached: BOTHsession-artifacts have exactpublished claim-issued,claim-consumed,claim-binding; no claim-pre/admission/exposure yet. Maindown36by5529s, both37by5739s,Alice38by5799s. DO NOTequatethese withfinalclaim. Nativeclaimscanner usesactualanchors so canadvancebeforecoordinatorrouteprojection logsfinalfunding (rootpumpsbeforelaterroutehalf).
Monitorfunctions.store run24monitor NOWprintsclaim marker kinds fromimmutablefilenamesonly (excludesdotstaging) foreachleg+economicJSON+main/auxrevisions. NOliveDBopened orfilecontentsread.
Staticfunding->claimresourcecheck production_funding_runtime_v20:304 release_funding_vault finishesrelayfundingsigning, takesfunding_signer returningvault into nativefunding_vault_v23 separately; provisioningfundingalreadyrequiresrefund_signerNone. No establishedresourceownershipbug inthisread. No sourceedit/build/newtest/GitHub/interrupt duringrun. Continue58364 untilterminal. Goalnotgreen,allremainingworkflowcasesunproven.

NEW STATIC BUG CANDIDATE CONFIRMED CONTROL FLOW (NOT observedrun24cause, noeditwhiletestactive): production_f7_runtime_v12.rs661-717 samplesclaim.universal_authority_recent_v12 andselectsUniversalRecent iftrue. Claim.step production_dom_claim_runtime_v12.rs284 firstrequire_owner (callsvalidate_dom_binding) THEN refresh rechecksat395 authority.can_reuse_observation_v12. Storef7_v12.rs2099canreuse elapsed+15s<=MAX60s (45sreuseboundary). Observationagecanpass45betweenfirstandsecondchecks -> refresh fallsintoScope at397. is_retryable103-123 returnsfalse forScope; F7RuntimeError delegatesClaimretryable androot treatsfatal. Thisis timingmarginraceevenwhenactual60svalidityhasnotexpired. DO NOTbroadenScope retries, extend60s, renewtimestamps, or weakenfreshness. Afterrun24terminal fixbyexplicit refresh-needed/deferred outcome beforeanyprivateoperation, reacquirefreshconcreteanchors; deterministicclock/boundaryshorttest shouldcoverbothsides45s andunchangedscopefailclosed. Needreadfullcallers beforeimplementation; no testsorchangesforthisyet.
RUN24 at6190s(~103m10) stillactive58364, mainAlice35/38 Bob35/37, downstreamclaimissued/consumed/bindingboth, nofinalclaims. BothupstreamFINAL,bothdownexternalized. Continueuntilexit; normaldeadline7200unchanged.

RUN24 latestverified-wait at6641s(~110m41), session58364 ACTIVE. AliceDOWNSTREAMFundingFINAL6439.684s(~107m19); BobdownstillExternalized5914.767. BOTHupstreamFINAL. MainAlice35/38 Bob35/37, claimmarkersdownissued/consumed/bindingboth, no claim-pre/exposure/final. ~10minuntiloriginal7200claimphasebound; DO NOTinterrupt norinferterminalbeforepoll. Letrunnercompletearchivecleanupbeforeanybuild.
/proc~105min: AliceR user3348.05s kernel1087.22s readcalls83524406 physicalread4153344B;BobS(wait_woken) user3224.27s kernel1047.22s readcalls80983305 physicalread4386816B. Heavyprocessing+cachereadscontinue,notproofproductiveprogress.
Staticchecks: relay_worker1263 finish_funding_signing onlytakesOperationalSigning withpurposeFunding, earlyreturnsforClaimingress; no accidentalClaimdisarmfound. f7_readiness_complete_v25 ->retainedgate->prepare_next_f7_ready_vote_locked(f7_v12:767) returnsNone/ready immediatelyifaccepted==2 BEFOREphasechecks; advancedclaimphasealonecannotcloseglobalreadiness. These hypothesesnotestablishedbugs. PreserveNEW45sreusemarginrace noteabove; needsnarrowrefresh-neededfix+shortdeterministicregression aftercurrenttestterminal. No sourceedit/build/test/GitHub/interrupt inthiscontinuation. Goalstillactivefullscope.


## RUN24 terminal and urgent latency work (2026-09-22 continuation)
User explicitly prioritizes latency optimization urgently, without removing necessary safety checks. RUN24 session58364 TERMINAL exit1; cargo101, failed7234.12s, runner7277.037s, cleanup_verified true, synthetic-fixtures.tar.gz saved. No manual interruption. Both actors both funding phases FINAL (Bobdown6788.134s); claim revisions Alice38/Bob37, no finalclaim. Terminal cause route_runtime -> draft.materialize_plain -> authority inconsistent, no SIGBUS. Full failure details remain in evidence test.log. Exact internal materializer cause NOT yet proven; no false assertion it is the freshness race. 572 logged custody_mount scopes sum3969.855s across2processes (NOTwalltime), max15.750s.
Static claim latency duplication: resume_post_anchor_dom_claim_signing_session_v12 required consumed handle, then bounded helper required SAMEhandle under SAMEoperationlock, then binding independently authenticate_f7_claim again. Implemented first narrow optimization: skip second full consumed-handle authentication in bounded resume only, retain second require_recent_observation(), call same locked session/binding/round helper (visibility widened internally, callers audited). Bind path unchanged. NOcrosscallcache, no freshness-window increase.
New manual cfg(test) f7_claim_resume_replay_v25_tests.rs under f7_v12: private archived Store authentication benchmark compares former3-auth path to optimized2-auth; rejects expired synthetic observation, wrong consumptiondigest, corrupted consumed/binding records; restoresprivatecopy and asserts sessionunchanged. Synthetic monotonic observation only for localbenchmark; NOTchainproof, NOsigning/staging/publication. Copy /home/leonardov/.dx-v23/run24-claim-replay-v25 (AliceDOWNcontracts and Alice native-contracts-budget.bin only) extracted fromarchive with0600/0700, no secretsprinted/liveaccess.
ACTIVE TEST session36689: cargo test --locked -p dom-scriptless-store --lib --profile crypto-test archived_claim_resume_cost_and_fail_closed -- --ignored --nocapture --test-threads=1, TMPDIR=/home/leonardov/.dx-v23 DOM_XMR_CLAIM_REPLAY_V25=/home/leonardov/.dx-v23/run24-claim-replay-v25, escalated. Log /tmp/branchcodex-claim-resume-cost-v25.log. CurrentlycompilingStore; noresultyet. Poll36689, do not rerunblindly. New code notfullyvalidatedyet. gitdiffcheckpassed. No releasebuild/newfullscenario/GitHub. Need address remaining duplicated custodyvalidation, confirmed terminalerror, narrow45sselectionrace afterbenchmark.

First latency optimization VERIFIED: session36689 terminal0. Manual archived claim resume test1passed,95.21s total (Storeopen/archive authentication included), compilation2m52. Measured baseline3953ms optimized1791ms (~54.69% lower in this one sample of local resume). Expiredsyntheticobservation, wrongconsumptiondigest, corruptclaim-consumed, corruptclaim-binding allrejected; privatecopyrestored; originalsessionbytesunchanged. No proof of total-swap speed/green. Readonlyprocess3452351finishednaturally betweenCPUcheck andthreadcheck; nointerruption. Fulltest58364alsoendednaturally. Nativecustody revalidate potential combinedsameoperationaudit remains toimplement/read carefully; first requireReady authenticates fullgraph templates, auditordinary repeatsReady-reconstruct butdoesnotitselfcomparealltemplates identically, so cannot simplyremovefirstcall. Need combinedStoremethod with sharedfreshgraph, preserving audit_transport, all graph byte comparisons and ordinaryscope check.

## Combined custody latency optimization in progress
Previous goal turn made progress: claimresume optimization passed replay (3953->1791ms). Next urgent optimization implemented in xmr_round_audit_v11.rs: split ordinaryaudit into publiclockingwrapper + private lockedhelper accepting optionalborrowed freshReadygraph onlyfromsameoperation. New public revalidate_xmr_ready_custody_and_rounds_v25 holdsoperationlock, audit_transport, reconstructReady, compares ALLoriginalgraphbytes via require_same_xmr_graph_v25 wrapper in custody_provisioning, exactcustodyscope, exactopeninstance, fullordinaryaudit using samefreshgraph, exactscope_digest. No crosscallcache/noClone/no guardremoved. ProductionXmrGraphCustodyV23::revalidate retains custody.revalidate thenusescombinedmethod insteadseparateready+ordinarycalls. Existing standaloneaudit unchangedsemantics withNone.
Extended archived_ready_gate_revalidates_original_markers_after_every_read tobenchmarkpreviousReady+ordinary vscombined andassertcombined rejects corrupt/missingStartedANDReady, restoresprivatecopy, originalsessionunchanged. Initialcompile21868exit101 onlymissingdoc(originalpublicmethoddocattachedtoinsertedprivatehelper), corrected. ACTIVE TEST34709 recompile samecommandas21868, log/tmp/branchcodex-combined-custody-cost-v25.log, privatefixture run23-gate-replay-v25 (unchangedoriginalarchive). Currentlycompilingdominteropd. Poll34709; doNOTstartfulltest/release/GitHub. Code unverifieduntiltestfinishes.
Static terminalinvestigation: discardedlegacyfallthroughhypothesis becauseactuatorf7_final_claim_progress_v21 checksretainedgate thenStoreprogress returnsNeedsAdaptation evenwithoutclaimpre. Newcandidate: Store final_claim_v14.rs1069f7_final_claim_progress insistslocaltransport signer==gate.role.dom_claim_sender; prepare_native_claim_child_v21 alwayscallsit. Needverifyroutehalf preventsreceiverparticipantfromattemptingClaim; BOTHactorsneednativeclaimsigningbutonlysenderexposes. NOTestablishedrun24causeyet. No changeforit. Earlier45sreusemarginracealsostillunfixed. Fullscopegoalnotgreen.

Combinedcustody replay34709 terminal0:1passed75.96s, compilation6m35. One timing sample baselineReady+ordinary7190ms versus combined5780ms (~19.61%lower). Corrupt/missingStartedANDReady rejected, originalsrestored, originalsessionunchanged. Firstcompileerror21868documentationonlyfixed. No fullswap claim. Duringcompile strongmemory/I/Opressureobserved1.5GBavailable, swapused~3.2GB, PSI IOfullavg10~68%; compilerlatency notproofswapcause. Scopepreservesfullgraphcomparison, transportaudit, ownership, custodyfiles,ordinaryproofs. Running short production_composite_loop::tests regressions log/tmp/branchcodex-combined-custody-regressions-v25.log via newexecsession; recordhandlefromtool. No daemonfulltest,releaserebuild,GitHub. Bothoptimizations now independentlyreplayvalidated; fullworkflowstillredunresolved.

Regression99063 terminal0:26production_composite_loop::tests passed0.00s usingcurrentcompiledbinary. gitdiffcheck+frozenconsensuscheckpassed. No activecurrenttesthandles remain(34709and99063terminal; oldrun2458364terminal). Continueurgentlatencyandrun24terminaldiagnosiswithout full2hrdiagnosticrerun. DoNOTmarkgoalcomplete.

Userauthorizedcleanupcompleted session34183exit0: removed ONLY target/debug/{incremental,deps,build,.fingerprint}, ~18GiB prior du. Preserveddebugdominteropdexecutable,release,crypto-test,eigenwalletartifacts,evidences,source. Userthenexplicitlyreturnedprioritymainmission; nofurthercleanup. Noactivecompilers/targetexecutables foundbeforedeletion. Mainterminaldiagnosiscontinues: receiver-to-sender-only f7_final_claim_progress candidate; needtraceactualpublication/observerpath, notestablishedexactfailureyet.

## RUN24 publication role diagnosis confirmed (2026-09-22)
New manual readonly test archived_claim_publication_role_diagnosis in f7_claim_resume_replay_v25_tests.rs, session96067TERMINAL0,1passed87.48s,compile2m45. Log/tmp/branchcodex-claim-role-diagnosis-v25.log. OnexistingprivateAliceDOWNrun24copy: local_is_sender=false,revision38,publication_progress=Err(InvalidTransition). Gate/issuance/signer authenticated; sessionbytesunchanged. This confirmsAliceisRECEIVER andsender-onlyprogressAPIrejectsher. RUN24log firstdiagnosticblocklines1604route_runtime+exit1,2331draft.materialize_plaininconsistent,secondblock2338unknown. report_diagnostics_v25 coldstart119iteratesprocessesAlice/Bob; Aliceisfailedactor. Bothfundingsfinalbeforefailure; claimpreabsent. Direct path prepare_native_claim_child_v21:104alwaysactuator.f7_final_claim_progress_v21 -> Storefinal_claim_v14:1069checks localsigner==gate.role.dom_claim_sender thenrejectsreceiver. No role-awareguard in materializerfirstexposure path found. Strongexactfailureexplanation, but testdidnotreconstructfullcoordinatorrequest.
Need COMPLETEreceiverobservationpath, notjustmapInvalidTransitionretryableorremoveguard. Currentcallchain: ProductionDomChildPort.materialize ->prepare_native_claim_child_v21 thenbind_final_claim_settlement_child_v2; latterContractscontracts513->retained_final_claim_transaction_id_v2:607->retained_f7_claim_transaction_v21:548 againSENDERonly+ownexposure/mirror. ExternalizeProductionDomActionAuthority BroadcastClaim production_child_dom424 AGAINcalls senderprogress+sameownerauthorityandbroadcast. validate_dispatch production_child_dom1329 alsoresumes samebinding. Existing nativeREFUNDobserverpath providespattern (native_refund_observer, retained_native_xmr_refund_settlement_child_binding). Need analogous verifiedF7receiverobservation-backedDOMchild with exacttransaction,sameStores,scopebinding,dispatch/reconcile/finality andoriginal-store-reopen tests. Bothactorsmuststillparticipate6signmessages; onlysenderpublishesDOMclaim. Receiver mustwaitforrealnativeobservation andmustnotmintsigning/exposurepermission, spoofsender, duplicateprivateorigin, claimgreenonretryforever. ClaimReceiver APIs in Storeclaim_receiver_v15.rs support facts+observedtoken. Userknowsrolehypothesisconfirmedonarchiveandworkcontinuing, notfixedyet. Noactive96067handle,noactivefulltest. Cleanup34183completedearlier ~17GiBfreed.

## Receiver settlement path: foundation and full-flow audit
Currentgoalturnimplements typedreadonly Storequery F7ClaimReceiverStateV25 {Sender,AwaitingObservation,Observed(ObservedF7FinalClaimV15)} plus f7_claim_receiver_state_v25(&PreparedF7FundingGateV12,chain,participant) in claim_receiver_v15.rs. Underoperationlock authenticatesgateancestry, localsigner+chain, fullF7artifactinventory, exactsender/receiverrole; onlyrealpersistedobservationreturnsObserved; otherwisependingreceiver; malformedinventorymusterror. No nonce/share/submission/finalitypermission. Exported throughf7_v12/sessionstore/linux/runtime/lib. Notyetwiredintodaemon, deliberatelynotmaskingreceiverfatalwithendlessretry.
Extendedmanualarchived_claim_publication_role_diagnosis toassertAliceAwaitingObservationwhileoldsenderAPIstillrejects, foreignparticipantrejected, corruptedgatefilefails(notwaiting), restoreoriginal+rechecksessionunchanged. Initial95724terminal101(E0432missingruntime.rsexport), fixed. ACTIVE31705 same Storemanualtest, log/tmp/branchcodex-receiver-state-v25.log, envDOM_XMR_CLAIM_REPLAY_V25=/home/leonardov/.dx-v23/run24-claim-replay-v25; noothercurrenttests. Poll31705, nofullrun.
FULLCHAINSTATICFINDINGS forcompletefix: prepare_native_claim_child_v21 -> sender-onlyf7progress; binding contracts.rs513->607->retained_f7_claim_transaction_v21 requiresownexposure+mirror; actionexternalizeANDreconcileproduction_child_dom424senderprogress+submission; validate_dispatch1329samebinding; observe_native_claim_settlement_finality_v15(final_claim_v14:450) startsrole-neutralfactsbutthenexposed_f7_final_claim_facts/require_f7_final_facts/retained_final_claim_identity allsender-only. revalidate_final_claim_settlement_finality_v2contracts2212requiresowncustody; recoverinvalidationcontracts2270requiresownclaimidentity. Thusdonotjustskipprepare.
Storedeepguards: persist_authenticated_settlement_child_binding(store.rs2549) requires OP_COMPLETED then settlement_child_transaction_matches_operation5766 forClaimrequiresload_final_claim_attempt_v2 exacteffect/tx andreceipt==exposure_record_digest. record_terminal_finality3016Claimcallsrequire_exposed_claim_identity4973 (V1/V2ownattempt), expectedCLAIM_BROADCASTstage. Receivercannotfabricateownsenderattempt; requiresdistinct verified-observation-backedjournal integration orseparateobservingchildport withdurability/reorgproof. DoNOTweakenexistingguards globally. Existing native_xmr_refund_v23 pattern useful butClaimstricter. ObservedF7FinalClaimV15 onlyhistorical, nevercurrentcanonicality; alwaysfreshverified_f7_claim_finality_v15 forfinality/reorg. stage_final_claim_transport_v1 onlystages onF7ClaimAdmitted/FinalClaimAdmitted; observation-backedExternalizedmustnotreturnadmissionbundle. No implementationchoicefinalizedyet; continuedfullflowreadrequiredforreceivercontroljournal.

Additionalreceiverjournaldesignread: DomActuatorstoreV10schemafixed(open_existing1821refusesmigration). Avoidnewtable/migrationifpossible. Existingnative_f7_funding_v20 mirrorsauthenticatedread-onlynativefunding/refund into dom_operations OP_COMPLETED withdomainseparatedevidence+receipt+eventstage, neverfabricateslegacyceremony. Potentialreceiveranalog canrecordverifiedObservedF7FinalClaimV15 via internalmethod requiringexactbinding/receiver/nativeStoreauth, domain-separatedreceiver-observationevidence, receipttxhash, no secret_binding_digest and NO final_claim_attempt_v2. Extend child-transaction matching ONLYexplicitreceiverdomain andcompletedexactscope, thenreceiver-specificfinality/reorg methods usefreshchainproof andnativeobservation, keep sender APIsrefusingreceiver. Existinggeneric record_terminal_finality requiresownexposedidentity; either add narrowreceiverentrypoint (notglobalpermissionbypass) or authenticateexplicitreceiverjournal identity. Needauthenticateeveryreopen/locatoragainstStoreobservation, exacteffect/role/chain/tx. ThisisDESIGNcandidate notimplemented/verified. Full path includes dom_secret_installer forfirstexposure; recipient publicsecret extraction already supportsStoreObservedF7FinalClaimV15 but installationcurrentlyrequiresmaterializedchild; verify exactsource/role/exposureflags.
31705compilefinished2m12; manualreceiverstate replaycurrentlyRUNNING (logendtestname). No activefulldaemon.

Receiverstate31705TERMINAL0:1passed95.03s compile2m12. ConfirmsAliceAwaitingObservation, wrongparticipantrejected, corruptgatefails(notwaiting), restoredgate+sessionunchanged. Sender-onlyprogress stillInvalidTransition asrequired. No activecurrenttests. NewAPIexportchaincomplete; codebasecompilesStoretest. Observedpositivebranchnotyetcovered(noobservedclaiminrun24copy); senderpositivebranchalsoneedsfixture. DaemonstillUNWIRED; doNOTcallactualfailurefixedorfullgreen. Next: complete observation-backedchildjournal using originalschema, materialization/dispatch/reconcile/observation/reorg/reopen; followdetailednotesabove. ProductionDomPublicSecretInstaller.install_from_exact_child and reextract already supportreceiverStoreobservation; no secondprivateoriginneeded.

## Receiver actuator journal implemented and locally tested
NEWcrates/dom-actuator/src/native_f7_receiver_journal_v25.rs (privateStoremodule). Publiccrate retain_f7_receiver_claim_v25 takesOpaqueObservedF7FinalClaimV15, checkssession/chain/receiver/nonzeroobservation, delegatesprivatejournalprimitive (rawidentityaccessibleONLYtests/private). Writesdom_operationsOP_COMPLETED usingdomain-separatedreceiver-observationevidence(scope+tx),receipttx,no secretbinding, andClaimBroadcaststageevent. NOownfinalclaimattempt/admission. OriginalschemaV10unchanged. Replaysrequireexactscope/domain/tx/authhash andoldfence<=livelease; no freshsendcap.
Store settlement_child_transaction_matches_operation permitsnewreceiverreceiptONLYwhennoV2attempt andnoV1custody and exactnewdomain+completedop+receipt+scope+authdigest. Senderbranchunchanged. receiver_transaction_v25 enumerateslocalcompletedClaimops, authenticatesdomains+scope+receipt, rejectsduplicateidentities. require_terminal_claim_identity_v25 acceptsONLYexactreceiveridentitywithoutmixedownattempt; otherwiseoriginalsenderguard. Usedbyrecord_terminal_finality,record_terminal_reorg,andreopenaudit_terminal_finality_records (3sites); sendercustody APIsstillunchanged. require_no_refund_after_claim_exposure nowalsoblocksretainedreceiveridentity (mustpersistafterreorg).
Firsttest74108exit0:receipt/reopen/wrongtx/noownattempt passed2.31s,compile2m11. Extendedtest28788exit0:1passed3.30s,compile37.97s; includeswrongtxfinalityrejected,correctfinality,originalstoreopen,reorg,refundauthorizationrejected,secondreopen,newleaseat12000,originalchildlocatorretained,noownattempt. Uses syntheticidentity+finalityrecordsONLYprivatejournalunit test; NOTchainproof. Log/tmp/branchcodex-receiver-journal-v25.log. NEWexistingclaimregressionslaunched(log/tmp/branchcodex-receiver-journal-regressions-v25.log),recordhandlefromtool.
NOTYETintegratedactuatorfacadeorproductiondaemon. Next: facadeinDomContractsActuator toqueryStoref7_claim_receiver_state, authenticateObserved+facts, bindviaretain_f7_receiver_claim+persistchild; historicalreceiptonlycannotassertfreshfinality. Forreceiver externalize/reconcile mustobserveactualchain andnevercallsenderdispatcher; finality usesruntimeverified_f7_claim_finality_v15 andnewterminaljournalidentity; reorg/recovery mustuseexactcheckpoint/receiveridentitywithoutowncustody. ProductionDomChildPort.materialize/validate_dispatch/dispatch/reconcile/observe/revalidate/recoverinvalidation allneedwiring. Parentglobalgoalnotgreen.

Receiverjournalregressions86055TERMINAL0:40existingclaimtests passed114.93s; includesforeignsender/selfreceiverrefusal, tamperonreopen, exactsameidentityretries, takeover/fence, finality/reorgwithoutadmission, heldStorelockchecks. Noactivecurrenttests. Journalintegrationfoundationvalidated; facadedaemonstillunwired. Nextgoalturncontinuefullreceiverobservationflow, notfull2hrdiagnostic.

## Receiver facade integration resumed after compaction (2026-09-22)
User explicitly restored checkpoint: receiver preparation/binding/finality/reorg were already wired; compile and test those connections next, do not restart implementation or full run. Disk 273GiB free, RAM 2.1GiB available; host process check found no cargo/rustc/dom-interopd/monerod before launch.
New native_f7_receiver_claim_v25.rs facade authenticates receiver state and verifies actual transaction using real DOM verifier. contracts.rs binding/retained identity/revalidation/invalidation and final_claim_v14.rs observation use receiver identity. production_claim_owner_v21.rs skips sender preparation only for authenticated observed receiver; pending is retryable ContractsAuthorityUnavailable. production_child_dom.rs receiver dispatch/reconcile verifies exact observed tx and returns Externalized, never sender admission or submission. These connections still need daemon compilation and positive observed-path validation.
Added ignored archived_receiver_facade_waits_without_sender_authority in receiver journal tests using private RUN24 contracts+control.sqlite copy. Initial26043 exited101 due ONLY new test import TrustedChainIdV1 wrong crate; fixed to dom_adaptor. Current79469 running rerun, /tmp/branchcodex-receiver-facade-v25.log. No long run, no push. Copy root /home/leonardov/.dx-v23/run24-claim-replay-v25 contains control.sqlite(+sidecars) copied previously; do not reextract over it or print sensitive files.
Static follow-up: canonical_terminal_snapshot supports resolve-mode zero anchor evidence and resolves actual tx from authenticated chain. local_origin_needed_v21 callers both guard sender/origin role before invoking sender-only progress, so no additional receiver bypass needed there. New source rustfmt and git diff --check passed before rerun. Full scenario remains unverified.

Receiver facade replay:79469 compiled43.43s then failed0.03s InvalidStorageAuthority because archive copy lacked original .lock. Static Store acquire_process_lock(false) confirmed missing sidecar; copied exact zero-byte Alice daemon-dom_actuator_store.lock from same RUN24 archive to private control.sqlite.lock mode0600. No production guard changed. Rerun83088 TERMINAL0:1passed92.64s, build14.02s, log/tmp/branchcodex-receiver-facade-v25.log. Actual archived control binding+Contracts now confirm facade AwaitingObservation maps temporary unavailability, sender progress still denied, session unchanged. No successful observed tx fixture proof yet. Launched production_composite_loop::tests with no-default-features/features production/profile crypto-test; /tmp/branchcodex-receiver-daemon-integration-v25.log; get new session handle from tool output. No full daemon scenario or GitHub triggered.

Continuation verified wait:12007 still live production daemon compilation (host cargo3491372, rustc3492556, rust-lld3494731 at5m39 elapsed; no test running yet). Log /tmp/branchcodex-receiver-daemon-integration-v25.log warnings only as of12:46. Prior status-only user answer was no-progress; this turn confirmed83088pass and launched compilation. Static receiver order production_run_universal.rs2024 calls step_f7_claim_receiver_v15 every native loop before coordinator, records real observation via scanner/persist CAS; no materialization circular dependency found. production_plan_source.rs717+ already selects receiver observation for fresh publicsecret extraction, separate sender admission. Positive scanner+signed claim fixture found production_xmr_native_observation_v23_tests.rs run_claim receiver callback442-475; suitable next extension to exercise facade verified_f7_receiver_claim on actual signed captured tx (snapshot ancestry synthetic, NOT live payment), avoiding full daemon before focused proof. Do not alter source while current compilation active. After12007 completes, run production_child_dom::tests and receiver/phase tests, then extend positive fixture if needed. Full workflows unproven; no push.

12007 TERMINAL0: production daemon compiled and26production_composite_loop tests passed0.00s.96330 TERMINAL0:13production_child_dom tests passed3.68s. Initial extra receiver/ownership filters had wrong module prefixes and selected NONE; do not count them as passed. Correct paths from actual binary --list: production_contracts::claim_receiver_v15::tests and production_run::universal::native_phase_ownership_v24::tests. Running correct substring filters directly on target/crypto-test/deps/dom_interopd-7316c4a7a2f3501f; /tmp/branchcodex-receiver-phase-regressions-v25.log.48205 read-only privatefixture observation filename search terminal0 with no matches (no positive archived receiver observation found there). No active compile/fullscenario.

Correct receiver/phase regressions TERMINAL0:6passed0.00s, /tmp/branchcodex-receiver-phase-regressions-v25.log. Latest integration evidence totals26coordinator+13DOMchild+6receiver/ownership =45short daemon tests, plus archivedfacade1pass92.64s. This validates compilation/regressions and awaitingreceiver path ONLY; full three red jobs and workflow gates remain unproven. All recent handles terminal, no current test/daemon/compiler started by this agent. Next concrete task: add positive receiver facade check to existing real signed-claim/scanner fixture callback production_xmr_native_observation_v23_tests.rs around observed.tx_hash verification; existing callback has claim_bindings[actor],store,chain,runtime,Observed token and actual signed tx, so test verifies exact observed role/tx and verified_f7_receiver_claim_v25, plus reject substituted tx. Need identify caller test and cost before launch; do not rerun full2h scenario for diagnosis.45sreuse-margin race remains separately documented/unfixed.

## Positive receiver facade validation started
Extended existing production_xmr_native_observation_v23_tests.rs run_claim receiver callback after persisted real scanner observation: bind actualclaim_bindings[actor], queryreceiverobserved exacttx, verified_f7_receiver_claim_v25 against snapshot runtime, reject mutatedtx CapabilityMismatch, senderprogress stillerr. Runs for firstreceive AND reopenedreceive. Synthetic header ancestry explicitly remains NOTlivepayment/PoW; signedtx/template/scannerverification real. This extends known-green GPLcomponent specifically to validate newlychangedfacade; do not credit existinggreenjob as newfix.
Launched exact v23_native_claim_six_messages_and_presignature_with_real_output_scan (production/crypto-test) with CARGO_BUILD_JOBS1, privateenv sourced without printing, TMPDIR.dx-v23; /tmp/branchcodex-receiver-positive-v25.log; failedfixturemarker /tmp/branchcodex-receiver-positive-v25-fixture.txt. Recordhandlefromtool and poll; DO NOTinterrupt active test. No full2h daemon, noGitHub. Newtestassertions unverified until this completes.

Positive receiver validation handle99728 confirmedLIVE repeatedly; still compiling dom-interopd, warning-only log as of latestpoll. No claim fixture phase yet, no success claimed. Continue same99728; do not restart on observation timeout. New assertions are already in working tree and part of this compile. No other testactive. Remaining45srecencyrace safe narrow design: distinct RefreshRequired error only for (Universal consumed authority, UniversalRecent request) whose reuse guard turnedfalse; keep Scope for profile/owner mismatches; retry onlynewerror, nextoutertick necessarily obtains freshopaqueanchors since reuse remainsfalse. Currentouterretryable delegatesClaim.is_retryable, and refresh precedes anyprivateoperation. NOTIMPLEMENTED, needs deterministicboundary/failclosedtest afteractivevalidation.

Verified-wait continuation:99728 stillLIVE, rustc3497969/cargo3497710 confirmedhostactive at4m47 elapsed then repeatedhandlepolls remainedlive. Positive receiver component notstarted yet; logstillcompilerwarnings. Do not mistakewarnings orobservationtimeout for failure; do not restart. No sourcechanges/newtest/push inthiscontinuation, onlyhandoff. Resume99728 and /tmp/branchcodex-receiver-positive-v25.log until terminal; preservefailedfixturemarker iffailure.

99728 positive receiver component: compilationSUCCESS6m21, testRUNNING. Firstmarker nativegraphfixtureready82.914594449s. NextC/D proofs/twoleggraphs/custody/funding/claim continuation/newreceiverassertions. No failures yet; stillnotclaimfinality. Preserve99728 untilterminal, nointerrupt/sourceedit.

99728 verifiedLIVE latestpositivecomponent: Cleg1 ready235.213860464s. Timingexplicitfixture_restart_only=true,actual_daemon_latency=false:54actor_ticks/54tick_mounts/54identityreopens, mounts47.233137s,resttick99.059660s,totalnativeoutput152.152311s. Do NOTpresentthis as swaplatency; testdeliberatelyreopens. Dleg1 next. Nofailures; receiverassertionsnotreached.

99728 verifiedLIVE nextmarker Dleg1ready365.409857793s (~6m05 testelapsed). Dnativeoutput130.032680s;54fixture-restartticks,NOTdaemonlatency. BothC/Dfirstlegpassed; remaininggraph/reopen/C-Dotherleg/custody/funding/claim/receiverfacadeassertions notyetcomplete. No failure/sourceedit/restart. Samehandle andlog.

99728 verified-wait currentfixture identified /home/leonardov/.dx-v23/.tmpKyyiuM, hosttestPID3501199 at8m42 elapsed CPU3m15, cargo3497710. ReadONLYfilenames: actor alice,bob runtime-contracts session-records17each and runtime-contracts-leg1 records18each; bothsession-artifacts empty. LastlogDleg1ready365s. Sessionfilecounts are NOTcompletionstage17/18. No liveDBopened, no sourceedit, nointerrupt. For futureprogress inspect exactsession-recordfilename maxrevision/markerfilenames only, no secrets. Same99728stilllive.

Latest99728log: Cleg0ready586.251800537s (~9m46); nativeoutput190.481967s, fixture_restart_only true. ThusbothC/Dleg1 andCleg0 passed, Dleg0pending. No claims yet, no failure. Continue samehandle.

99728 verifiedLIVE: Dleg0 ready782.420527851s (~13m02 testelapsed), all4C/Doutputs completed. LastDnativeoutput196.003726s (fixture-restartonly). Nextrolebinding/custody/funding/claim; newreceiverassertionsnotyetreached. No error/sourcechange/newprocess/restart. Additionalstaticcheck map_f7_claim_error_v21(Error::Actuator) delegatesmap_actuator_error, so receiverAwaitingObservation remainsUnavailable (notConflict) through coordinator boundary. Keep99728.

99728 verifiedLIVE majorprogress: graphformation+2commitpositionsaccepted; all3six-envelope signingrounds accepted163.994100138s (rounds36.305735258/44.448392308/51.023674117; each14fullprefixaudits). BOTHactors completionverified ANDoriginalgraphStoresreopened/replayedall3edges successfully (~10.9s eachreplay). bothclaimrolesbound1104.438374534s (~18m24 testelapsed). GPLfundingobserverREADY, localUDS helper started under fixtureAlice/xmr-v23-w0bj74. Next custody_and_funding_for_claim thenrun_claim positivefacade callback. Thisisgraphreopen,NOTfullrouteoriginal-storeclaimreopenjob. No newreceiverassertionsyet/no fullgreen. No sourceedit/restart/interrupt/GitHub. Same99728 /tmp/branchcodex-receiver-positive-v25.log.

99728 verifiedLIVE fundingprogress: BOTHencryptedcustodyReady+refusalchecks+T/Ureopen passed; readiness2votesaccepted17.21112534s. Funding signersready actor0 33.609739239s,actor1 24.356390939s. Envelopes1..5loggedauthenticatedbothStores18.33/18.43/21.08/22.56/22.93s. BOTHcompletion/refusal audits passed6.374/5.145s. Latestactor0independentreopen,custodyloss,sixreplaysPASS79.912150056s. Waitingactor1 equivalent andfinalfundingmarker; no claimcontinuation/newfacadeassertionsyet. No failure/sourcechange/restart/interrupt/GitHub; keep99728.

99728 verifiedLIVE: actor1fundingindependentreopen/custodyloss/sixreplaysPASS80.879093721s. FINALfundingmarker sixfundingenvelopes,identicaldurablebytes,reopen/replayverified;no broadcast. Fundingblockcomplete351.160033805s. Nowrun_claim preparation/privateforkrefundrecovery beforefreshF7claimcontinuation; no newclaimmarker orreceiverfacadeassertionsyet. This confirmscomponentfundingonly,notfullnative daemonclaims. Same99728 continues, nointerrupt or sourcechange.

99728 verifiedLIVE afterfunding: hosttest3501199 at27m52 CPU17m26; helper3511740/sidecar3511745alive. Privatefork .dx-v23/.tmpEHuD5i (separatefrommainfixture.tmpKyyiuM) actor0cancel/refundattempt markers observedbyfilenameonly. LATESTLOG private-forkrefund canonicalUobserved;exercisingrefundtransport. No error, no claimassertionsyet. Thisiscomponentisolatedrefundscenario,NOTfullredrefunddaemonjob. Continue99728; nointerrupt/sourceedit/DBopening.

99728 verifiedLIVE: refundtransportPASS signedpending/durablereplay/tamper/grantloss; private-forkrefundrecoveryCOMPLETE. Latestmarker nativeClaim enteringfreshobserved-fundingauthorizationandretainedsigning. Nowactualclaimcontinuation underway; newreceiverfacadeassertionsstillpending untilsignedclaim+observation. No errors/sourceedit/interrupt/GitHub. Continue same99728 andlog.

99728 verifiedLIVE CLAIMmilestone: bothfreshauthorities/signersready37.586558791s/38.636459357s. All6claimenvelopes0..5accepted/liveauthority+bothStoresverified; turntimes42.59114768,49.446351112,53.762151609,60.059332573,68.067769316,75.569657938s. Theseincludecomponentverification,NOTmeasuredfullswaplatency. Nextpresignature/exposure/receiverrealobservation/newfacadeassertions/reopen. Stillnotfulltestgreen; no newerrors/sourceedit/interrupt/push. Keep99728.

99728 verifiedLIVE: identicalpresignatures+accepted0x0fPASS82.851369037s. Latestactor0independentreopen/replay/scopedexposurechecksPASS216.930868492s. Beforethatfilenamecheck BOTHmainruntime-contracts haveclaim-issued/consumed/binding/pre, no claimexposure/observationyet; do not equateactor0genericmessage tosenderpublication. Originalsigners/authorities/stores explicitlydropped beforeactorreopen(no sameownerlockdeadlock found). Actor1reopenandcapture/receivercallbackstillpending. No failures/codechanges/newtests/interrupt. Continue99728.

99728 verifiedLIVE latestfile-markerprogress: Bobruntime-contracts/session-artifacts NOWhasf7-v12-claim-exposure-v14;Aliceonlyclaimissued/consumed/binding/pre. Thisisactualpersistedexposuremarker,NOTcurrentfinality/receiverassertionproof. Lastlogstillactor0reopenpassed216.93s; actor1currentlyexposure/replay/capturechecks. NoDIAGfailures. Keep99728, do notinterrupt.

## Positive receiver component TERMINAL GREEN; next F7 recency race correction
99728 TERMINAL0,1passed3405.49s (~56m45), compile6m21. /tmp/branchcodex-receiver-positive-v25.log explicitly contains NEWproductionfacade verifiedexacttx/rejectedsenderauthority marker; substitutedtx assertion also passed (beforemarker). Receivercanonicalobservation/extraction check231.624012592s; Claimportion1426.188381679s. ThisKNOWN-GREEN GPLcomponent was extendedforNEWreceiverfacade validation, do NOTcredit its oldgreenstatus asfixing3redjobs. Correction to earliernotes: receivecallback invokedONCE in claimfixture at512, afteropeningreceiverStore; it persistsobservationthenverifiesfacade. DoesNOT prove reopeningafterthisnewobservation. Fulltwo-daemonoriginal-store-reopenjob stillrequired, nofulljobgreenclaimed.
After99728terminal ONLY, implemented documented45sreuse-marginrace in production_dom_claim_runtime_v12.rs: newRefreshRequired error, retryableonlynewvariant, Universal+UniversalRecent checks currentreuseguard andreturnsRefreshRequired ifmarginexpired; Scope remainswrongprofile/owner, steprefreshstillbeforeprivateoperations. No60s/15s/timeouts changed. Addedruntimeclassificationassertions Scopefalse/RefreshRequiredtrue and outerF7test ensures Claim(RefreshRequired)retryablebutScopeandRequiresRestart(Some(RefreshRequired))NOTretryable. Theseareclassificationregressions, notdeterministicclockinjection tests. NoStorechanges.
ACTIVE61918 cargo production/crypto-test -- dom_claim_runtime_v12::tests f7_runtime_v12::tests production_composite_loop::tests production_child_dom::tests --test-threads=1. CARGO_BUILD_JOBS1 TMPDIR.dx-v23. Log/tmp/branchcodex-f7-refresh-required-v25.log. Poll61918, no otheractive tests/daemonsfromcomponent (99728terminalcleaned). Needconfirmactualselectedtestcounts/notwrongfilter. Afterpass nextfullclaimsdaemonvalidation required; doNOTrerununchangedhourGPLcomponent. NoGitHubpush/newworkflow. Goalstillall3rednativejobs+bothworkflows+latency,unachieved.

61918 stillLIVE compilerwarningsonly; consensusguard+gitdiffcheckpassedcurrenttree. Nextfullrunner scripts/run_native_daemon_scenario_v23.py --evidence-dir /home/leonardov/dom-xmr-evidence-claims-reopen-20260922-run25 --timeout-seconds9000 --scenario native_real_daemon_two_claims_survive_original_store_reopen_v23. BEFORElaunch: finish61918tests, buildrelease (cargo build --locked --offline --release -pdom-interopd --no-default-features --featuresproduction, jobs1),chmod755 executable, update ONLY DOM_INTEROP_REAL_BINARY_BLAKE2B256_V23 inprivateenv tohashactualnewbinary (neverprintenv). Runner checks actualbinaryagainsthash. Sourceprivateenv whenlaunch, TMPDIR.dx-v23, escalationguardrequired. Run25 NOTstarted yet; oldreleasehashstillrun24. Nofullgreenclaim.

61918 TERMINAL0:44tests passed4.50s, includingdom_claimruntimeScope/refreshtaxonomyandNEWf7_runtimeobservation_refresh_retries_without_relaxing_scope_or_consumed_custody. Allselectedfiltersconfirmedactualtests. Newrecencyracecode nowcompiled/tested; consensus+diffcheckpassed. RELEASErun25buildjustSTARTED log/tmp/branchcodex-release-run25-build.log (recordnewsessiontooloutput), cargo build --locked --offline --release -pdom-interopd --no-default-features --featuresproduction CARGO_BUILD_JOBS1. No fullscenarioactive. Afterreleaseterminalsuccess chmod755 target/release/dom-interopd; computeBLAKE2b256andupdateonlyprivateenv DOM_INTEROP_REAL_BINARY_BLAKE2B256_V23; thenrun25claimsoriginalstorereopen runner asnotedabove unchangedtimeouts. DoNOTusetheoldreleasehash orclaimfullgreen.

Active release build handle48030; poll it before fingerprint or run25.44testcompile6m26s, tests4.50s.

48030 releasebuild verifiedLIVE, progressedthroughStoreandproductionwarnings, noerror/terminalyet. Run25 NOTstarted; do notfingerprintpartialbinary orreuseoldrelease. Runner environmentsetsCARGO_BUILD_JOBS2 foralreadycompiledcrypto-test, preserves9000max. BuildstillCARGO_BUILD_JOBS1. Continue48030.

## RUN25 full claims/original-store reopen launched
48030 releasebuildTERMINAL0,7m00. Actualtarget/release/dom-interopd chmod755, BLAKE2b256=37e49f457842cc085fc296566c252cb28ce899d9d5809a026ddbd971b7fa4ff9; exactenvbinarypathasserted, privateenvONLYhashlineatomicallyupdated0600 (noenvprinted). NewRUN25runner launchedrequire_escalated (recordhandletooloutput), original9000runner/7200phasebounds. Evidence/home/leonardov/dom-xmr-evidence-claims-reopen-20260922-run25; runnerstdout/tmp/branchcodex-run25-runner.log; scenario native_real_daemon_two_claims_survive_original_store_reopen_v23. Needpollhandle+test.log toconfirmstartup. DoNOTinterrupt/restart/rebuild/editproductioncode whileactive. Existing99728component3405.49sPASS and61918fortyfourshortregressionsPASS underpinthisintegration, notfullgreen. NoGitHubpush/action.

RUN25 firstattemptTERMINAL1 BEFOREANYTEST: campaign.jsonfailed mandatorydependency DOM_INTEROP_REAL_BINARY_BLAKE2B256_V23 missing. HashlineexistsinprivateenvbutNOTexported; bare source omitted it fromchildenvironment. No testcase/result.json/daemonstarted. Preservefailedcampaign. Correctedlaunch uses set -a; sourceprivateenv; set +a; validateshashformatwithoutprintingenv. NEWrun25a evidence/home/leonardov/dom-xmr-evidence-claims-reopen-20260922-run25a, runnerlog/tmp/branchcodex-run25a-runner.log, samehash37e49f...andbounds. Recordhandletooloutputandverifyteststartup. EarliernoteRUN25launched meantattempt, notexecutedtest; correctedhere. No protocolcodechanges.

RUN25a ACTIVE handle44518 CONFIRMEDLIVE, result.jsonstatusrunning/returncodeNone, synthetic_tmp /home/leonardov/.dx-v23/dx-ltjc92hl. Fulltestlog initiallyempty(startup); pollsame44518and case/test.log. Exactcasepath /home/leonardov/dom-xmr-evidence-claims-reopen-20260922-run25a/native_real_daemon_two_claims_survive_original_store_reopen_v23. No active48030/61918/99728 (allterminal). No code/binarychanges while44518active. set-aexportrequiredforfutureprivateenvlaunch.

RUN25a44518CONFIRMED testSTARTED: cargoFinishedcrypto-test26.65s,running1 exactignoredclaimsreopenscenario; cold_swap_preparation started elapsed0 then native startup preparing original enrollment and funding owners. Runnerstdout mirrorslog; prefercase/test.log forsinglecopy. Keepactive44518 throughterminal/archive/cleanup. No failureyet.

RUN25a44518verifiedLIVE: cold_swap_preparationCOMPLETE200085ms,export_and_launchCOMPLETE15044ms. Bothfirst_route_snapshotsobserved15055/15056ms; 4funding+4claim projectionsnot_prepared. Mainfixture /home/leonardov/.dx-v23/dx-ltjc92hl/.tmpF47J6A, actorStorepaths daemon-upstream_contracts anddaemon-downstream_contracts; all4mainrevs0latest. CreatedREADONLYmonitor /tmp/branchcodex-run25a-status.py (0600): parsesonlyTIMINGV24whitelistedprogress/completedfields andimmutableSessionfilenameheads/custody/claimmarkerfilenames. NEVERopensactiveDBs. Runmonitoralongsidepoll44518(livenesscomesfromhandle,notfiles). No errors/startupregressionestablished; productionprotocoljustbeginning. No productioncode/binarychanges whileactive.

RUN25a44518verifiedLIVE: daemonPIDs3545428/3545432 are namedcomm3 (execviaFD), NOTmissingdom-interopdprocesses; test3543219,cargo3542987,helper3543867 and4sidecars3543936/3543959/3543970/3543981 alive. Latestmonitor mainAliceup11/down10,Bobup11/down11, nocustody/claimmarkers,economicprojectionsstillnot_prepared. Initialrevision0waitresolvedbyactualprogress; no earlyregression established. Memoryavailable1.9GiB/swap1.4GiB; IOpressurefullavg10~30%, memorypressure0, notproofsolelatencycause. Neveruseprocesscommgrepdom-interopdaloneasdeathproof. Keep44518 andreadonlymonitor.

RUN25a44518verifiedLIVE latest: AliceMAINup19/down19,BobMAINup20/down20. All8auxsessionscreated: upstream3e38d1/fb4db1,downstream1a5eb0/9c00f5 ineachactorStore. Aliceauxall0,Bobauxall1. No custody/claimmarkers; projectionsstillnot_prepared. Actualprogress beyondinitial0and11, nofailurereported. Usemonitor andsamehandle, nointerrupt/codechange.

## RUN25a live continuation: measured persistence wait
Handle44518 re-polled and LIVE. Host read-only ps confirmed test3543219 and both daemon3545428/3545432 alive; sandbox ps cannot see these host processes, so empty sandbox ps is NOT terminal evidence. At daemon elapsed13m59 sample, both stateD: jbd2_log_wait_commit and folio_wait_bit_common. IO full avg10=10.37%, availablememory1902MiB, memorypressureavg10=0. This is concrete disk wait evidence, not proof of sole latency cause; do not remove durability barriers. Daemon stderr captured in parent memory (process.rs drain_live), no live log files found; do not touch pipes/databases to obtain it.
Latest immutable heads: both mainup21/down25; both upstream auxiliaries2/2, downstream6/6. Thus up resumed from19/20 and down from24; no custody markers or finalclaim projections yet. No source/binary change, no new test, no interruption. User told full scenario is NOT near end and full green remains unproven. Continue same44518 and /tmp/branchcodex-run25a-status.py; do not rerun known-green GPLcomponent.

RUN25a verified-wait update:44518 stillLIVE. Latest all8auxiliaryheads6; Alicemainup26/down26, Bobmainup25/down25; no custodyStarted/Ready markers or economicprogress transitions yet. Static nextstage verified in production_relay_xmr_signing_v23.rs:prepare_xmr_graph_completion_v23 requires refund_complete and bothauxiliary_complete, resumes all3signedsessions and reconstructs completedrounds before graphcomplete/custodymount. Revision6alone is NOT proof of Complete/Ready. Fullfinalchecks re-read: normalexit both, finalnativechildren/aggregateidentities, originalStore restart, heartbeat-or-success, secondnormalexit and immutable economic snapshots. Receiver terminaljournalidentity is wired into reopen audit; runtimeproof remains pending. No new test/sourceedit/push/interruption. Continue44518 and readonlymonitor.

## RUN25a milestone: all four custody Ready
Handle44518 confirmedLIVE. Authoritative test.log custody report at1171s: Alice bothStarted1/Ready1; at1201s: BOTH ACTORS BOTH LEGS Started1/Ready1, repeated1231s. Allmainheads26/allaux6. Economic projections lastreportednot_prepared; funding/claims/reopen stillpending. IMPORTANT monitoring correction: filename substring filter reports [] even while test validatesStarted/Ready. Do NOT infer custodyabsence from matching_marker_filenames_only. Updated /tmp/branchcodex-run25a-status.py to print last actual test custody report and rename filename-onlylabel. Earlier no-marker reports described filename scan and were insufficient; authoritative test custody output wins. No productioncode/test/binary change, nointerrupt/restart/push. This milestone~1201s is nearRUN24~1232s, does not establish meaningful overall speedup. Receiver-path correction is later than thispoint and still awaits fullscenario exercise.

RUN25a44518 verifiedLIVE at testphase1562s: bothmainup32/down27, allaux6, all4custodyReady remainsconfirmed by test.log. Economic TIMING lasttransitions stillallnot_prepared. Noerrors reported/no terminalresult. This continuation is VERIFIEDWAIT, not fullscenario success; retain samehandle, no newtest/build/push. Current nextunproven milestone is actualFunding progress, then Claims/naturalexit/reopenaudits. Do not mislabel session revision as completioncount.

RUN25a44518 stillLIVE at phase2163s (~36min). Bothmainup34/down32, allaux6; all4custodyStarted1/Ready1 stillconfirmed in test.log. Sincepreviouscheckpoint upstream32->34 anddown27->32: actualongoingprogress, NOTstalledatoldrevision. Economic TIMING stilllastnot_prepared; nofunding/claimfinal orreportedfailure. No productionchanges/newtests/restarts/interruptions/push. Continue SAME44518; updateevery~30s whilewaiting. Fullobjective unproven.

## RUN25a first economic progress
44518 verifiedLIVE. TIMINGV24 upstream_funding progressed not_prepared -> committed: Bob2403088ms, Alice2414977ms. This is NOTFinal/confirmed. Downstreamfunding+bothclaims stillnot_prepared. Bothmainup35/down33, allaux6, all4custodyReady. Userinformed firstfundingstatechange at~40min launch. Continue samehandle andmonitor, no sourcechanges/restarts/newtest/push. Fullclaims/reopen stillunproven.

RUN25a44518 verifiedLIVE atphase2794s (~46m34). All4mainheads35, allaux6, all4custodyReady. Upstreamfunding bothcommitted (Bob2403088ms/Alice2414977ms); downstreamfunding andallclaims lastnot_prepared. No reportedfailure/terminal, no restart/interruption/sourcechange/push. Fullscope stillpending. Continue same44518 andreadonlymonitor.

RUN25a44518 verifiedLIVE latestphase2975s. ECONOMIC unchanged upstreamcommitted, othernot_prepared; allmain35. NEWhostps sample daemonelapsed49m51 bothstateRl withCPUtimes34m20/32m01 (vs~4m earlier); IOpressurefullavg10=0.26%,memory0. Currentphase is CPU-running, doNOTattribute ongoingdelaysolely todiskwait fromearlysample. Test3543219active53m27. No terminal/error/newtest/restart/codechange. Continue samehandle.

## RUN25a upstream funding Externalized
44518 verifiedLIVE. New TIMING state upstreamfunding Externalized BOTH: Bob3184851ms,Alice3184951ms (~53m05 fromlaunch). Previouslycommitted2403/2415s. Externalized is NOTFinal; no finalfunding/claim yet. Allmain35/allaux6/all4custodyReady, downstreamfunding+claims lastnot_prepared. No reportederror/sourcechange/testrestart/push. Continue same44518, monitor exactTIMING; nextupFinal anddownstreamprogress unproven.

## RUN25a upstream funding FINAL confirmed
44518 verifiedLIVE. TIMING upstreamfunding FINAL Bob3591458ms,Alice3591559ms (~59m51 fromlaunch). PriorExternalized3184851/3184951ms. This is actualupstreamfunding finalprogress BOTH, notClaims/jobgreen. Downstreamfunding+allclaims stilllastnot_prepared; allmain35/allaux6/all4custodyReady. Userinformed truefinalfundingmilestone. Noerror/sourcechange/restart/newtest/push. Continue44518; nextdownstreamfunding, thenclaims/naturalexit/originalStore reopenaudits required.

## RUN25a downstream funding Committed
44518 verifiedLIVE. NewTIMING downstreamfunding not_prepared->committed Bob3796904ms/Alice3797107ms (~63m17 launch). Upstreamfunding remainsFINALboth. Allclaims stillnot_prepared, allmain35/allaux6/all4custodyReady. No reportedfailure. Continue same44518; downstreamExternalized/Final thenclaims/reopen unproven. No sourcechanges/restart/newtest/push.

## RUN25a downstream claim authorization markers appeared
44518 verifiedLIVE phase4327->4357s. Bothdownstreammain36 (up35), matching immutableartifactfilenames now f7-v12-claim-issued,claim-consumed, thenclaim-binding BOTHactors. This proves filenames/newdurablerevisions only, NOTfullauthaudit, signature, publishedclaim or routeClaimPrepared. TIMINGroute stilldownstreamfundingcommitted/allclaimsnot_prepared; upstreamfundingFINAL. No reportedfailure. Userinformed narrowinternalprogress. Continue44518, next actualsigning/pre/publication/finalclaims plusoriginalStore reopening unproven; no liveDBaccess/codechange/restart/push.

RUN25a44518 verifiedLIVE atphase4597s (~76m37). DownstreamAlice38/Bob37, upstreamboth35. This matchesRUN24finalrevisionpair BUTeconomicstate differs: downstreamfundingstillcommitted vsRUN24Final. Therefore NOTproofpastoldfailure/fixsuccess. Allclaimsnot_prepared, no pre/exposed markerfilename yet. Userinformed narrowly, no reportederror. Continue44518; no source/testrestart/push.

## RUN25a downstream funding Externalized
44518 verifiedLIVE. TIMINGdownstreamfunding Externalized Bob4645375ms/Alice4666519ms (~77m25/77m46 launch). UpstreambothFINAL; allclaimsnot_prepared. HeadsdownAlice38/Bob37,upboth35; claimissued/consumed/bindingfilenamespresent. No finaldownstream/claimpublication proof yet. No reportederror/sourcechange/restart/newtest/push. Continue same44518.

RUN25a44518 verifiedLIVE phase5199s (~86m39). No neweconomictransition since downstreamExternalized at4645/4666s: upstreambothFinal,downstreambothExternalized,allclaimsnot_prepared. DownheadsAlice38/Bob37/upboth35; issued/consumed/binding present, no pre/exposedfilename. This is VERIFIEDWAIT with livehandle, notterminal/blocker and NOTproofpastRUN24error. No newtest/sourcechange/restart/push. Continue same44518 andreadonlymonitor; mustobservefullclaims/naturalexit/reopen orinspectterminalfailure beforeanyrerun.

RUN25a44518 verifiedLIVE: Bob downstreamfunding FINAL5395746ms (~89m56 launch), Alice downstreamstillExternalized last4666519ms. UpstreambothFINAL; allclaimsnot_prepared. HeadsdownAlice38/Bob37 unchanged. Threeof4fundingprojections nowFinal; NOTbothclaims/jobgreen. Continue same44518, no restart/sourcechange/push.

## RUN25a ALL FOUR FUNDINGS FINAL
44518 verifiedLIVE. Alice downstreamfundingFINAL5566086ms (~92m46 launch), Bob5395746ms. All4fundingprojections nowFINAL. Allclaimsnot_prepared. HeadsdownAlice38/Bob37/upboth35, claimissued/consumed/bindingfilenamespresent. This approaches oldRUN24failureconditions but doesNOT provefixedreceiverpathcomplete orgreen. No reportederror/terminal. Continue SAME44518 andmonitor throughclaims/naturalexit/originalStore reopen; nointerrupt/sourcechange/rebuild/newtest/push.

## RUN25a continuation: claim wait isolated by static reading
Handle44518 re-polled LIVE; authoritative test custody report6401s, allfourFundingFinal, allClaimsnot_prepared, downstreamAlice38/Bob37/upstream35. No new test/build/source edit/interruption/push. Read production_run_universal.rs native burst, production_relay_stage12.rs, production_xmr_claim_bootstrap_v23.rs, production_f7_runtime_v12.rs, production_dom_claim_runtime_v12.rs, receiver facade and downstream revelation gate. Signing is driven before receiver observation and before coordinator child preparation, so receiver AwaitingObservation alone does not statically block signing. Upstream native signing intentionally waits for downstream public DOM claim (observe_downstream_claim_gate_v23); downstream is the first diagnostic target. Current loop silently swallows retryable native-claim errors and ignores returned pump progress; this is a concrete observability gap, NOT proof of which refusal occurs. When this run terminates, inspect captured daemon stderr and archived downstream signing envelopes, exact pending/accepted application IDs and fresh authority paths before rerunning. Prefer narrow archive replay. Do not infer envelope count or phase from revision38/37 alone. git diff --check passed.

## RUN25a new downstream transport evidence (read-only)
Read only immutable session-messages headers (first208bytes; layout verified at session_store.rs:33512); this is diagnostic metadata, not full Store authentication. Alice downstream has35 message files, Bob34. Alice-only file sender d39f4845... sequence17, type0x0c, successor38. Both have sender88c9df59... sequence16,type0x0c,successor37. Thus observed headers identify the missing second claim nonce-commit at Bob, rather than merely revision mismatch. No outbound-dsc1-request filename lacked its corresponding reconciled filename on either actor downstream. This suggests investigate post-ACK delivery/ingress, does NOT prove remote acceptance or transport fault. Relevant code: relay_worker.rs handoff_claim_signing_v19; production_composite_loop.rs poll_retained_inbound_renewing_v25. Auxiliary ingest.refused is checked explicitly, main inbound report is returned; do not assume quarantine without evidence or make all refused traffic fatal indiscriminately. Actual receiver refusal/queue state still unknown; do not open live DBs.
Host read-only ps: test3543219alive elapsed1:55:01; both daemons3545428/3545432 Rl elapsed1:51:26 CPU1:29:27/1:23:40; currentIOfullavg10=0.08%. No evidence of dead daemons or disk-only cause. Broad rg forAGENTS completed handle68601exit2(permissionerrors inunrelatedpaths); exact/home/leonardov/AGENTS.md read and no repo-rootAGENTS. No new tests/sourcechanges/restarts/push. Continue44518 unchanged.

RUN25a44518 verifiedLIVE at6822s, economic state/head unchanged. Continued static read: resume_outbound_dsc1 authenticates historical reconciled requests and excludes them; stage_store_outbound_dsc1 records Store handoff only on AlreadyAcked. This is local Relay ACK, not remote Contracts acceptance. Main durable inbox can quarantine an outer-envelope refusal and acknowledge that delivery page; main composite returns the ingest report without the explicit fatal refusal check used for auxiliary inbox. This is only a candidate requiring archived queue evidence, NOT confirmed quarantine or justification to weaken ingress. Read step_f7_readiness_v19 and claim ingress handoff; no evidence readiness blindly replaces current ClaimAdaptor authority. No code changes/new test/interrupt/push. Perf exists but perf_event_paranoid=4; no profiling attach attempted. Continue same handle through terminal and archive exact missing downstream sender d39f4845 sequence17/type0x0c on Bob.

## RUN25a TERMINAL FAILED — transport localization
Handle44518TERMINAL1. result.json: failed, cargo101, 0passed/1failed, test7476.21s, runner7521.669s, cleanup_verified and fixture_cleanup_verified true, dependencies unchanged. Exact error real daemon claim observation reached its explicit deadline. No user/manual interruption; harness7200phase timeout stopped/drained daemons. Archive preserved at evidence run25a/case/synthetic-fixtures.tar.gz. Originalfixture cleaned; DO NOTpoll44518 again.
Safely extracted archive regularfiles/directories only into PRIVATE /home/leonardov/.dx-v23/run25a-static-diagnosis/.tmpF47J6A (umask077, rejectlinks/absolute/traversal). ReadONLYsqlite mode=ro on stopped COPY includingarchivedWAL. Main downstream inboxquick_check bothok, quarantineempty BOTH. Bob inboxlastouterseq17 delivered1; NOTsameasDSCseq17. Exactcorrelation: Alice immutableDSCmessage senderd39f4845...seq17,type0x0c,length248 -> route_application.signed_dsc1 exactmatch -> delivery_status2,outerfirst/finalseq18,1ACK -> sender_history.envelope_digest -> Alice relay_envelopes exactdigest PRESENT ordinal128,seq18. Bobrelayqueue exactdigestABSENT; Bobinbox exactdigestABSENT. Alice relayqueue hasexactly1envelope, Bob0. Thus missingsecondnoncecommit remains on ALICE LOCAL RELAY, not Bobquarantine/ingress. MainDSCfilenameabsence isexplainedby no remotetransportyet. Nextread production_relay_network_runtime exchange/scoped delivery path and correlateAlice remainingenvelope scope/cursors withretainedprimary/downstream scopes. DoNOTrerunwhole2h scenario; archive isavailableforfocusedtransportreplay. No sourcefix yet. Newlogsinclude manycustody_mount6-12s repeatedandidleexchange, butlatency issecondarytothisprecisedeliverygap.

## V26 focused scheduler correction in progress
Archive relay query: targetAlice envelope outerseq18 ordinal128 remains in Alicequeue; matching scopedflow acknowledgedsequence17, one matchingroute46464646/sessiond1. No pending-envelope evidence of wrongscope. Final stderr blocks show successfuldownstreamexchanges cease after listenercall114/connector108 (firstclaimcommit), upstream successescontinue with risingconnector sessionerrors. This supports rendezvous investigation, not proof alllatencyresolved.
Static concrete scheduling gap: accept_one_until_v25 yields when siblinglistener haspendingpeer; run_relay_leg_v25 previously only serviced selectedleg and selectedlegpending again, leaving sibling behind a nativeburst. Changed only production_composite_loop.rs focusedpass to service already-pending sibling then selected, atmostonceeach, throughsameownership/bootstrap/authenticatedexchange. No timeoutchange/guardremoval. Added test focused_relay_services_peer_waiting_on_sibling_after_accept_yields bothdirections, asserts pendingdrains,traffictrue,calls[selected,sibling],2renewals; existing no-pending/shutdowntest retained. Test wouldreturnmovedfalse witholdcode.
ACTIVE compile/test handle53676 (functions cell4196 alreadyresolved). Command CARGO_BUILD_JOBS=1 cargo test --locked -p dom-interopd --no-default-features --features production --lib --profile crypto-test production_composite_loop::tests -- --test-threads=1; log/tmp/branchcodex-relay-sibling-v26.log. Host escalation, umask077. It is compilingdom-interopd, warningsonly sofar; noresultyet. DO NOTrestart while53676live. Run25a44518terminal, donotpollthatagain. No releasebuild/newfullscenario/push. gitdiffcheckpassedaftercodeedit; runagainafterhandoff. Need thisfocusedvalidation then targetedrealTCP/Noise regression or archivepage replay beforeclaiming deliveryfix. Full3jobs/workflows stillunproven.

## V26 scheduler and Noise focused validation PASSED
53676TERMINAL0: production_composite_loop::tests 27passed/0failed/793filtered, runtime0.00s, compile5m16. New siblingyieldregression passed bothdirections. Log/tmp/branchcodex-relay-sibling-v26.log.
88816TERMINAL0: production_noise_relay::tests::loopback_persists_before_source_ack_and_preserves_source_on_backpressure exact1passed/819filtered, runtime6.08s,cargostart26.27s. Log/tmp/branchcodex-relay-loopback-v26.log. UsedTMPDIR/home/leonardov/.dx-v23,productionfeature,crypto-test,CARGO_BUILD_JOBS1,hostescalation. This provesgenericNoise durability/backpressure, NOTarchivedclaimreceipt/naturalexit/fullgreen. Noactive test now; no release rebuild/push.
User again asks reduce time; answered yes targetredundantwork, cannotpromiseminuteswithoutmeasurement. Quantified archivedstderr blocks: custody_mount346calls2366.09s(max12.61s),other332calls2158.68s(max10.32s). Timesoverlapbetweenactors, donotsumtooverallwalltime. Codepath step_xmr_recovery_signing_with_renewal_v25 sees graph.signingNone and calls step_xmr_graph_custody_v23, Custodied=>custody.revalidate everybootstrappre/postnetwork. Activation also revalidates. Existing combinedReady+roundsaudit alreadyreusesfreshgraph underoneStorelock; doNOTblindlyremovefreshguards/cacheauthority. Need furtherboundedoptimization/profiling/replay toreduce redundantproofs whilepreservingcorrupt/deletedmarkerrefusal. Currentfix onlyfocusedrelaypending-sibling scheduling. Full3redjobs/workflowsscopeunproven.

## V26 custody inventory duplicate reconstruction optimization ACTIVE
Found exactsameoperation duplicate: audit_transport_inner scans Started andReady names independently, each invokes audit_xmr_graph_custody_provisioning_v23 which authenticatesBOTHmarkers andreconstructsfullgraph. NewlocalBTreeMap keyedparent onlywithinrostersinventory; firstcall returns(startedbytes,optionalreadybytes), secondfilenamecallsnewrecheck_xmr_graph_custody_records_v26 rereadingBOTH authenticatedrecords andrequiringexactbytes. No crosscallcache/persistedauthority/timeoutchange. Missing/changedrecord onsecondencounter rejects; firstauditstillfullyreconstructsgraph, parentload andremaininginventorychecksunchanged. HostFilesystem/StoreBusy mappingpreservedthroughcapture_host_failure. Changedsession_store.rs andxmr_graph_custody_provisioning_v23.rs. No other callerofold auditmethod found. Parseronlyacceptsexactnonzerosession Started/Ready filenames.
Before-changecompiledtest directexecution handle3089TERMINAL0: exact archived_ready_gate_revalidates_original_markers_after_every_read 1passed68.03s, baseline5895ms/combined5709ms. EnvDOM_XMR_GATE_REPLAY_V25=/home/leonardov/.dx-v23/run23-gate-replay-v25; log/tmp/branchcodex-custody-before-v26.log. Sourceeditedwhilethisoldalreadyloadedtestbinaryran, notduringcompile; measuredOLDimplementation.
NOWACTIVEhandle43208 compilingandrunningSAMEexactarchivedtest withnewsource via cargo test --locked -p dom-interopd --no-default-features --features production --lib --profile crypto-test relay_worker::readiness_gate_v25_tests::archived_ready_gate_revalidates_original_markers_after_every_read -- --ignored --exact --nocapture --test-threads=1. CARGO_BUILD_JOBS1,TMPDIR/home/leonardov/.dx-v23,samereplayenv,hostescalation; log/tmp/branchcodex-custody-after-v26.log. Needpoll43208, DONOTrestart orparalleltestagainstsamecopy. No resultyet. gitdiffcheck andscripts/check-consensus-unchanged.sh passed. Previous53676/88816/3089/44518allterminal. No fulltest/releasebuild/push. Userwantslatencyreduction; don'tclaimspeedupuntilcomparativeevidence.

## V26 custody replay passed; speedup SMALL, now profiling
43208TERMINAL0. Rebuiltcrypto-test6m31, exactreplay1passed68.32s (corrupt/deleteStartedandReadyreject,restore/sessionunchanged). Costafter baseline5691ms/combined5549ms versus before5895/5709. Combineddrop160ms=2.8%one sample; TOTAL68.03->68.32s essentiallyunchanged. DoNOTclaimmeaningfulend-to-endgain. Code dedupremainsstrictsameinventoryscope;consensuscheckpassedearlier/diffcheckpassed.
Needdominantcostmeasure beforefurtheroptimization. Added OPT-IN DEBUG_ASSERTIONS-only timing to audit_transport_inner in session_store.rs, envDOM_STORE_AUDIT_TIMINGS_V26. BTreeMaprosterclass counts/microseconds (outbound,graph-custody,graph-other,other), messagekindnumericcounts/microseconds andtotalaudit_us. PrintDOM_STORE_AUDIT_COST_V26 onlywhenenabled; nocanonicalbytes/IDs/secrets; releasecfgexcludesallinstrumentation. Allauth/errorflowsunchanged.
ACTIVEhandle6546 compiling/runningSAMEexactarchivedcustodyreplaywithprofileflag. Log/tmp/branchcodex-custody-profile-v26.log. Sameproductioncrypto-test CARGO_BUILD_JOBS1, TMPDIR/home/leonardov/.dx-v23, DOM_XMR_GATE_REPLAY_V25=/home/leonardov/.dx-v23/run23-gate-replay-v25, escalated. No newfullswap/releasebuild/push. Poll6546; previous43208/3089/88816/53676/44518TERMINAL. Needanalyzeprofilingtotalsaftertest andtargetdominantbranch, notspeculativeguardremoval.
Staticreadingwhilewaiting: readiness voteauth F7gate reconstructsReadybeforeaccepted==2; nativeclaimtransportauthboundgraph independently. But haveNOTremovedbootstrapcustodyrevalidate orchangedauthorizationboundaries; doNOTinferthoseguardsredundant withoutcompletecallcoverage.

## V26 profiling follow-up (2026-09-22)

- Handle 6546 terminated with exit 0: archived readiness corruption/deletion replay passed 1/1 in 67.28s; log `/tmp/branchcodex-custody-profile-v26.log`. Full daemon scenario remains unproven.
- Successful transport audits ~5.2s: message kinds 0x0c/0x0d/0x0e total ~2.7s; readiness 0x17 ~0.7s; outbound roster processing ~0.09s. Custody dedup remains only a small measured improvement.
- CPU sampling attempt handle 11950 terminated exit 255 BEFORE test execution: host perf_event_paranoid=4 denies events. No running test from that attempt; no system setting changed.
- Reading graph successor shows per-message origin/binding reconstruction followed by full prefix collection and authentication. Existing public signature and semantic caches already cover pure crypto; do not add authority caches blindly.
- Added development-only, opt-in graph successor timing (binding versus round), same DOM_STORE_AUDIT_TIMINGS_V26 switch. No protocol validation changes in this follow-up. Next: run archived replay and use split to target the actual expense.

- Split replay handle 49440 completed exit 0, 1/1 passed in 67.79s (`/tmp/branchcodex-graph-split-v26.log`). Graph successor binding typically 15–22ms, round ~2–6ms; these are NOT the major portion of the 2.7s grouped signature cost. Funding successors are now the remaining focus.
- Static discovery: bounded funding round still collected messages with the quadratic lexical directory scanner, unlike graph prefix/round collectors. Reused the existing physically revalidated, bounded-pass untrusted collector there. Authentication lexical order, every signed envelope, durable successor, pending-record exclusion and complete round semantic checks remain unchanged. No authority cache introduced. New funding collector edit awaits validation/measurement.

### Active validation after funding collector edit
- Handle `39915` is the only new active test/build. Sequential shell with `set -e`: archived gate replay first (`/tmp/branchcodex-funding-collector-v26.log`), then seven `graph_message_collect_` Store tests (`/tmp/branchcodex-collector-regressions-v26.log`). Poll the same handle; never duplicate the archived replay while live.
- Changes: bounded funding round now calls `xmr_graph_proposal_v22::message_collect_v25::collect_untrusted_messages_v25`; module/helper visibility widened only within Store. Existing helper retains triple physical inventory checks, bounded fallback, fresh reads and lexical authentication order. No signature, successor or authority checks removed.
- Next static finding (NOT CHANGED): `session_store.rs::authenticated_derived_transport_records_with_recovery_scope` (~17800) has an identical lexical message-collection block. It is called by `f7_ready_count_v12`, which is called by funding binding authentication through `optional_f7_funding_signing_v20`. Can reuse the same collector after current measurement and validate recovery/error semantics. This may explain additional grouped funding/readiness cost.
- Do not edit compiling Rust sources mid-build. Full daemon proof, all three red scenarios, workflow gates and publication remain incomplete. No new GitHub run or push.

## V26 functional-priority checkpoint (2026-09-22)

- Operator explicitly reprioritized: ignore further transaction-time optimization until all three real-daemon workflow scenarios are green.
- Handle `39915` completed exit 0. Archived custody/readiness replay passed 1/1 in 65.70s (`/tmp/branchcodex-funding-collector-v26.log`); collector adversarial suite passed 7/7 in 9.17s (`/tmp/branchcodex-collector-regressions-v26.log`).
- Current crypto-test binary then passed: `focused_relay_services` 2/2, `v15_receiver_does_not_retry_substituted_evidence_or_corrupt_store` 1/1, and `activation_checks_retained_receiver_before_and_after_network_round` 1/1. One earlier invocation used `--exact` with only the suffix and selected 0 tests; it is not evidence and was immediately rerun correctly.
- Static/archive refinement: Alice's pending downstream envelope is ordinal 128, scope recipient `88c9...`, route `46...`, session `d1...`; its scoped acknowledged cursor is position 126. The prior run transferred the preceding downstream envelope (connector sent=1/listener recv=1) and then the two peers repeatedly missed each other/channel-failed. This remains consistent with the sibling-listener scheduling correction now covered by the 2/2 focused tests.
- Next authorized sequence: build current release production daemon, derive and export its BLAKE2b-256, run the full claims/reopen scenario locally with a fresh evidence directory, diagnose any new terminal failure, then proceed in workflow order to DOM compensation and XMR refund. Do not push or trigger GitHub until local full scenarios prove green.

## RUN26 claims/reopen live checkpoint (2026-09-22)

- Current release build completed successfully in 4m11s. Binary `/home/leonardov/Branchcodex-two-workflows/target/release/dom-interopd` has verified BLAKE2b-256 `e01aff969082eae9d504d6bcc0cd1282ef9c5bae946226719d42241d3daf18eb`; frozen consensus check and `git diff --check` passed.
- Full scenario `native_real_daemon_two_claims_survive_original_store_reopen_v23` is ACTIVE under runner handle `52325`, evidence `/home/leonardov/dom-xmr-evidence-claims-reopen-20260922-run26`, synthetic root `/home/leonardov/.dx-v23/dx-qj7937q8/.tmprhRZuD`. Never interrupt or restart this run; poll the same handle.
- Cold preparation completed in 181322ms and export/launch in 12852ms. Both real daemons, runner, funding helper and four sidecars were verified alive; both daemons were consuming CPU.
- The run passed the prior concern around revisions 17/18. At phase 1472s all eight auxiliary signing sessions were at revision 6 and all four custody pairs were authoritatively `Started=1, Ready=1`. Main heads were Alice 26/26 and Bob 25/25 (upstream/downstream). All funding and claim projections remained `not_prepared`; therefore this is meaningful progress but not a green scenario.
- Read-only monitoring adapts `/tmp/branchcodex-run25a-status.py` in memory by replacing the evidence and fixture paths. It reads timing log events plus immutable filenames only and never opens active databases.
- User's sole current priority is functional green for the three red real-daemon jobs. Do not resume latency optimization until all three pass locally. After this run: if green, run DOM compensation then XMR refund; if failed, diagnose exact terminal evidence/archive statically before any new full run.

## CAUSA RAIZ (rodada 58) — o primeiro voto 0x17 nunca chega à sessão do par

Primeira medição com **cada linha de quórum identificada pelo daemon que a escreveu**
(`local=` em `DOM_READY_QUORUM_V25`). Rodada completa, 7452 s, deadline de fase.

```
local=3a0446  accepted=0  bound_rev=25  cur_rev=25  next=9d67f2
local=9d67f2  accepted=0  bound_rev=25  cur_rev=25  next=9d67f2
local=9d67f2  accepted=1  bound_rev=25  cur_rev=26  next=3a0446
READY ENTRY: 2x vote_for=9d67f2
SIGNER:      1x signer=9d67f2 expected=9d67f2 match=true
```

Leitura, sem inferir de ausência:

- `9d67f2` vê `accepted=0`, identifica que o voto da vez é o seu, entra no caminho de
  assinatura, assina, e **sua** sessão avança de `cur_rev=25` para `26`.
- `3a0446` permanece em `accepted=0`, `cur_rev=25`, e continua achando que o voto da vez
  é de `9d67f2`. **Ele nunca vê o primeiro voto.**

Cada lado acha que o outro deve o voto. Impasse simétrico de percepção, permanente.

Isto explica retroativamente a forense da rodada 45, que na época foi mal interpretada:
o inbox durável do par **tinha** o `0x17` do outro (sequência `0x0D`, `message_type`
`0x17`, `delivery_state=1` = *Applied*) e mesmo assim a sessão dele não avançava — 16
entradas no inbox contra 15 mensagens aplicadas na sessão.

**Defeito: um `0x17` entregue e confirmado como aplicado não avança a sessão do
destinatário.** O relay está inocentado (rodada 47: `out_backlog=false` em 80 de 80), o
envelope chega, o inbox o marca `Applied` — e a sessão de Contracts fica onde estava.

O alvo é o caminho que consome o `0x17` no destinatário:
`relay_worker.rs::accept_unseen`, ramo `PreparedContractsIngressKindV1::UniversalReadyToFundV12`
(linhas ~1591-1608), onde `accept_prepared_operational_xmr_ready_to_fund_vote_v12` é
chamado e em seguida `accept_transport_message_derived` produz o recibo. Instrumentar a
diferença entre "recibo emitido" e "revisão da sessão avançou" nesse ponto fecha o caso.


## Consolidated handoff before operator-requested pause (2026-09-22)

### Mission and success criteria

- Make these three workflow items green, in order: native_real_daemon_two_claims_survive_original_store_reopen_v23; native_real_daemon_dom_compensation_without_counterparty_v23; native_real_daemon_xmr_refund_after_public_u_without_counterparty_v23.
- Transaction-time optimization is postponed. Do not resume latency tuning until all three scenarios and their workflow-equivalent local checks pass.
- Short, unit and archive-replay tests prove only their narrow invariant. A real-daemon scenario is green only when its exact ignored test exits 0 with one passed test, all natural-exit/reopen assertions pass, and runner/fixture cleanup is verified.
- Do not push or start GitHub Actions before local proof. Working branch: feat/domxmrclaim-green. Any later commit/publication must use only Soren Planck <sorenplanck@tutamail.com>, with no coauthor trailer.

### Environment and reproducible inputs

- Repository: /home/leonardov/Branchcodex-two-workflows.
- Private environment: /tmp/branchcodex-local-xmr-env.vars. Never print it. Load with set -a; source it; set +a.
- Native fixtures use TMPDIR=/home/leonardov/.dx-v23 and umask 077.
- Production daemon build succeeded with cargo build --locked --release -p dom-interopd --no-default-features --features production --bin dom-interopd in 4m11s.
- Binary: /home/leonardov/Branchcodex-two-workflows/target/release/dom-interopd; 24,246,040 bytes; verified BLAKE2b-256 e01aff969082eae9d504d6bcc0cd1282ef9c5bae946226719d42241d3daf18eb.
- Required funding helper and four real sidecars were installed and used. Frozen consensus baseline 37d9da730b1a765671d2500fed940aeb2ecb5edd passed. git diff --check passed before RUN26.
- Native tests need host execution/escalation here because sandbox ownership/process namespaces invalidate their guards. The daemons have comm name 3 and command /proc/self/fd/3 run; absence from a dom-interopd name search does not mean death.

### Exact RUN25a failure and diagnosis

- RUN25a ended naturally after about 2h05 with: real daemon claim observation reached its explicit deadline. Cleanup and fixture cleanup were verified; it was not manually interrupted.
- All four custody pairs were Ready and all four fundings reached Final. Downstream stopped at Alice revision 38 and Bob revision 37; claims stayed not_prepared.
- Archive analysis found Alice's second downstream DSC1: sender d39f4845..., inner sequence 17, type 0x0c, successor revision 38. It was absent on Bob.
- The signed application matched Alice's relay-sender delivery-status 2 record, outer sequence 18. Its digest remained in Alice's central relay queue at ordinal 128, absent from Bob's queue/inbox. Alice's scoped acknowledged cursor was 126.
- Both stopped inbox databases passed quick_check and had empty quarantine. The message was retained on Alice's local relay; Bob had neither rejected nor quarantined it.
- The preceding downstream transfer succeeded, then the two peers repeatedly missed each other. This isolated sibling-listener scheduling/liveness, not signatures, authority, storage or consensus.

### Functional corrections under full proof

- production_composite_loop.rs: focused run_relay_leg_v25 now detects a pending sibling listener after the selected leg and services [sibling, selected] at most once through the ordinary leased/authenticated relay path. No ingress authentication, ACK, scope, signature or successor check was weakened.
- Focused relay coverage, including focused_relay_services_peer_waiting_on_sibling_after_accept_yields, passed 2/2.
- Receiver-side final claim support now separates sender progress from receiver observation. The receiver binds the transaction actually observed on-chain, retains an authenticated receiver journal/identity, does not call the sender-only progress API, and carries that identity through finality, reorganization and original-store reopen.
- Main receiver files include crates/dom-actuator/src/native_f7_receiver_claim_v25.rs, native_f7_receiver_journal_v25.rs, contracts.rs, final_claim_v14.rs, store.rs, claim_receiver_v15.rs and the interop child/runtime paths. Do not revert them during later diagnosis.
- Receiver regressions passed: v15_receiver_does_not_retry_substituted_evidence_or_corrupt_store 1/1; activation_checks_retained_receiver_before_and_after_network_round 1/1. An earlier suffix-only --exact invocation selected zero tests and is explicitly not evidence; it was rerun correctly.

### Other accumulated validated work

- Custody/readiness authentication reuses a freshly authenticated graph only within the same locked operation. Transport audit, Started/Ready records, graph byte equality, open-instance ownership, ordinary recovery rounds and exact scope digest remain enforced.
- Same-inventory duplicate custody reconstruction became one full authentication plus a second fresh record-byte recheck in that inventory operation. No persistent authority cache or removed safety check.
- Bounded funding message collection now uses the existing physically revalidated bounded collector instead of the quadratic lexical scanner. Authentication order, signed envelopes, durable successors, pending exclusion and complete-round semantics remain.
- Archived custody/readiness corruption/deletion replay passed 1/1 in 65.70s: /tmp/branchcodex-funding-collector-v26.log. Collector adversarial suite passed 7/7 in 9.17s: /tmp/branchcodex-collector-regressions-v26.log.
- Debug-only profiling is opt-in with DOM_STORE_AUDIT_TIMINGS_V26 and absent from release behavior. It showed graph successor binding/round reconstruction was not dominant. Do not continue performance work before functional green.

### RUN26 exact live state when paused

- Runner handle 52325 was still live when the operator paused work. Do not start a duplicate.
- Evidence: /home/leonardov/dom-xmr-evidence-claims-reopen-20260922-run26/native_real_daemon_two_claims_survive_original_store_reopen_v23.
- Synthetic fixture: /home/leonardov/.dx-v23/dx-qj7937q8/.tmprhRZuD.
- Command: python3 scripts/run_native_daemon_scenario_v23.py --evidence-dir /home/leonardov/dom-xmr-evidence-claims-reopen-20260922-run26 --timeout-seconds 9000 --scenario native_real_daemon_two_claims_survive_original_store_reopen_v23.
- At documentation time result.json still had status=running, returncode=null, cleanup_verified=false. That is a live state, neither success nor failure.
- Cold preparation completed in 181322ms; export/launch in 12852ms. Runner, both daemons, helper and four sidecars were alive. Later host sampling showed Alice about 73.5% and Bob 72.5% CPU, proving active computation.
- The run crossed revisions 17/18. All eight auxiliary sessions reached revision 6. All four custody pairs reached authoritative Started=1, Ready=1 around phase 1472s and stayed Ready. All four main sessions reached revision 35.
- Upstream funding for both: Committed about 2860s, Externalized about 3450s, Final about 3841s.
- Downstream funding: Committed both about 4036s; Externalized Alice about 4854s/Bob 4879s; Final Bob about 6094s and Alice about 6195s. All four funding projections were Final.
- Claims crossed the old terminal point: Alice downstream revision 41 and Bob 42, versus old 38/37. Both had durable f7-v12-claim-issued, f7-v12-claim-consumed and f7-v12-claim-binding artifacts. Immutable downstream message counts were Alice 50 and Bob 51.
- This proves the scheduler correction crossed the exact previous transport blockage. It does not yet prove green: last observed claim projections were still not_prepared; natural exits and original-store reopen were not yet reported; runner remained live.
- Last documentation read saw watchdog phase about 6460s, all four custody pairs Ready and no protocol error. After the user's pause request, no production source, build or new test was started, and the live test was not interrupted.

### Safe continuation

1. Inspect result.json and tail test.log first. If runner handle 52325 remains available, poll that handle. Never duplicate RUN26.
2. If passed, verify exactly one passed test, both natural exits, stopped-daemon finality/nonalias checks, original-store reopen, heartbeat/new exit, immutable economic snapshots, runner cleanup and fixture cleanup.
3. If failed, let archive and cleanup complete, then diagnose the exact terminal evidence and stopped fixture statically before any full rerun. Prefer a focused archive replay of the exact failed edge.
4. After verified claims/reopen green, run native_real_daemon_dom_compensation_without_counterparty_v23 with a fresh evidence directory and the same release/hash.
5. Then run native_real_daemon_xmr_refund_after_public_u_without_counterparty_v23. Its public-U/refund path must finish naturally; do not increase deadlines or accept forced termination as success.
6. Only after all three pass locally, run remaining local equivalents for interop-hardening.yml and heavy-test, review the full diff, repeat consensus/format/checks, commit with required identity, push the separate branch and inspect GitHub.

### Repository cautions

- The tree is intentionally dirty and uncommitted. At this checkpoint: 43 tracked-file modifications plus new receiver/reconciliation/replay files; roughly 3172 insertions and 381 deletions against HEAD. These are accumulated mission changes. Do not reset, discard or overwrite them.
- Earlier sections of this file contain the full chronological investigation, archives, static call chains, test commands and benchmark caveats. Use this consolidated section first, then earlier dated entries for forensic details.
- No branch push or GitHub workflow run was performed from this final local-validation stage. Do not report any of the three red jobs green without exact terminal evidence.
