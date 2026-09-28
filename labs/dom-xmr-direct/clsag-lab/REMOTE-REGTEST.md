# Participantes DOM↔XMR em hosts separados — Regtest

Este roteiro executa somente a perna DOM↔XMR dos candidatos DXA1 e DXF1. BTC
não participa. Os comandos usam Regtest, moedas sem valor e os identificadores
fixos do exemplo; eles não ativam o candidato em uma rede pública.

São necessários três hosts: coordenador, dono DOM e dono XMR. Instale em todos
o mesmo build de `arbiter_party_proxy`; os dois participantes também precisam
de `arbiter_party`, e o coordenador precisa de `arbiter_regtest` e do
`monerod` 0.18.4.0 usado pelo ensaio.

No coordenador, obtenha os parâmetros da sessão:

```sh
SETTLEMENT=$(printf '72%.0s' $(seq 1 32))
CONTEXT=$(printf '73%.0s' $(seq 1 32))
./arbiter_party_proxy regtest-bootstrap "$SETTLEMENT" "$CONTEXT"
```

Guarde os campos `chain_id` e `session` impressos. Em seguida, crie uma
identidade de cliente para cada participante. O comando imprime a chave
pública; envie somente essa chave pública ao host correspondente.

```sh
./arbiter_party_proxy identity /secure/dxa1/dom-client-noise
./arbiter_party_proxy identity /secure/dxa1/xmr-client-noise
```

Em cada host participante, crie a identidade do servidor e devolva somente a
chave pública impressa ao coordenador:

```sh
./arbiter_party_proxy identity /secure/dxa1/server-noise
```

No host do dono DOM, inicie o servidor substituindo os campos em maiúsculas:

```sh
./arbiter_party_proxy server-persistent ./arbiter_party \
  dom-owner SETTLEMENT CONTEXT CHAIN_ID /secure/dxa1/dom-owner.state \
  /secret-store/dxa1/dom-owner.wrapping-key \
  0.0.0.0:PORTA /secure/dxa1/server-noise \
  CHAVE_PUBLICA_CLIENTE_DOM SESSION
```

No host do dono XMR, use o mesmo comando com o papel e o estado correspondentes:

```sh
./arbiter_party_proxy server-persistent ./arbiter_party \
  xmr-owner SETTLEMENT CONTEXT CHAIN_ID /secure/dxa1/xmr-owner.state \
  /secret-store/dxa1/xmr-owner.wrapping-key \
  0.0.0.0:PORTA /secure/dxa1/server-noise \
  CHAVE_PUBLICA_CLIENTE_XMR SESSION
```

Restrinja cada porta ao endereço do coordenador. O Noise XX autentica e cifra
o canal. Na primeira execução, o participante cria a chave de wrapping com modo
`0600` e cifra o estado com XChaCha20-Poly1305. Guarde a chave em storage
separado do estado e faça backup seguro dos dois; perder a chave torna a share
irrecuperável. Um host que consiga ler os dois arquivos ainda precisa ser
protegido por isolamento, KMS ou HSM.

Para não manter uma chave local, substitua o argumento
`/secret-store/dxa1/*.wrapping-key` por um socket do agente externo, por exemplo
`unix:/run/dxa1/key-provider.sock`. O socket precisa ser absoluto, Unix stream e
modo `0600`; o agente deve continuar disponível depois das reconexões. O formato
binário, a política de criação/restauração e o limite do modelo estão em
[`KEY-PROVIDER.md`](KEY-PROVIDER.md). O provedor protege a chave persistente em
repouso, mas um host privilegiado ainda pode atacar a memória do signer.

O handshake deve terminar em até 15 s e cada mensagem Noise completa em até
45 s. Esses prazos incluem todos os fragmentos da mensagem; conexão silenciosa
ou fragmentação incompleta é encerrada. Configure o supervisor para reiniciar o
servidor caso o processo termine por erro local e mantenha o limite externo de
180 s para o ensaio completo.

No coordenador, crie um arquivo `remote-parties.json`:

```json
{
  "dom_owner": {
    "address": "HOST_DOM:PORTA",
    "server_public": "CHAVE_PUBLICA_SERVIDOR_DOM",
    "client_key_path": "/secure/dxa1/dom-client-noise"
  },
  "xmr_owner": {
    "address": "HOST_XMR:PORTA",
    "server_public": "CHAVE_PUBLICA_SERVIDOR_XMR",
    "client_key_path": "/secure/dxa1/xmr-client-noise"
  }
}
```

Execute o Claim financiado:

```sh
DXA1_REMOTE_PARTIES=/secure/dxa1/remote-parties.json \
  ./arbiter_regtest /caminho/monerod claim
```

Para o mecanismo rápido novo, use `fast-reorg`. Esse caso faz o compromisso
XMR, retira o Claim por uma cadeia DOM concorrente e exige a republicação do
mesmo Claim sem liberar Refund:

```sh
DXA1_REMOTE_PARTIES=/secure/dxa1/remote-parties.json \
  ./arbiter_regtest /caminho/monerod fast-reorg
```

Para o DXA1, o resultado final deve conter `"remote_participant_servers":true`,
`"participant_restart_restored_bound_shares":true` e um tempo positivo de
`ready_to_complete_seconds` de no máximo 180 segundos. Ele também deve registrar
`"bounded_noise_handshake_and_message_deadlines":true`, alvo DOM de 120 s,
espera nominal de 240 s para duas confirmações e
`"dom_two_confirmations_nominally_fit_three_minutes":false`. O tempo rápido
mede somente o Regtest acelerado. Para validar todo o caminho numa única máquina
antes de distribuir os hosts:

```sh
python3 -B scripts/test_arbiter_remote.py \
  --binary target/debug/examples/arbiter_regtest \
  --party target/debug/examples/arbiter_party \
  --proxy target/debug/examples/arbiter_party_proxy \
  --monerod /caminho/monerod
```

O runner específico do DXF1 também valida os hashes do bloco órfão, da nova
inclusão e da ponta final, além da continuidade dos servidores:

```sh
python3 -B scripts/test_fast_handoff_remote.py \
  --binary target/debug/examples/arbiter_regtest \
  --party target/debug/examples/arbiter_party \
  --proxy target/debug/examples/arbiter_party_proxy \
  --monerod /caminho/monerod \
  --outcome fast-reorg \
  --evidence-file /caminho/novo/dxf1-fast-remote-reorg.json
```

Se Docker estiver disponível, o ensaio mais forte coloca coordenador e os dois
participantes em três namespaces de rede e sistemas de arquivos separados, numa
rede interna sem rota externa:

```sh
python3 -B scripts/test_arbiter_containers.py \
  --binary target/debug/examples/arbiter_regtest \
  --party target/debug/examples/arbiter_party \
  --proxy target/debug/examples/arbiter_party_proxy \
  --monerod /caminho/monerod \
  --outcome fast-reorg \
  --timeout 300 \
  --evidence-file /caminho/novo/dxf1-container-reorg.json
```

O arquivo deve registrar `three_distinct_network_namespaces`,
`participant_state_mounts_separate` e
`coordinator_has_no_participant_state_mount` como verdadeiros. Isso valida a
separação lógica no mesmo host; o ensaio físico de três hosts permanece a etapa
seguinte.
