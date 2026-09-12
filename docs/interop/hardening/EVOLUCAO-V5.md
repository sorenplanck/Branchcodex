# DOM — evolução cumulativa V5

Base oficial: `mainnetswap`, commit `7d9d41a1fd4a67ed25bf437846c739ee18f5cb36`.
V4 preservada: SHA-256 `8ed4c7dfd147ac3594ac7b929416ecd40c20cf9ab8b55a7c016da83c5afaf559`.
Esta entrega contém código aplicado sobre a V4, testes e comandos de execução.

## Mudança de comportamento

| Fronteira | V4 | V5 |
|---|---|---|
| Prova temporal atualizada | Método de instalação sem fonte concreta no runtime | Inbox ligado ao root, consultado antes de preparar novo funding, revalidar plano novo ou renovar seu fence |
| Publicação de prova | Sem ferramenta nesta entrega | Publicador Python verifica assinaturas públicas e escopo, faz substituição atômica e sincroniza arquivo/diretório |
| Quorum XMR | Grupo ancorado na primeira resposta de inclusão | Agrupa todos os pares altura/hash e exige maioria estrita dos endpoints configurados |
| Inclusão XMR | Localização e header consultados separadamente | Txid exato, participação na lista de transações do bloco, releitura do header e genesis |
| Confirmações XMR | Contagem com incremento adicional | Comprimento da cadeia menos altura de inclusão, limitado pelo menor comprimento entre os votantes concordantes |
| Reconciliação de broadcast | Qualquer elemento em `txs` podia significar conhecida | Só aceita uma transação com o txid solicitado; ausência exige `missed_tx` exato |
| Recusa permanente | Actuator convertia todos os erros em `accepted=false` | `BroadcastRejected` chega ao child como `Refused`; mantém `SendAttempted` e os bytes para recuperação |
| RPC local | Validação textual e comportamento padrão de redirects | URL analisada, sem credenciais, caminho extra, query, fragmento, proxy ou redirects |

## C06 — atualização temporal conectada

`crates/dom-interopd/src/production_time_inbox.rs` retém a capability do diretório
de estado já aberto pelo runtime. Lê apenas `route-time-refresh.v2`, arquivo regular
do usuário atual, modo 0600, sem hardlink/symlink, limitado a 16 KiB. Confere identidade
e metadados antes/depois da leitura. A abertura não bloqueante evita espera em FIFO
introduzido entre as verificações; não constitui prazo absoluto de I/O em disco.

`production_time_guard.rs` encaminha o candidato ao mesmo `DurableRouteTimeAnchorStoreV2`
que autentica política, autoridades, sequência, âncoras e ancestralidade antes de
emitir a autorização contextual de funding. Ler um arquivo não autoriza funding.
`production_run.rs` conecta essa fonte à capability real do estado. Não modifica
o artefato inicial autenticado em `inputs/time-evidence.v2`.

Arquivo ausente conserva a exigência de prova corrente válida no journal. Arquivo
presente inválido recusa a nova preparação. Claim, refund e recuperação de funding
já comprometido não consultam esse inbox. O construtor não lê o inbox, para uma
falha de transporte não impedir por si só a inicialização para recuperação.

Os testes Rust adicionais usam assinatura real de autoridades de teste, o wrapper
de persistência, SQLite e reabertura: expiração seguida de refresh, persistência
sem a cópia de transporte, assinatura inválida, substituição válida, corrupção,
permissões, aliases e equivocation assinada com invalidação durável.

`scripts/time_evidence_oracle.py` verifica independentemente o formato público
DOMRTSE2, assinaturas BIP340 sobre o digest BLAKE2b, limiar, ordem dos signers,
escopo, sequência e janela temporal. Não verifica toda a escada temporal, política
ou ancestralidade; esses controles continuam no Rust. Os pins do operador devem
vir da configuração de confiança, nunca de um arquivo recebido sem autenticação.
Os pins exportados pelo teste Rust servem à comparação entre implementações,
não à descoberta das autoridades confiáveis de produção.

`scripts/publish_time_refresh.py` não cria assinaturas nem guarda chaves. Recebe
prova assinada por autoridades externas, verifica os pins e publica com lock,
arquivo temporário exclusivo, rename e fsync. Impede rollback/equivocation do
snapshot publicado e substituição entre escopos. Retry idempotente completa o
fsync do diretório mesmo se uma tentativa anterior falhou depois do rename.

Uso operacional, quando as autoridades reais já fornecerem a prova e os pins:

```bash
python3 scripts/publish_time_refresh.py --signed /caminho/prova-assinada.v2 --pins /caminho/pins-confiaveis.json --state-dir /caminho/estado-da-rota
```

O diretório existente deve ser do operador, modo 0700. Os campos do JSON de pins
são `public_keys` (lista ordenada de chaves x-only hex), `threshold`,
`minimum_sequence`, `policy_digest` e `route_scope_digest`. A geração operacional
das provas continua sendo responsabilidade das autoridades configuradas.
Não publique fixtures de teste como evidência operacional.

## C09 — Monero, identidade e quorum

`xmr-rpc-broadcast-blocking` exige resposta para a identidade consultada.

| Resposta de `/get_transactions` | Resultado da consulta de conhecimento |
|---|---|
| `status=OK`, confiável, `txs=[]`, `missed_tx=[txid solicitado]` | `Ok(false)` — ausência explícita |
| Uma transação exata, sem entradas em `missed_tx` | `Ok(true)` — conhecida |
| Outro txid, miss para outro txid, duplicidade, contradição ou ambas as listas vazias com status OK | `Err(SpendPortError::Rejected)` — resposta permanentemente inválida |
| HTTP/transport indisponível, daemon ocupado ou resposta marcada não confiável | Erro, sem voto de ausência |

`xmr-actuator` propaga a recusa permanente como `BroadcastRejected`; o executor
Monero a traduz para `ChildAuthorityRefusalV1::Refused`. Não a transforma em
resposta negativa. O estado já persistido permanece `SendAttempted`, pois uma
resposta inválida não prova que uma transmissão anterior deixou de ocorrer.
Bytes não são apagados nem reconstruídos. O teste de regressão reabre o banco
e confere essa retenção. Falha transitória conserva o resultado ambíguo anterior.

O observador exige o txid exato na lista do bloco informado e confirma o mesmo
header após obter o comprimento da cadeia. Genesis é conferido antes/depois.
Isso é corroboração entre respostas RPC sob as premissas dos daemons; não é uma
verificação independente do consenso ou da prova de trabalho Monero.

`production_xmr_quorum.rs` separa ausência, mempool, inclusão e falha. Falhas
abstêm-se, sem reduzir o denominador nem virar votos negativos. A maioria pode
prosseguir com os outros votantes válidos. Um key image reportado gasto por uma
observação válida veta a conclusão de não gasto. Quorum deve ser maior que N/2,
com 1–16 endpoints. Aliases da mesma porta local não contam como dois votantes.
Portas diferentes não demonstram independência física: essa continua sendo uma
premissa de configuração; 1 de 1 continua confiando em um único daemon.

As consultas são concorrentes por endpoint, com um máximo de 16 threads e limites
por requisição de 5 s de conexão/30 s total. Uma observação completa pode executar
seis requisições sequenciais por daemon; isso não é deadline global de 30 s.
Respostas JSON são limitadas a 4 MiB e redirects são recusados.

A contagem de confirmações usa a semântica documentada de `get_height` como
comprimento da cadeia: [documentação oficial Monero](https://www.getmonero.org/resources/developer-guides/daemon-rpc.html#get_height).
Uma transação no bloco de índice 100 com comprimento 101 tem uma confirmação.

## Executar e observar

Extraia o ZIP em uma pasta nova e entre em `dom-protocol`:

```bash
python3 scripts/test_interop_hardening.py --format --mode runtime
```

Esse comando roda Python, testes do transporte HTTP Monero e actuator, toda a
suíte `dom-interopd` de produção, exporta trace de rotas e prova temporal do Rust,
e executa os respectivos verificadores Python. Ausência do arquivo Rust exportado
ou divergência faz o comando falhar; não existe substituição por fixture sintética.

Regressão cumulativa: `python3 scripts/test_interop_hardening.py --format --mode components`.
Suítes existentes com Core/Foundry/Anvil: `python3 scripts/test_interop_hardening.py --format --mode full`.
Sem Rust: `python3 scripts/test_interop_hardening.py --mode offline`.

Pré-requisitos: Linux, Python 3, Git, Rust/Cargo/rustfmt, compilador C, clang,
cmake, pkg-config e dependências Cargo via cache/rede. O workflow existente usa
Rust 1.96.1. `full` também exige Bitcoin Core, Foundry e curl. O script não instala
ferramentas. `--format` registra o hash após formatação. Resultados e logs ficam
em `artifacts/interop-hardening`; saídas 0/1/2 significam conclusão/falha/bloqueio.

## Evidência e limites desta entrega

36 métodos Python passaram aqui, contra 23 na V4: 13 novos cobrem o verificador
temporal e a publicação, inclusive falhas antes/depois do rename. Testes Rust
foram escritos, mas não compilados/executados neste ambiente sem toolchain.
A checagem auxiliar da gramática Rust não verifica tipos, linking ou execução.
A comparação cruzada Rust/Python depende da execução no ambiente de testes.
O `Cargo.lock` da V4 foi preservado; foi habilitada a feature `fs` do rustix já
declarado, sem adicionar uma biblioteca ao lock nesta versão.

As mudanças Monero estão na fábrica concreta; o bootstrap root continua limitado
a EVM+BTC e ainda não conecta SOL/XMR ou pares da mesma família. Novos planos BTC
continuam recusados pela integração pendente de scope/M.8. Não foram executados
swaps de produção. As 16 combinações via DOM continuam no objetivo e no status
por rota, mas não estão operacionalmente concluídas. Esta V5 não recebe 10/10.

Permanecem: bootstrap por duas pernas independentes; readiness/M.8 com recuperação
real; operação das autoridades temporais; campanha de crash/reorg/fees pelo
binário real; provas formais ligadas à implementação; privacidade e auditorias
independentes. `STATUS-META-10.json` registra essas pendências sem pontuação fictícia.

Na raiz do ZIP, `COMPARACAO-V4-V5.json` discrimina arquivos idênticos, modificados,
novos e removidos, hashes e linhas por arquivo. `V4-PARA-V5.patch` reproduz o
incremento; `ALTERACOES.patch` é cumulativo desde o commit oficial. Os patches já
estão aplicados na branch entregue. Histórico e evidências V1–V4 permanecem no ZIP.
