# DOM — código aplicado na V6

Base oficial: `mainnetswap`, commit `7d9d41a1fd4a67ed25bf437846c739ee18f5cb36`.
Incremento sobre a V5, SHA-256 `11a04e565b31623369cf012ab3c0b48e0f62f981cf6260cc31d9539586c4c767`.

Esta V6 entrega provisionamento de autoridades Bitcoin por perna, um driver
completo da troca de assinatura de claim por socket local e dois verificadores
independentes. O restante das alterações V1–V5 está preservado.

**A V6 não conclui os oito pacotes do plano anterior.** Ela implementa parte
dos pré-requisitos de inicialização/autoridades, o componente de troca pós-âncora,
testes locais de recuperação e verificadores. O root ainda exige EVM+BTC e não
conduz a prontidão bilateral que permitiria habilitar funding novo. Não foram
executadas as 16 rotas completas. Código Rust não foi compilado neste ambiente.

## 1. Autoridades de assinatura por perna

`crates/dom-interopd/src/production_chain_signers.rs` passa a guardar dois slots
posicionais de autoridade Bitcoin. Cada slot possui chave autorizada pelo roster,
cofre de nonce e chave de selagem próprios. A presença de cada credencial deve
corresponder exatamente à presença de uma perna Bitcoin autenticada. São aceitas
zero, uma ou duas pernas Bitcoin; uma credencial extra, ausente ou zero recusa.
As duas autoridades representam o mesmo participante local em settlements
distintos, nunca as duas chaves contrapostas de uma mesma rodada.

O novo `provision_production_chain_signers_v6` deriva a selagem com binding de
rota, termos, participante, posição e papel. Cria arquivos Bitcoin distintos para
upstream/downstream. O mesmo segredo local, se legitimamente previsto nos dois
rosters, não compartilha identidade de sessão/cofre/selagem entre as pernas.

O provisionamento verifica os bindings de ambas as chaves antes de abrir cofres,
recusa aliases e trata prefixos ordenados de criação com dois, três ou quatro
bancos. Em retomada, apenas a última autoridade publicada pode estar em criação
parcial; as anteriores precisam estar inicializadas e economicamente vazias.

O root existente chama o wrapper V1, que agora delega a essa implementação.
Esse wrapper preserva o caminho Bitcoin e o digest V1 originais para compatibilidade
com a V5. A API nova usa nomes/digest V6. A seleção de uma única perna Bitcoin
passou a retornar erro quando houver zero ou duas; o root trata esse erro.

O carregador de credenciais do root ainda é V3/V10 e seleciona EVM+BTC. A API
generalizada não é uma migração automática de journals nem libera rotas por si só.
F6, serviços por perna e formatos de bootstrap continuam precisando de integração.

## 2. Driver Bitcoin executável

Novo `crates/btc-actuator/src/claim_driver.rs`:

1. Pede ao signer a exposição ou reprodução do nonce local persistido.
2. Troca mensagens autenticadas de nonce.
3. Pede ao signer a validação do nonce remoto e a produção/reprodução da parcial.
4. Troca as mensagens de parcial vinculadas ao transcript.
5. Valida e agrega pelo signer local, devolvendo sua conclusão opaca.

O driver não possui contador próprio de nonce ou journal concorrente. Em retry,
recomeça na fase de nonce e utiliza os registros persistidos pelo actuator/cofre.
Uma falha não apaga registros, não cria nova tentativa de assinatura e não
constitui autorização de funding.

`UnixBitcoinClaimTransportV6` usa um socket conectado, envelope `DOMBTCX6` de
12 bytes e os frames autenticados V3. Valida fase, tamanho e framing antes de
aceitar o pacote. O máximo é 270 bytes por mensagem. As operações de leitura/
escrita recalculam o prazo restante; o prazo configurável por troca é positivo
e limitado a 60 segundos. Peer silencioso, pacote truncado, tamanho excessivo e
fase trocada resultam em erro, nunca em conclusão da rodada.

O transporte não comprova a identidade do peer por si só: a assinatura V3 e o
roster fixado são verificados pelo actuator antes de vincular o nonce remoto.
O envelope não é uma mensagem DSC1 nem foi registrado como um novo tipo Relay.

`ProductionBitcoinParticipantAuthorityV1::drive_claim_v6` conecta esse driver
aos métodos reais de assinatura V3 e ao actuator retido. Seu callback deve obter
nova `ProductionLocalBitcoinM8AuthorizationV2` em cada uma das três operações.
Essa capability só é consumida pelo mesmo participante/leg/role autorizado.
A conclusão mantém o handoff opaco `ProductionBitcoinCompletedClaimV3`.

O driver está implementado como componente completo. O root ainda precisa
possuir o transporte e conduzir prontidão bilateral, F7 e recuperação para
invocá-lo com todas as condições satisfeitas. Não foi habilitado funding apenas
preenchendo o scope ausente.

## 3. Testes Rust novos

`crates/btc-actuator/tests/support/driver_v6.rs`, incluído pela suíte
`participant_signing`, usa dois participantes reais de teste, dois cofres,
dois actuators SQLite, sockets Unix e MuSig2/adaptor reais:

- Troca completa e finalização da mesma transação pelos dois participantes;
  três autorizações locais solicitadas por participante.
- Interrupção após persistência das parciais, fechamento físico/reabertura dos
  bancos, reconexão e comparação byte a byte de todos os frames reproduzidos.
- Frame remoto adulterado recusado antes de persistir uma parcial local.
- Peer silencioso e envelopes de tamanho/fase inválidos.

O teste de retomada reabre sob o mesmo owner/fence ainda válido. Takeover com
novo fence tem cobertura anterior na suíte V3; não está sendo apresentado como
um novo teste desta V6. Funding, âncoras e destinatário do fixture são sintéticos;
esta suíte não transmite uma transação para Bitcoin Core.

A suíte de provisionamento acrescenta as 16 combinações de presença de famílias
com correspondência exata das credenciais Bitcoin, todos os prefixos de criação
de 2–4 bancos e aliases de caminhos. Esses testes de forma/prefixo não constituem
um bootstrap completo de 16 rotas.

## 4. Verificadores independentes

`scripts/bitcoin_driver_oracle.py` recebe a transação final exportada pelo teste
Rust e verifica por Python seu BIP340/SIGHASH_DEFAULT, prevout, script do contrato,
destinatário, principal e taxa exatos. Os pins de prevout precisam ser autenticados
externamente. O verificador não prova que o funding existe na cadeia. No teste
cruzado, os pins vêm do fixture Rust: isso mede concordância entre implementações,
não confiança independente numa transação de produção.

`scripts/route_economics_oracle.py` recebe dois JSONs separados: termos fixados
(`--pins`) e observações (`--witness`). Exige dois settlements, quatro locks
(DOM e contraparte em cada perna), identidades exatas e conservação por chain/ativo.
Não soma valores de moedas diferentes. Verifica destinatário, principal, taxas
deduzidas, mínimo de recebimento, duplicação de eventos/effects e claim/refund
mutuamente exclusivos. Doações ficam registradas como saldo excedente residual.

Aceita três classes contábeis terminais:

- `settled`: os quatro principals financiados e resgatados pelos destinatários.
- `compensated`: todo principal efetivamente financiado devolvido ao funder;
  permite funding unilateral recuperado.
- `aborted`: nenhum principal foi financiado.

Essas classes são do verificador, não uma alegação de equivalência formal a todas
as semânticas de compensação do protocolo. Compensações alternativas precisam de
outro witness/modelo; o verificador as recusa em vez de inventar uma equivalência.
Custos de gas pagos fora do principal e redistribuição de excedentes não são
modelados. `finalized=true` no JSON é uma premissa do coletor, nunca prova de
consenso. O resultado declara explicitamente que inclusão/consenso não foram
verificados. Não existe ainda coletor universal ligado aos quatro RPCs e à DOM.

Os exemplos de schema e as mutações adversariais estão em
`scripts/tests/test_route_economics_oracle.py`. Para usar observações já coletadas:

```bash
python3 scripts/route_economics_oracle.py --pins /caminho/termos.json --witness /caminho/observacoes.json
```

## 5. Executar a V6

Extraia o ZIP em uma pasta nova, entre em `dom-protocol` e execute:

```bash
python3 scripts/test_interop_hardening.py --format --mode v6
```

Roda todos os testes Python, os testes Rust do novo driver e sua verificação
Python cruzada, a suíte dom-interopd de produção e os verificadores V4/V5 dos
exports de rota/tempo. Se o Rust não exportar o arquivo da transação, o comando
falha; não substitui o arquivo por fixture Python.

Regressão cumulativa: `python3 scripts/test_interop_hardening.py --format --mode components`.
Regtest/Foundry/Anvil existentes: `python3 scripts/test_interop_hardening.py --format --mode full`.
Sem Rust: `python3 scripts/test_interop_hardening.py --mode offline`.

Linux, Python 3, Git, Rust/Cargo/rustfmt, compilador C, clang, cmake, pkg-config e
dependências Cargo via cache/rede são os pré-requisitos. O workflow existente usa
Rust 1.96.1. `full` exige também Bitcoin Core, Foundry e curl. O runner registra
logs e hashes em diretórios exclusivos sob `artifacts/interop-hardening/`.

O comando `--mode routes --all` anunciado no plano ainda não foi implementado.
O modo `v6` identifica testes de desenvolvimento; não declara uma campanha de
swaps on-chain. Nenhuma ferramenta é instalada automaticamente.

## 6. Evidência desta entrega

50 métodos Python passaram aqui: 36 preservados, 4 novos do claim final e 10 novos
do verificador contábil. Um dos novos métodos percorre 48 casos sintéticos:
16 pares × 3 classes terminais. Isso não corresponde a 48 swaps executados.

Rust e os testes cruzados não foram compilados/executados por ausência de
toolchain. A checagem de gramática dos arquivos Rust alterados não encontrou
erros, mas não verifica tipos, linking ou comportamento. O lockfile/dependências
foram preservados nesta V6.

O ZIP inclui fontes, índice Git, patch cumulativo, incremento V5→V6 e comparação
dos bytes de todos os fontes com a V5. Os patches já estão aplicados.

## 7. Estado do plano de oito pacotes

| Pacote anunciado | Estado real nesta V6 |
|---|---|
| Inicialização universal | Pré-requisito de recursos Bitcoin por perna implementado; root/F6/serviços ainda pendentes |
| Autoridades por perna | Zero/uma/duas autoridades Bitcoin implementadas; signers SOL/XMR e carregador universal pendentes |
| Prontidão e M.8 | Driver de troca e bridge local implementados; prontidão bilateral e chamada pelo root pendentes |
| Execução Solana completa | Integração nova ao root não entregue |
| Execução Monero completa | Integração nova ao root não entregue; preserva correções V5 |
| Recuperação integrada | Novo teste de queda/reabertura da rodada Bitcoin; campanha da rota inteira pendente |
| Laboratório pelo binário real | Comando de testes V6 entregue; laboratório universal de swaps pendente |
| Verificador econômico | Verificação independente de claim BTC e contabilidade implementada; coleta/validação de consenso universal pendente |

O objetivo continua sendo as 16 combinações com a DOM no centro. A nota 10/10
não foi atribuída. `STATUS-META-10.json` mantém os bloqueadores por rota e a
distinção entre código escrito, teste executado e integração operacional.
