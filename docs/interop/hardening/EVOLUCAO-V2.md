# Evolução V2 — pré-requisitos para a meta 10/10

Esta versão **acumula integralmente a V1** e implementa os pré-requisitos abaixo.
Base: `mainnetswap`, `7d9d41a1fd4a67ed25bf437846c739ee18f5cb36`.
Branch: `interop/security-hardening-20260908`. Não houve commit novo nem push.
ZIP anterior: SHA-256 `96168641e993a8062b49788ddfb6e7efd3302f1eccb6eebedf85bc6bf2d498c2`.

O objetivo continua sendo o plano completo de 10/10. **Esta versão ainda não
atinge esse objetivo.** O claim Bitcoin/M.8 não foi conectado ao production root,
e nenhuma das quatro rotas completas foi demonstrada por esta entrega.

## Executar

Extraia em uma pasta nova e entre em `dom-protocol`. Linux, Python 3 e Git:

```bash
python3 scripts/test_interop_hardening.py --mode offline
```

Esse comando executa o novo verificador independente, seus vetores públicos e
regressões adversariais. Usa somente a biblioteca padrão do Python e não precisa
de RPC, wallet ou conexão com uma blockchain.

Com as ferramentas Rust/C, Bitcoin Core e Foundry indicadas na entrega V1:

```bash
python3 scripts/test_interop_hardening.py --format --mode full
```

Para os testes Rust sem Bitcoin Core/Foundry:

```bash
python3 scripts/test_interop_hardening.py --format --mode components
```

Os modos `components` e `full` também incluem o verificador independente.
Agora incluem explicitamente os pacotes `kaystra-core` e `solana-kaystra-source`,
afetados pelo checkpoint de observações. O comando retorna 2 se faltarem
ferramentas, 1 em falha e 0 quando os comandos daquele modo terminarem com sucesso.
Logs e JSON são gravados em `artifacts/interop-hardening/`.

**Aqui foram executados os 10 testes Python**, incluindo os 19 vetores BIP340,
o vetor BIP341 SIGHASH_DEFAULT e as mutações de transação. Todos passaram.
O Rust **não foi compilado nem testado aqui**: cargo, rustc, clang, cmake e
pkg-config continuam ausentes. Os testes Rust novos estão escritos, não aprovados.
O relatório anexado registra o bloqueio; não reutiliza resultados do CI antigo.

## Código implementado

### Bitcoin: vinculação da autorização M.8 ao claim

`AnchoredCrossChainWindowV1` retém o txid de funding Bitcoin e a rede que passaram
pela validação da política e das âncoras. A nova operação
`validate_bitcoin_claim` confere esses campos, o hash dos termos e o prazo CSV,
incluindo a distinção entre blocos e unidades de 512 segundos. Funciona com a
perna Bitcoin antes ou depois da perna DOM na janela.

O actuator executa essa verificação **antes de qualquer alteração no journal ou
acesso ao nonce vault**, nas operações de exposição do nonce, produção da parcial
e agregação. As respostas já persistidas passam pelo mesmo controle no replay.
As funções internas do signer também fazem a verificação.

As regressões cobrem troca de termos, rede, txid e prazo; recusa sem criação de
transcript; nonce em cache; parcial em cache; retomada com fencing novo; e ambas
as ordens/unidades da janela. A fixture de assinatura existente usava M.8 para
10 blocos enquanto seu contrato usava CSV de 144 blocos; foi ajustada para uma
janela coerente com o contrato real da fixture.

Isso fecha uma lacuna de vinculação no componente. **Não produz prova de inclusão
ou finality por si só**, não substitui o scanner F7 e não autentica mensagens de
um participante remoto. Os codecs/digests M.8 existentes foram preservados; os
campos adicionais são internos à autoridade Rust. A composição distribuída M.8,
o transporte entre participantes e a instalação do claim no root permanecem abertos.

### Solana: observação atômica e recuperação sem perda de histórico

O pump passa a usar `persist_observation`, que grava âncora, evento, revisão e tip
na mesma transação SQLite. Observar uma transação antiga não apaga eventos mais
novos nem diminui o tip. Repetições idênticas não criam revisões novas; conflito
de âncora, slot ou ação recusa a transação inteira.

O banco fica vinculado persistentemente à cadeia, settlement e termos, inclusive
quando vazio. O índice único por settlement/txid/instruction-index impede mudar
o tipo de evento para a mesma instrução. A migração de V1 recusa identidades
incompatíveis ou eventos ambíguos.

O cursor V2 conserva a revisão do feed. Eventos descobertos depois que o scanner
avançou provocam releitura idempotente; substituição explícita de histórico
provoca invalidação. O journal conserva a primeira âncora retirada, permitindo
emitir invalidação mesmo quando ela saiu do histórico limitado a 512 âncoras.
Isso permite detectar uma reorganização profunda; não demonstra que qualquer
reorganização seja economicamente recuperável.

O scanner confere novamente a revisão ao terminar. Se houve uma gravação
concorrente, recusa o lote com `StaleCursor`, preservando o cursor anterior.
O método adicional `ChainSourceV1::cursor_at_from_scan` permite ao engine gerar
checkpoints seguros sem reconhecer uma revisão que não foi lida. Outros adapters
mantêm a implementação padrão; Solana conserva a revisão do scan, inclusive
quando o checkpoint cai em slot sem bloco.

Os testes novos usam o store SQLite e o source reais: ordem invertida,
duplicação, conflito com rollback, reabertura, binding vazio, migração,
reorganização dentro/fora do histórico, gravação concorrente e checkpoint seguro.
São testes escritos; dependem da execução Rust no seu ambiente.

**Compatibilidade:** o decoder aceita cursor V1 e emite V2. Os esquemas V1
permanecem, com tabelas/índice adicionais. Depois da migração, use somente
binários novos para escrever nesse banco: um writer V1 não mantém o journal
V2. Pare os processos e preserve uma cópia do banco antes do teste de migração.
O journal de revisões ainda não tem compactação; o crescimento deve ser medido
antes de uso prolongado. A rota Solana continua bloqueada no root de produção.

### Segundo verificador: claim Bitcoin independente

`scripts/bitcoin_claim_oracle.py` implementa parsing canônico de transações,
txid, BIP341 SIGHASH_DEFAULT e verificação Schnorr BIP340 sem importar nenhum
componente Rust da DOM. Confere o outpoint, os scripts congelados, o pagamento
do principal menos a taxa exata, e a assinatura do claim key-path de uma entrada
e uma saída. Recusa annex, sighash explícito, bytes extras, CompactSize não
canônico, tipos JSON ambíguos e alterações na assinatura/pagamento.

Para verificar um caso próprio com os campos do exemplo:

```bash
python3 scripts/bitcoin_claim_oracle.py meu-caso-publico.json
```

Exemplo executável, **sintético e sem vínculo com fundos reais**:

```bash
python3 scripts/bitcoin_claim_oracle.py scripts/tests/vectors/synthetic-bitcoin-claim.json
```

Os txids JSON usam a ordem exibida pelo Bitcoin Core. `funding_transaction` e
`claim_transaction` contêm os bytes de consenso em hex. `principal_sat`, `fee_sat`
e `funding_vout` são inteiros. Os campos `expected_*`, os scripts e os valores
devem vir de termos autenticados por uma fonte independente do produtor da
transação. O verificador não atesta esses termos nem liga sozinho o route_id a
uma prova criptográfica do protocolo.

O resultado `verified-offline` atesta somente esse recorte. Não verifica inclusão
em bloco, finality, assinaturas dos inputs do funding, refund, extração do segredo
adaptor, DLEQ nem as pernas DOM/EVM. O verificador é uma segunda implementação;
**não equivale a uma auditoria feita por outra equipe**.

Os vetores públicos foram obtidos do repositório oficial
[BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv) e
[BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json).
Os JSON preservam os hashes dos arquivos de origem; só os campos públicos
necessários foram incorporados. As fontes normativas são
[BIP340](https://bips.dev/340/) e [BIP341](https://bips.dev/341/).

## Correspondência com o objetivo 10/10

| Frente | Implementação nesta sequência | Falta para encerramento |
|---|---|---|
| Pré-requisitos 9/10 | V1 preservada; V2 fortalece C02/C05/C11. | Compilar e executar Rust; fechar os demais pacotes. |
| Rotas pelo binário real | Guard temporal conectado na V1; validação M.8 reforçada na V2. | Claim/transporte M.8, fonte EVM e campanha BTC→DOM→EVM, EVM→DOM→BTC, BTC→DOM→BTC, EVM→DOM→EVM. Nenhuma dessas quatro rotas foi encerrada por esta entrega. |
| Verificação formal | Nenhuma prova/modelo formal novo entregue. | Modelar, verificar e ligar as propriedades à implementação. |
| Validação independente | Oracle Python executável e validado no recorte claim BTC. | Refund, demais pernas, provas e comparação com bytes de swaps do daemon. |
| Fronteiras de confiança | Authority M.8 mais estrita; origem dos pins do oracle explícita. | Revisão/testes completos de signers, RPCs, ativos e sidecar XMR. |
| Recuperação extrema | Regressões SQLite/cursor e M.8 após reinício escritas. | Executá-las; fault injection em todas as fronteiras do daemon e campanha combinando reorg/fees/indisponibilidade. |
| Privacidade | Nenhum experimento novo entregue. | Modelo de correlação e medições entre pernas. |
| Auditorias complementares | Nenhuma auditoria externa realizada. | Criptografia e execução distribuída revistas independentemente no commit candidato. |
| Operação reproduzível | ZIP cumulativo, patches, hashes, comandos e logs reais. | Builds/SBF reproduzidos e recuperação por operador independente. |

A prioridade seguinte de integração continua sendo Bitcoin/M.8 e claim no root,
seguida da fonte pública EVM e da execução integral das rotas. Os pré-requisitos
não mudam essa prioridade nem autorizam atribuir a nota antes das evidências.
