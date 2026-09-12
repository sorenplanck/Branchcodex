# V15 — receptor do claim e integração de verificação

Esta versão contém código cumulativo sobre a V14. **Ainda não conclui os três critérios de aceitação nem as 16 rotas.** Não contém um executável compilado. Os testes Rust novos foram escritos e não executados neste ambiente; Cargo e rustc estão ausentes.

## Código entregue

- `dom-scriptless-store/.../claim_receiver_v15.rs`: material público rederivado do perfil nativo F7, observação durável antes de exposição e extração, retomada do sucessor exato e autoridade de ingresso `0x12` vinculada à abertura do Store. Identidade, papel, sessão, chain, transação, template, output compartilhado e transcript são cruzados. Equívocos assinados usam o journal nativo.
- `adapters/dom-real/src/f7_claim_receiver_v15.rs`: descoberta do spend do output congelado, verificação da pre-signature contra a assinatura final, ancestralidade até uma única ponta observada e revalidação antes da extração. O consumidor exige um token de observação emitido pelo Store.
- `production_claim_receiver_v15.rs` e `production_run_universal.rs`: o worker é chamado para as duas pernas DOM antes de drenar Relay. Recebe o scanner que já pertence ao filho DOM. Não abre outro banco, signer ou cliente de chain externa.
- `production_plan_source.rs`: a fonte instalada de segredo público aceita a observação nativa F7 e verifica novamente sessão, chain, txid, papel e ponta canônica. A autorização da rota e a retenção selada existentes continuam exigidas. O verificador legado passa a ser construído no momento da extração.
- `production_child_dom.rs`: deixa de exigir os verificadores pós-funding na construção inicial. A observação de finalidade escolhe o perfil nativo no momento da operação.
- `dom-actuator/src/final_claim_v14.rs` e `adapters/dom-real/src/terminal_finality.rs`: finalidade do emissor F7 sem fabricar uma autoridade M.8 Bitcoin. Reutiliza o checkpoint terminal cercado por lease e o revalidador de reorg existente. Não extrai o segredo para validar finalidade.

## Fronteiras e recuperação

A observação carrega a ponta usada pelo verificador concreto de ancestralidade. O Store valida a prova de abertura criptográfica, a identidade da operação e sua genealogia persistida. A cadeia canônica continua sendo verificada no adapter; o Store não vira um light client. O tag da observação não é autoridade de papel: o papel é rederivado do vínculo congelado e do signer local.

Se a ponta mudou, o receptor primeiro registra uma projeção reversível obtida **da mesma observação**, depois publica `DOMFOB15` com o predecessor e o sucessor de exposição exatos, e finalmente grava o sucessor. Falha antes do marcador exige nova observação; marcador completo antes do sucessor é recuperado pelo plano de abertura após auditoria. Registros órfãos/adulterados não são convertidos em ausência nem apagados como staging válido. A recuperação mantém a identidade física do arquivo-fonte.

O marcador é evidência histórica de exposição e permanece após reorg. A extração faz uma nova consulta canônica do txid exato; ausência e pouca profundidade resultam em indisponibilidade, enquanto evidência substituída e corrupção resultam em inconsistência. O armazenamento não extrai escalares. Exposição do emissor e observação do receptor são mutuamente exclusivas.

A fonte de segredo exige a instalação pelo plano exato do filho e a exposição autenticada no coordenador. A existência de uma transação na RPC não cria, sozinha, autorização de gasto ou funding.

## Revisão das permissões

Comparação com a árvore V14 `3d68ee51b1586471376c4d4af160b7991c59ec9a`: no arquivo central do Store, somente `derive_recovery_actions` e `retain_recovery_sources` mudaram entre as funções existentes. Foram adicionados testes. As funções existentes que contêm verificações Sponsor/strict-purpose permanecem byte a byte idênticas. Os arquivos centrais `dom-actuator/src/contracts.rs` e `dom-actuator/src/store.rs` também permanecem idênticos. O guard registra o novo hash exato do Store depois desta comparação; não amplia sua lista de permissões de custódia.

Isso é revisão do código desta entrega, não auditoria externa ou prova formal. A inspeção sintática não verifica tipos, borrow checking, linking, resultados econômicos ou swaps reais.

## Testes novos

Dez testes Rust cobrem truncamento em cada byte, mutação em cada byte, corrupção semântica com checksum recalculado, campos nulos, overflow de revisão, identidade de sessão e tipo de staging, sucessor sem exposição, discrepância de ponta/revisão, arquivos órfãos, prefixos interrompidos em disco e distinção entre ausência/transitoriedade e substituição/corrupção. Os testes em disco usam a abertura nativa do Store.

Não há ainda um teste completo de rodada F7 + observação + `0x12` + reinício nesta entrega. A espera de confirmações e o reenvio Relay precisam ser demonstrados em conjunto, incluindo chegada de `0x12` antes da finalidade exigida.

## O que continua faltando

1. Montagem integral do bootstrap: BP operacional, templates, refund/readiness e assinatura de funding derivados das shares retidas.
2. Instanciação e agendamento do emissor F7 e de seu worker de adaptação/claim no root universal. A chamada do receptor e a finalidade no filho não substituem essas etapas.
3. Compensação DOM funcional cuja condição de funding XMR seja exigível também fora do daemon. Uma flag local ou uma assinatura posterior ao funding não satisfazem o mecanismo requerido. Não foi criado um oracle ou liberado o produtor inseguro.
4. Posse completa do grafo XMR/funding/recuperação no root. A recusa preventiva das rotas XMR compensadas permanece.
5. Compilação Rust e demonstração das 16 rotas.

## Executar no seu ambiente Linux

Na pasta `dom-protocol`, com os pré-requisitos do projeto já instalados:

```bash
python3 crates/dom-interopd/scripts/test_daemon_v15.py
python3 scripts/build_daemon_v14.py --output dist/v15/dom-interopd --report-dir artifacts/daemon-v15-build
```

O segundo comando reutiliza o construtor introduzido na V14 e publica o binário **desta árvore V15** em `dist/v15/dom-interopd`, somente após build Cargo bem-sucedido e verificação do artefato ELF. Falha de build não substitui um executável anterior.

Para os novos testes do Store isoladamente:

```bash
cargo test --locked -p dom-scriptless-store --features evidence-only --lib v15
```

Para os novos testes de classificação do daemon:

```bash
cargo test --locked -p dom-interopd --no-default-features --features production --lib v15
```

Os relatórios distinguem código-fonte, build, testes e swaps. `self-check` e matrizes de configuração não são evidência de 16 swaps concluídos.
