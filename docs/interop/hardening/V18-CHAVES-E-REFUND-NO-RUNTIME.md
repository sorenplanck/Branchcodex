# V18 — chaves compostas e assinatura do refund no bootstrap

Esta versão continua a V17, árvore Git
`9a157397fd9c994902d44dd87528a7e3507248cd`. O código novo está aplicado ao
projeto completo. Não foram executados builds, testes, scripts do protocolo
ou swaps: a execução fica com o usuário, conforme solicitado.

## Mudança funcional

A V17 montava os templates, mas não autorizava no Store as chaves de kernel
compostas pela carteira nem conduzia a assinatura do refund. A V18 escreve
esses dois caminhos e os conecta ao bootstrap usado pelas raízes de produção.

Para pernas DOM com contraparte BTC, EVM ou SOL, o caminho novo é:

1. Recuperar a carteira, as reservas e a share colaborativa nativas.
2. Compor as chaves de funding, claim e refund e provar posse de cada uma.
3. Reter e trocar as ofertas públicas com as provas.
4. Concluir a BP e reconstruir independentemente os três templates.
5. Aceitar ambos os compromissos DSC1 `0x0b`.
6. Reter a autoridade das chaves, vinculada à BP, aos termos e aos templates.
7. Conduzir os seis passos nativos de compromisso de nonce, revelação e
   assinatura parcial do refund (`0x0c`, `0x0d`, `0x0e`, dois participantes).
8. Reconstruir e reter a transação de refund assinada, transportar o `0x10`
   pelo emissor canônico e aguardar sua aceitação antes de concluir essa
   parte do bootstrap.

O passo 8 distribui a transação assinada entre os participantes via DSC1.
Não transmite o refund à blockchain antes do prazo. Também não é autorização
de funding: os gates econômicos, temporais e de assinatura continuam necessários.

## Arquivos e responsabilidades

| Arquivo, relativo à raiz | Implementação V18 |
|---|---|
| `crates/dom-adaptor/src/bootstrap_keys_v18.rs` | Envelope canônico limitado com três provas nativas de posse; vínculo por finalidade, chain, sessão, termos, participante e todos os bytes da oferta. |
| `crates/dom-actuator/src/wallet_templates_v17.rs` | Produção das provas usando as shares opacas reais; reuso das provas públicas exatas após reinício. |
| `crates/dom-scriptless-store/src/runtime/linux/session_store/bootstrap_keys_v18.rs` | Registro imutável das chaves, reconstrução da BP e dos templates, conferência bilateral `0x0b` e emissão do roster por finalidade. |
| `crates/dom-scriptless-store/src/runtime/linux/session_store.rs` | Validação das chaves autorizadas na assinatura e no replay; inventário fechado do registro novo. |
| `crates/dom-interopd/src/production_run.rs` | Preparação e retenção das provas na função compartilhada pelas duas raízes de produção; transferência das shares para o proprietário do bootstrap. |
| `crates/dom-interopd/src/production_bootstrap_templates_v17.rs` | Consumo das ofertas V18, instalação da autoridade nativa e chamada do driver de refund após acordo dos templates. |
| `crates/dom-interopd/src/production_bootstrap_refund_v18.rs` | Assinatura nativa de refund com custódia retida, replay do outbox, finalização e agendamento do `0x10`. |
| `crates/dom-interopd/src/production_dom_shared_bootstrap_v12.rs` | Custódia das shares por finalidade, transferência exclusiva do vault ao signer e retenção das provas públicas. |
| `crates/dom-adaptor/src/vault_signer.rs` | Devolução do mesmo vault ao proprietário após encerrar o signer, preservando o histórico de nonces. |
| `crates/dom-scriptless-store/src/runtime/linux/session_store/bootstrap_v16.rs` | Leitura autenticada da conclusão do refund e espera limitada para transições no mesmo lote do inbox. |
| `crates/dom-interopd/src/relay_worker.rs` e `production_composite_loop.rs` | Troca de autoridades de ingresso entre templates, assinatura de refund e refund final; avanço antes e depois da troca de rede. |
| `crates/dom-interopd/scripts/import_wallet_offer_v18.py` | Importação atômica da oferta pública V18 com conferência de tamanho e dos identificadores esperados. |

## Autoridade criptográfica e persistência

A chave da BP representa a contribuição ao output compartilhado. As chaves
de kernel incluem também entradas, saídas e offsets da carteira. A V18 não
trata essas chaves diferentes como se fossem a mesma chave.

Cada prova usa o verificador nativo `SharePoPStatementV1`/`ShareProofV1`, com
domínio `DOM:bootstrap-wallet-kernel-possession:v18`. Seu contexto inclui a
finalidade e a oferta pública canônica inteira. A prova não autoriza nonce,
assinatura de transação ou transmissão de fundos.

O Store só instala o registro `<session>.bootstrap-wallet-keys-v18` depois
de revalidar as identidades, a BP final, as seis provas de posse, o orçamento
dos termos e os dois compromissos de templates. Reconstrói as três transações
e exige os mesmos hashes aceitos pelos participantes. A instalação inicial
exige `TemplatesCommitted`, sem funding autorizado ou rodada já vinculada.
Uma reabertura exige bytes idênticos.

O registro é limitado, canônico, imutável e incluído explicitamente no
inventário de recuperação. Sua existência muda a regra de ancestralidade
das chaves para aquela finalidade e template exatos; corrupção não permite
voltar à regra antiga de usar a chave BP. Sessões sem o registro conservam a
regra antiga e não ganham permissão para usar uma chave composta arbitrária.

As shares privadas permanecem na carteira e no proprietário nativo. Só as
ofertas e provas públicas são serializadas por esta alteração. O signer
consome a share de refund e o vault existente, com os controles de reserva,
exposição e consumo nativos. Funding e claim conservam shares distintas.

## Reinício e mensagens que chegam entre fases

O daemon recupera o mesmo registro público, as mesmas reservas, o prefixo
de assinatura aceito e o outbox. Se uma assinatura pública já foi retida,
o caminho de retomada usa o artefato exato; não cria uma substituição de nonce.

A consulta de conclusão exige o histórico nativo do `0x10`: um arquivo de
refund final presente, mas ainda não aceito no transporte, não conclui o
bootstrap. Uma fase avançada com histórico ausente ou inconsistente é erro.

O Relay agora permite a progressão explícita Early → BP → Templates →
Assinatura de Refund → Refund Final. A substituição não aceita uma finalidade
de assinatura diferente nem converte permissões lineares F7/M.8/claim.

Se um lote do inbox completar templates e trouxer imediatamente `0x0c`,
ou completar as parciais e trouxer `0x10`, o Store confere escopo, identidade,
sequência e predecessor antes de sinalizar espera pela troca de autoridade.
Para `0x10`, reconstrói também a transação final exata. Não emite recibo de
aceitação enquanto espera; uma mensagem alterada continua sendo erro.

## Perfil e troca das ofertas

O perfil econômico continua sendo **`policy_version = 17` nos termos
assinados**. V18 é a versão do envelope de provas e da implementação; não
mude o campo dos termos para 18. Ambas as partes precisam usar a implementação
V18 para este caminho. Os documentos V17 no ZIP são históricos.

O Stage12 publica em cada `state_dir`:

```text
dom-wallet-offer-v18-<session_id_hex>.local
```

Transporte esse arquivo público para a contraparte. No destinatário:

```sh
python3 crates/dom-interopd/scripts/import_wallet_offer_v18.py \
  --source /caminho/oferta-recebida.local \
  --state-dir /caminho/absoluto/do/state-dir \
  --chain HEX64_DA_CHAIN_DOM \
  --session HEX64_DA_SESSAO \
  --terms HEX64_DOS_TERMOS_ASSINADOS \
  --peer-participant HEX64_DO_PARTICIPANTE_REMOTO
```

Use identificadores conhecidos da sessão, não copiados sem conferência do
arquivo recebido. Repita nos dois sentidos e para cada sessão da composição.
O diretório deve pertencer ao operador e ter modo 0700. O importador escreve
`dom-wallet-offer-v18-<session_id_hex>.peer`, modo 0600. O máximo é 16.591 bytes.
Ele verifica estrutura externa e escopo; o Rust verifica as provas e a
construção econômica. A entrega por rede das ofertas ainda não é automática.

Uma oferta V17 sem provas não é convertida em autorização V18. Ao reabrir
material local V17, a carteira recompõe a oferta e pode criar uma única
versão das provas públicas, que é retida antes de publicar. Histórico nativo
de assinatura incompatível é recusado, não migrado silenciosamente.

## Código de verificação entregue para executar no seu ambiente

Foram escritos sete testes Rust novos: cinco para o envelope e as provas,
dois para a fronteira de conclusão/retomada do refund. Eles cobrem troca de
finalidades, alteração de termos e offsets, reetiquetagem de participante,
role e chain, limites do codec, reinício após `0x10` e espera sem aceitação
nem ocultação de mensagem inválida. **Não foram executados nesta entrega.**

Com os pré-requisitos do projeto instalados, os comandos são:

```sh
cargo test --locked -p dom-adaptor bootstrap_keys_v18::tests
cargo test --locked -p dom-scriptless-store --features evidence-only --lib v18_
python3 scripts/build_daemon_v14.py \
  --output dist/v18/dom-interopd \
  --report-dir artifacts/daemon-v18-build
```

O ZIP contém código-fonte e instruções de build, sem executável compilado.
Relatórios de versões anteriores não demonstram o resultado desta árvore.

## O que permanece aberto

Esta versão **não fecha as 16 rotas nem justifica nota 10/10**. Ainda faltam:

- Condução completa da assinatura de funding junto à emissão/consumo F7 e
  sua revalidação temporal. As shares e templates de funding existem, mas
  guardá-los não equivale a utilizá-los no runtime.
- Entrega da autoridade M.8 consumida ao claim quando houver BTC, produtor
  universal de claim e conclusão de todas as etapas no runtime.
- Compensação DOM condicionada ao funding XMR por regra que também impeça
  gasto fora do daemon, além da execução e recuperação XMR completas.
- Transporte automático das ofertas e demonstração ponta a ponta pelo
  binário nas 16 combinações, incluindo reinício e desaparecimento do peer.
- Evidências formais, avaliação de privacidade, operação reproduzível e
  auditorias independentes exigidas pelo roteiro de qualidade acordado.

O driver novo recusa `CrossCurveSharedSpend` com `XmrRecoveryGraphRequired`:
um refund DOM comum não substitui o grafo adaptor/refund/compensação XMR.
Uma compensação pré-assinada gastável sem funding XMR continua inaceitável.

## Revisão de fonte e guardas

O diff de `session_store.rs` contra a V17 foi lido antes de atualizar seu
SHA256 em `scripts/guard_layer_policy.py`. A alteração acrescenta a autoridade
de chaves aos validadores e ao replay, registra o sufixo no inventário fechado
e acrescenta dois testes. Os gates de fase, finalidade, agregado de kernel,
refund anterior ao funding e assinatura pós-âncora permanecem no caminho.
Nenhuma finalidade Sponsor foi acrescentada ou autorizada. A atualização
do hash mantém a guarda vinculada ao arquivo modificado; não é execução da
guarda, auditoria externa ou evidência de compilação.
