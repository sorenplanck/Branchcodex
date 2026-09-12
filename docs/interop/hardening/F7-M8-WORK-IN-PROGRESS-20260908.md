# Integração F7/M.8 em andamento — 2026-09-08

Este documento registra trabalho posterior ao ZIP V8 entregue. Não representa
uma entrega completa nem comprova execução das 16 rotas. O ZIP entregue não
foi substituído por esse trabalho em andamento.

## Código implementado

- `production_bitcoin_claim_driver.rs`: coleta da transação exata pelo Bitcoin
  Core, verificação F7 pelo runtime DOM já retido, seleção da autorização do
  participante local, consumo ou recuperação da autoridade Contracts e chamada
  do driver real de troca de nonce/partial. Repete a verificação em cada fase e
  devolve a autoridade de materialização do claim após agregação.
- Persistência: consumo ou retomada sob o mesmo lock; recuperação preserva os
  registros originais e a exclusividade do dono em memória. Revalidação de F7
  aceita crescimento da profundidade sobre a mesma âncora, confere novamente
  a identidade completa do gate e recusa redução da profundidade de emissão,
  troca de funding, termos, origem do segredo, roster ou composição.
- Dois testes Rust adicionados para prefixos de emissão/consumo, exclusividade,
  retomada e mutações da evidência. Usam a fixture criptográfica existente e
  fatos externos de laboratório; não são testes de nós reais.

## Integração ainda necessária

O novo driver ainda não é chamado pelo bootstrap. A configuração das 16 rotas
existe, mas `production_run.rs` ainda utiliza `legacy_deployments()` e
`into_legacy_clients()`, exigindo EVM+BTC. Ainda faltam o bootstrap universal,
o F7 para as outras famílias, execução/revelação XMR e o encadeamento de claim
no loop real. Esses itens continuam sendo critérios de entrega.

Não foi executado `cargo check`, teste Rust ou swap neste ambiente: não há
toolchain Rust disponível. A análise sintática não substitui compilação.

## Revisão do congelamento F1

O guard fixa o hash do arquivo inteiro `session_store.rs`, inclusive código
que não trata de Sponsor. A atualização segue o procedimento de nova fixação
documentado em `scripts/guard_layer_policy.py`.

- Hash anterior: `e18de70d069ee0af1dca250fe5b2fd9377bc201becbfd1194d44fa58778bfda0`.
- Hash revisto: `5b54a252bbb46171b0b01f08e3e00f1c73e922406adaedbe2cc5f1551c80e94c`.
- Comparação das árvores sintáticas: os 14 corpos de função que contêm
  `Sponsor`, `require_strict_phase1` ou `is_strict_v1_authorized` permanecem
  byte a byte idênticos ao arquivo anterior.
- O diff completo foi lido: não adiciona propósito de assinatura. O corpo
  anterior do consumo foi extraído para método privado, conservando o lock
  na entrada pública; a nova entrada também mantém esse lock durante emissão,
  consumo e decisão de recuperação. Nenhuma allowlist foi ampliada.
- A entrada antiga de comparação exata continua exigindo igualdade das duas
  profundidades; somente a nova entrada de revalidação de F7 admite crescimento.
- O guard permanece obrigatório e rejeita alterações posteriores não revistas.

Essa revisão é local, feita pelo implementador; não é auditoria independente.
