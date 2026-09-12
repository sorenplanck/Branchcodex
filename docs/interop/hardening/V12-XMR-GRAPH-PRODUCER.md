# V12 — produtor nativo do grafo DOM/XMR

Este pacote contém construção e assinatura novas. Não habilita funding XMR no
runtime e não comprova que a compensação possui exclusão econômica em todos os
casos adversariais. O bloqueio de inicialização permanece necessário.

## Código entregue

- `xmr-refund-policy::graph_builder::XmrRecoveryGraphTemplatesV12::build`
  constrói as cinco transações reais, usando os tipos e verificadores DOM:
  funding de C, claim com principal e troco da margem, cancel C→D, refund U de
  D e compensação ordinária de D. C contém principal, margem, taxa de cancel e
  taxa de compensação. D tem valor e sessão de Bulletproof independentes.
- `XmrOrdinaryRecoveryRoundV12` recebe nonces públicos e verifica cada parcial
  antes de produzir cancel ou compensação. A finalização é exclusivamente
  Schnorr ordinária; uma parcial adaptor não é aceita como compensação.
- `complete` produz o grafo verificado e a evidência econômica. Confere nonces
  distintos entre cancel, refund e compensação. Não recebe T ou U.
- O produtor de provas de payout utiliza PoP nativa. O método da wallet prova
  o blinding efetivamente retido, sem exportar o escalar.
- `complete_private_dom_refund_v12` carrega somente o U já retido no store
  local, revalida DLEQ, nullifier e setup, e completa o refund em um recipiente
  privado. Esse recipiente só atravessa a criação da custódia cifrada.
- `ProductionXmrGraphDriverV12` cria ou reabre a custódia real e exige a
  auditoria das duas sessões ordinárias no mesmo Contracts Store.
- `production_xmr_round_runtime_v12` prepara um passo de assinatura por
  participante, usa o signer e o vault nativos, assina o envelope no identity
  store e o encaminha ao Relay durável. O conteúdo das seis mensagens é
  revalidado contra identidades, sequências, transcript, compromissos de nonce
  e as equações nativas. Apenas os refunds ordinários auxiliares usam 0x10.
- `participant_shared_transition_signing_share_v12` produz a contribuição
  local `r_D − r_C − offset` a partir das duas capacidades de blinding. As
  shares das duas pessoas nunca são somadas dentro de um participante.

## Correção da cápsula nativa

O campo `BpStatementV1.recovery_binding_hash` contém o hash da cápsula nativa
de recuperação. A V11 o comparava ao hash da política de compensação, impedindo
que a wallet nativa produzisse os dados esperados. A V12 conserva a cápsula e
verifica seu hash contra o output C real. A política continua vinculada pelo
hash integral dos termos, autenticado pela PoP de cada contribuição em
`FrozenSharedOutputV1.terms_hash`. Não há troca do contexto de recuperação por
um digest econômico arbitrário.

## Fronteira que ainda recusa execução

O Store operacional histórico exige que a chave de assinatura de cada
participante seja igual à share pública do primeiro output compartilhado.
A chave de uma transação de gasto é outra: por exemplo,
`payout − r_C − offset`. Ele também recusa `RefundAdaptor` na gramática de
assinatura operacional, e o refund ordinário exige gastar o commitment do
Bulletproof da mesma sessão. Por isso, fornecer os novos templates e chamar o
driver não produz autorização válida sob esse perfil antigo.

A ligação completa precisa de um perfil nativo versionado que retenha as
chaves específicas de cada finalidade, suas provas e sua relação com C, D,
payouts e offsets; também precisa de inicialização e transporte auxiliares
autênticos. Nenhum teste ou callback deste pacote fabrica esses registros.
Não foi alterado o validador antigo para ignorar suas exigências.

Além disso, o grafo temporal por si só não prova que um participante não
obtenha um resultado indevido combinando revelação pública de U, disputa de
transações e execução manual de compensação. A execução com fundos precisa
de uma resolução protocolar demonstrada desse problema, além da implementação.

## Validação disponível

Foram escritos testes Rust novos para produção ordinária de cancel e
compensação, timelocks nativos, recusa de parcial adaptor, colisão de nonces,
equação da transição local C→D e preservação do vínculo cápsula/termos. Eles
não foram compilados ou executados neste ambiente. A análise sintática dos
arquivos novos passou; isso não substitui o compilador ou os testes.

Com toolchain e dependências locais, os testes específicos são:

```bash
cargo test -p dom-scriptless-crypto --test xmr_recovery_graph_v11
cargo test -p xmr-refund-policy
cargo test -p dom-adaptor v12_shared_transition
cargo test -p xmr-session-init
cargo check -p dom-interopd --features production
```

Esses comandos verificam componentes e composição. Não demonstram 16 rotas
operacionais nem autorizam remover o bloqueio de funding XMR.
