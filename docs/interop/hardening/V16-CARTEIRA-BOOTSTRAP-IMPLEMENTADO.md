# V16 — construção da carteira de bootstrap

Estado: implementação parcial posterior à árvore
`b17ee867dcc15295f87e2176a54246ed069632c8`. Não é a entrega final solicitada.

O runtime agora chama a construção nativa da carteira quando possui o bootstrap
privado autenticado. Isso está conectado tanto à composição universal quanto
à composição anterior. Sessões preparadas externamente preservam o caminho
anterior de reabertura e não recebem uma nova seleção de inputs.

Código implementado:

- `dom-actuator/src/wallet_bootstrap_v16.rs`: cria a abertura privada de um
  output de recebimento ausente, grava a carteira criptografada e só depois
  usa a preparação/pin/ativação nativa de payout. Uma seleção já existente
  com abertura ausente é erro; dois candidatos também são erro. Uma interrupção
  após a gravação C0 reaproveita a abertura existente.
- `dom-actuator/src/wallet_funding_v16.rs`: identifica o pagador DOM pelos
  termos autenticados, seleciona inputs, recalcula a taxa por peso a cada
  input adicional, respeita o teto assinado e reserva os inputs no actuator.
  O outro participante não precisa de saldo DOM para essa preparação.
  O troco positivo recebe abertura privada própria na carteira criptografada;
  seu pin é derivado pelo Store de uma reserva nativa ativa. A reabertura
  recupera os mesmos inputs e o mesmo output de troco, inclusive após a troca
  do proprietário do lease.
- `dom-actuator/src/store.rs`: autentica a reserva e o lease antes de emitir
  a proveniência de construção do troco. Essa proveniência não é autorização
  de assinatura, transmissão ou prova de funding.
- `dom-interopd/src/production_run.rs` e `production_run_universal.rs`:
  conectam as operações acima à inicialização, antes de early/BP e F6.
- `test_daemon_v16.py --focus-v16`: inclui os sete testes Rust novos.

Os sete testes novos abrangem criação de dois payouts locais, reabertura,
interrupção após C0, lease expirado, candidatos ambíguos, reserva e troco após
troca de lease, participante não pagador, conservação de valor e seleção com
reprecificação de taxa. Foram escritos; não foram executados neste ambiente.

Verificação disponível: 23 testes Python do daemon e 110 do repositório
passaram. Os guards de camadas passaram. A inspeção sintática com tree-sitter
dos sete arquivos Rust alterados não encontrou novos erros de gramática;
ela não verifica tipos, empréstimos, compilação ou comportamento dos testes.
Os manifests e as dependências locais do Cargo.lock foram conferidos.

Continuam pendentes os templates completos de funding/claim/refund, a
autorização das chaves de assinatura por finalidade, o emissor F7 no runtime,
o encaminhamento do resultado M.8 ao claim e a compensação XMR condicionada
à confirmação do funding por regra verificável fora do daemon. O cálculo
implementado cobre a taxa do funding; não resolve a provisão de taxa para
claim/refund preservando o principal integral. Nenhum swap das 16 rotas foi
executado aqui e nenhum executável foi produzido.

Para executar os testes novos no ambiente com os pré-requisitos do projeto:

```sh
cargo test --locked -p dom-actuator --lib bootstrap_v16_
python3 crates/dom-interopd/scripts/test_daemon_v16.py --focus-v16
```
