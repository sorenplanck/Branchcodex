# V11 em desenvolvimento — retomada preservada em 2026-09-09

Base V10: árvore Git `f082d8367574f5e456fd718130d4f9d2637dc8cc`.
Este estado é um checkpoint de desenvolvimento, não uma entrega V11 aceita.
Os três critérios obrigatórios ainda não foram demonstrados de ponta a ponta.

## Decisão econômica autorizada pelo usuário

DOM↔XMR tem três resultados distintos: troca concluída; recuperação do próprio
XMR quando o refund DOM revela U; compensação em DOM quando a contraparte
não coopera. Compensação não pode ser registrada como `XmrRefunded`.

O colateral DOM precisa estar confirmado antes de qualquer funding XMR.
A taxa racional, os destinatários, a margem positiva, as taxas e os prazos são
vinculados ao hash integral dos termos assinados. A compensação exige somente
artefatos já retidos antes do funding, sem assinatura posterior do desaparecido.
O refund cooperativo tem janela anterior e custo menor. A margem é finita:
não representa proteção contra oscilação ilimitada de preço.

## Código efetivamente acrescentado

- Entrada V4 em `run_production_v1`, com `production_run_universal.rs`:
  inicialização por posição, clientes das famílias selecionadas, autoridades
  de participantes, stores, Relay/F6, filhos e supervisor. Credenciais V3
  preservam a composição legada. V4 não converte sua rota em um par EVM+BTC.
  A chamada que ficou sem definição na interrupção foi substituída por um
  carregador concreto da prontidão Bitcoin retida: somente posições BTC
  consultam M.8. Ausência ou inconsistência recusa o início; não vira espera
  infinita baseada em um erro genérico de estágio.
- Recursos SOL/XMR: abertura existente sem criação/reparo de banco e renovação
  de leases com processo, inode, escopo e epoch retidos por posição.
- Bitcoin: prontidão bilateral do mesmo Store antes do funding, preparação
  tardia da sessão de claim com o efeito real, revalidação F7 a cada fase M.8
  e bloqueio da primeira exposição DOM até o claim BTC estar preparado.
  O pump sobre o mesmo router agora é chamado pelo loop root após cada passo
  da rota. O transporte UDS é independente por posição e abre somente na rodada
  efetiva. A autoridade Contracts resultante permanece retida; ainda precisa
  ser utilizada pelo produtor de assinatura do claim DOM.
- `f7-anchor-authority/families_v11`: verificadores concretos EVM, SOL e XMR,
  com identidade, funding e finalização da própria família. Evidência DOM/XMR
  combina o colateral nativo com o grafo e o setup. Esses resultados não são
  autorizações de assinatura e ainda precisam do consumidor V11 no Store.
- `xmr-refund-policy/compensation.rs`: política canônica de 436 bytes,
  comprometida por `assurance_policy_hash` nos termos; conversão racional com
  arredondamento inteiro, margem positiva, principal, colateral, taxas e
  prioridades de prazo/custo. `metadata` não concede autoridade econômica.
- `xmr-refund-policy/economic_graph.rs`: vínculo do valor de C, grafo nativo e
  payouts aos termos. Provas nativas de posse dos commitments autenticam os
  valores de principal e troco sem divulgar blindings. Falta o produtor dessas
  provas no fluxo da carteira.
- `dom-scriptless-crypto/xmr_recovery_graph`: validação nativa de funding C,
  claim, cancel C→D, refund adaptado U e compensação plain. Cancel e
  compensação são assinaturas ordinárias. A compensação não revela T.
- Arquivo criptografado do grafo com XChaCha20-Poly1305, chave própria,
  nonce aleatório e AAD de sessão/termos/grafo/custódia. A assinatura final
  privada U é retida somente pelo papel autorizado. Reabertura revalida
  transações, pré-assinatura e nonces públicos nativos.
- `dom-scriptless-store/runtime/linux/xmr_recovery.rs`: custódia com diretório
  retido, lock exclusivo, escrita sem substituição, fsync e recuperação do
  staging somente após autenticação. Nenhuma concessão de signing/funding.
- Auditoria no mesmo Store reconstrói duas rodadas ordinárias auxiliares
  distintas de cancel/compensação. Verifica a ancestralidade real de nonces,
  parciais e transcritos. O token opaco não pode ser restaurado de um digest
  fornecido pelo chamador. Seus tipos foram reexportados pelo limite público.
- `adapter-dom-real/xmr_recovery_finality`: observação nativa de C/D com
  ancestralidade, confirmação, consenso e alturas; distingue colateral,
  cancelamento, refund-U e compensação DOM. Tip mutável é indisponibilidade;
  identidade/ancestralidade substituída é conflito.
- `production_xmr_recovery_source`: fonte concreta dessa observação para o
  sweep; uma compensação nunca é aceita como revelação de U ou refund XMR.
  A abertura dessa custódia ainda não está ligada ao root.
- Inicialização e retomada XMR por papel: U para receptor do claim, T para
  receptor do refund; vínculo de sessão/termos/pontos/DLEQ. Retomada é somente
  leitura, sem novas shares, criação de schema ou reparo de registros ausentes.
- Observers XMR/SOL: resposta ausente continua distinta de txid/assinatura
  substituídos. SOL passa a verificar a assinatura efetivamente devolvida pelo
  RPC. XMR verifica inclusão no bloco e snapshot estável de quorum.

## Fronteiras ainda abertas — não chamar de concluídas

1. Produção bilateral das sessões auxiliares ordinárias, carteira/nonce vault,
   proofs dos payouts e custódia do grafo completo antes do funding.
2. Registro de prontidão V11, novos estados duráveis e concessão nativa de
   funding no Store. O `FinalRefund` plain do protocolo existente não pode
   transportar uma assinatura adaptor final antes do funding: revelaria U.
   A proposta de mensagem 0x17 NÃO foi implementada neste checkpoint.
3. Consumidor F7 por família e ligação ao produtor de claim DOM. O V2
   produtivo permanece específico de BTC, embora os novos observadores
   de EVM/SOL/XMR existam.
4. Utilização da autorização Contracts resultante no signer de claim DOM.
   A chamada M.8 e o transporte foram conectados, mas ainda não foram executados
   neste ambiente nem demonstrados com dois participantes reais.
5. Root XMR: abrir/produzir custódia, exigir colateral confirmado, executar
   funding, janelas de claim/refund privadas e compensação unilateral. Persistir
   o resultado `compensado em DOM` no coordenador e retomar após crash.
6. Executar as 16 rotas pelo binário real, incluindo contraparte ausente,
   crash, reorg e resultados econômicos. Ainda não há essa evidência.

O root V11 recusa explicitamente funding XMR enquanto faltar a autoridade
nativa bilateral de compensação. Esse bloqueio impede financiar sob a antiga
política de refund plain; não representa implementação concluída da rota.

## Verificação desta retomada

- `git diff --check`: aprovado.
- `python scripts/guard_layer_policy.py`: aprovado, inclusive isolamento de
  `evidence-only`, custódia do Store e limites de signing.
- As 14 funções do Store que contêm Sponsor/strict-phase e
  `authenticate_persisted_refund` continuam byte a byte iguais à V10.
  O pin integral foi atualizado somente depois dessa comparação. A mudança
  adicional no arquivo central registra a auditoria ordinária em submódulo.
- Manifests e dependências locais: 189 pacotes examinados, sem ciclo nas
  dependências normais/build, inclusive caminhos herdados do workspace.
  O pacote externo `external-gpl/monero-wallet-ng` não está presente; é uma
  dependência local do sidecar a obter pelo procedimento do projeto.
- Dependências dos manifests alterados estão representadas no Cargo.lock.
  Isso não substitui resolução e compilação por Cargo.
- Foram escritos testes Rust de política econômica, custódia, grafo,
  observação/finalização, prontidão BTC e recuperação por papel.
  Nenhum teste Rust foi executado nesta retomada: Cargo/Rust não estão
  disponíveis no ambiente. Análise sintática não verifica tipos ou linking.

## Comandos de validação no ambiente Rust

Depois de completar as integrações acima e obter as dependências do projeto:

```bash
cargo test --locked -p xmr-dleq-nullifier-store -p xmr-refund-policy -p xmr-session-init
cargo test --locked -p xmr-runtime-wiring -p xmr-observer
cargo test --locked -p dom-scriptless-crypto
cargo test --locked -p dom-scriptless-store --features evidence-only
cargo test --locked -p adapter-dom-real -p solana-rpc -p f7-anchor-authority
cargo test --locked -p btc-actuator
cargo test --locked -p dom-interopd --no-default-features --features config-only --lib
cargo test --locked -p dom-interopd --no-default-features --features production --lib
```

`evidence-only` pertence somente aos fixtures do Store; não habilitar no
binário de produção. CI verde nesses recortes não comprova as 16 rotas.

## Transporte BTC da composição V11

O bundle canônico `DOM-INTEROPD-BITCOIN-AUTHORITY-V11` inclui
`claim_peer_socket` (caminho relativo ao estado da posição) e
`claim_exchange_timeout_ms` (1 a 30.000 ms). O digest autenticado do manifest
precisa abranger esses campos. O peer local implementa o envelope `DOMBTCX6`
de `btc-actuator::UnixBitcoinClaimTransportV6`; mensagens de nonce/parcial
continuam autenticadas pelo signer nativo e sua roster, não pelo socket.
Cada tentativa usa uma nova conexão; nonce e parcial da mesma tentativa usam
a mesma conexão. Envelopes inválidos e respostas trocadas são recusas duras.
Ausência explícita de funding, profundidade insuficiente, snapshot mutável
e falha de transporte são estados de espera sem concessão de assinatura.

O comando único para registrar a validação da candidata é:

```bash
python3 crates/dom-interopd/scripts/test_daemon_v11.py
```

Os logs ficam em `artifacts/daemon-v11`. `--offline` executa apenas as regras
de arquitetura e os testes Python; seu sucesso não valida Rust. O modo padrão
executa também as novas suítes nativas de custódia, política, inicialização,
observação e build de produção. O script não transmite swaps.
