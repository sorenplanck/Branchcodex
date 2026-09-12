# V7 — implementação no daemon

Esta versão incrementa a V6. O código novo está em `crates/dom-interopd/`.
O `Cargo.lock` da raiz apenas registra dependências do pacote: Ed25519 para
o signer e rand/solana-pda para os testes, usando versões já presentes no grafo.
Os demais fontes, inclusive adaptadores e contratos, permanecem iguais à V6.

**Esta entrega não finaliza as 16 rotas. Nenhum swap completo foi executado
aqui e o Rust novo não foi compilado neste ambiente.** Há integração entregue
e bloqueios concretos descritos abaixo; passar os testes de componentes não
altera esse estado automaticamente.

## Código entregue

1. `src/production_materializing_children.rs`: fábrica de filhos concretos
   EVM/BTC/SOL/XMR, com dois recursos independentes por posição. Antes de
   construir qualquer filho, valida família, settlement e posição contra a
   topologia autenticada. O estágio 15 de `production_run.rs` usa essa fábrica.
   A variante Bitcoin que cria planos exige uma capacidade real de claim;
   a variante usada pelo root atual continua explicitamente de recuperação.
2. `src/production_f6/extended_terms.rs` e `production_f6_factory.rs`: owners
   F6 Solana/Monero criados somente a partir de sessões autenticadas, com
   compromissos de payout ligados à posição, termos, composição, registro,
   deployment e setup. Monero também revalida a prova de refund. Não existem
   construtores públicos de capabilities a partir de um booleano ou digest
   arbitrário. Esses compromissos não comprovam refund armado ou executor vivo.
3. `src/production_solana_signer.rs`: assinatura Ed25519 local e cliente/servidor
   para uma conexão Unix já autorizada. Valida a mensagem completa reconstruída
   do setup, papel e contas fixadas; permite initialize+fund atômico, claim e
   refund. Recusa conta/programa/instrução trocada, segredo inconsistente,
   mensagem excedente e resposta divergente. Usa limite de tamanho e prazo
   total por troca; erro interrompe a reutilização da conexão. O serviço não
   abre listener nem carrega credenciais por CLI: essa inicialização está pendente.
4. `src/production_child_solana.rs`: contas SPL explícitas para origem,
   recebimento e refund. Native SOL recusa essas contas. O programa continua
   responsável por verificar mint e donos das contas token. A construção de
   instruções usada pelo child e pelo signer é única, evitando políticas distintas.
5. `src/production_child_solana.rs`, `production_child_xmr.rs` e
   `production_children.rs`: despacho vinculado ao hash dos termos da rota;
   o hash do setup continua vinculado ao settlement. Os novos construtores
   também conferem o setup e deployment exatos contra a capacidade autenticada.
   Portas de recuperação precisam do vínculo de rota antes de despachar.
6. `src/production_route_topology.rs`: compara o digest do perfil do registro
   com a admissão correspondente. O hash do perfil do adaptador SOL/XMR tem
   outro domínio e continua conferido pela autenticação de sessão.
7. `src/tests/solana_signer_v7.rs`: sete testes Rust de assinatura native/SPL,
   seis combinações fund/claim/refund, mutações byte a byte, truncamento,
   identidade, papéis, socket real, resposta divergente, timeout e repetição
   das mesmas mensagens. A fábrica inclui mais dois testes de identidade das
   16 combinações e recusa de pernas trocadas/settlement repetido.
8. `scripts/solana_signatures_v7.py`: verificador Python independente da
   biblioteca Rust de assinaturas. Lê exatamente seis exports, verifica Ed25519
   por OpenSSL/cryptography, wire completo, papéis, programa, valor, prazo,
   destinatários e continuidade das contas. Não verifica DLEQ, derivação de PDA,
   execução do programa, inclusão ou finalidade. Seus sete testes Python
   também exercitam adulterações reassinadas, não apenas assinaturas inválidas.

A distinção solicitada entre ausência e contradição permanece: os adaptadores
Monero da V6 foram preservados byte a byte. No signer novo, resposta com escopo,
mensagem ou assinatura trocada resulta em `Conflict`; indisponibilidade/timeout
resulta em `Unavailable`. Nenhuma dessas falhas vira uma resposta de sucesso.

## Executar no seu ambiente

Extraia o ZIP em pasta nova e entre em `dom-protocol`. Em Linux com Git,
Python 3.11+, Rust/Cargo/rustfmt, compilador C, clang, cmake e pkg-config:

```bash
python3 -m venv ../dom-v7-tests
../dom-v7-tests/bin/python -m pip install -r crates/dom-interopd/scripts/requirements-v7.txt
../dom-v7-tests/bin/python crates/dom-interopd/scripts/test_daemon_v7.py --format
```

O comando executa testes do verificador Python, formata somente `dom-interopd`,
valida o lockfile, roda a suíte Rust de produção do daemon, verifica o export
Rust por Python, constrói o binário release e executa `self-check --json`.
As dependências do daemon também precisam ser compiladas. Não transmite swaps
nem cria configurações, identidades ou credenciais de operação.

Sem Rust, é possível executar somente o verificador Python:

```bash
../dom-v7-tests/bin/python crates/dom-interopd/scripts/test_daemon_v7.py --offline
```

Evidências: `artifacts/daemon-v7/<execução>/report.json` e logs com SHA-256.
Saída 0 = testes/comandos selecionados passaram; 1 = falha; 2 = pré-requisito
ausente. No modo completo, export Rust ausente ou inválido faz a execução
falhar; não há substituição por fixture Python. A execução para na primeira falha.
O relatório registra hash dos fontes antes/depois, inclusive formatação.

## Estado real das 16 rotas

`STATUS-V7.json` lista cada par ordenado, sempre com DOM no centro. A fábrica
representa as quatro famílias nas duas posições, incluindo pares da mesma
família com settlements distintos. Isso não equivale a inicialização e
execução completas pelo comando `run`.

- O carregador V10/V3 do root ainda seleciona uma perna EVM e uma Bitcoin.
  A seleção de recursos para as outras 14 formas continua pendente.
- Mesmo nas duas formas EVM/BTC, o root não possui a integração completa de
  prontidão bilateral, transporte M.8 e claim/recuperação. Por isso não habilita
  novos planos Bitcoin.
- Solana ainda precisa conectar os signers ao carregador e resolver o
  pré-funding do estágio 13: a evidência atual de refund exige escrow já
  financiado, enquanto o child constrói initialize+fund atômico. Relaxar a
  exigência não demonstra capacidade de recuperação.
- Monero ainda precisa de implementação produtiva de `ScopedXmrSweepAuthorityV1`
  com destinos/autorização de claim e refund completos. Uma implementação
  fictícia que apenas aceita bytes de um sidecar não foi adicionada.

Há também pré-requisitos que ultrapassam a restrição de alterar só o daemon:

| Bloqueio | Código existente | Consequência |
|---|---|---|
| F7 produtivo exige funding Bitcoin, bloco completo e ancestry | `crates/f7-anchor-authority/src/lib.rs`, `F7AnchorValidationRequestV2` | Rotas sem BTC precisam de generalização autenticada da autoridade de âncoras, não de provas Bitcoin inventadas pelo daemon. |
| Origem XMR não revela o scalar na chain Monero | `src/production_materializer.rs`, `secret_source_is_extractable_v1`; `crates/dom-final-claim-binding/src/lib.rs` | O plano atual upstream exige `VerifiedCounterpartyClaim`, cujo source deve ser a counterparty. A nova origem de revelação precisa de vínculo de protocolo; remover a recusa cria uma promessa inexequível. |

## Validação desta entrega

Os sete testes Python novos passaram neste ambiente. Os 50 testes Python
cumulativos são executados e registrados separadamente na entrega. São
fixtures públicas/sintéticas. Os nove testes Rust novos estão escritos,
**não executados**: faltam ferramentas de build neste ambiente.

A análise gramatical dos Rust alterados não detectou erros novos. Cinco
diagnósticos do parser sobre o identificador Rust `raw` já existiam na V6;
foram comparados com a base. Análise gramatical não verifica tipos, empréstimos,
linkedição ou comportamento, e não substitui `cargo test`.

O ZIP inclui comparação dos bytes V6→V7, manifesto SHA-256 de todos os fontes,
patch incremental e patch cumulativo. Os patches já estão aplicados. Relatórios
globais V1–V6 são históricos preservados; o estado desta entrega está neste
documento, no `STATUS-V7.json` e no `VERSAO.json` da raiz do ZIP.

Não há nota 10/10 atribuída, auditoria externa, prova formal ou demonstração
das 16 rotas ponta a ponta nesta versão. O código entregue reduz lacunas
identificadas no daemon, mas os bloqueios acima continuam impedindo a conclusão.
