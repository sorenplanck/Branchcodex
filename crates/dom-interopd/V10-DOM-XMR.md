# V10 — DOM↔XMR: código de execução e recuperação; integração ainda incompleta

Esta entrega é cumulativa sobre o ZIP V9. A prioridade passou a ser DOM↔XMR.
**Não fecha a rota de ponta a ponta nem as 16 rotas. O comando `run` continua
no bootstrap legado EVM+BTC.** Os componentes novos descritos abaixo estão
escritos, mas não foram compilados neste ambiente, que não tem Rust.

## Código acrescentado

- `production_xmr_sweep.rs`: primeira implementação concreta de
  `ScopedXmrSweepAuthorityV1`, usando o cliente Unix autenticado e o store
  criptografado existentes. Faz scan de funding, constrói claim com a share
  revelada e constrói refund com evidência tipada da DOM. Não possui porta de
  broadcast: devolve os bytes ao atuador durável, que persiste antes de enviar.
- Cada participante importa **uma** share local. O destinatário do claim XMR
  tem U e precisa aprender T; o destinatário do refund XMR tem T e precisa
  aprender U. Importar ambas antes da revelação quebraria a separação das
  partes. A chave pública local e T+U são conferidas contra o depósito.
- A admissão real em `production_inputs.rs` passa a verificar a prova de refund
  registrada e a soma das duas chaves públicas. O codec acrescenta o destino
  de refund no braço de tag 2. A tag 1 histórica preserva seus bytes; sua falta
  de destinatário não é preenchida automaticamente. A execução nova exige a
  tag com destino e a reautenticação do bundle correspondente.
- `dom-scriptless-crypto`: agregação/restauração da pré-assinatura pública de
  refund e extração de U a partir de uma assinatura final externa, com o
  verificador nativo. O material público pode ser revalidado após reinício.
- `adapter-dom-real`: extração vinculada à sessão, chain, refund retido,
  template, input compartilhado, kernel e confirmações. A observação de uma
  publicação pela contraparte não exige que o observador tenha transmitido
  localmente o refund. Essa prova de revelação não concede autorização para
  assinar, transmitir ou alterar o estado do Contracts Store.
- `production_contracts.rs` e `production_child_dom.rs`: ligação de leitura
  à mesma abertura do Store e ao mesmo runtime DOM. A autoridade XMR compara
  também a política de confirmações com os termos admitidos.
- `xmr-raw-tx-verify`: extrai todos os key images dos bytes canônicos e confere
  o txid. O filho XMR revalida o key image na construção e na recuperação.
  O atuador atual representa uma única imagem; sweeps com mais de uma são
  recusados explicitamente. O parser não verifica destino, valor ou CLSAG:
  a implementação nativa do sidecar continua sendo uma fronteira de confiança.
- `xmr-sidecar-auth`: os buffers temporários usados para autenticar pedidos
  com scalars privados passam a ser apagados ao sair do escopo.
- `xmr-secret-store`: abertura de recuperação sem criar banco ou schema
  ausente. Uma chave mestra errada continua sendo falha de autenticação.
- `production_config_universal.rs` / `production_node_universal.rs`: novo
  manifesto **V11** e stream de credenciais **V4**, com recursos por posição.
  Essas versões de formato são distintas da versão **V10 do ZIP**. O loader
  físico não exige banco/participante BTC ou banco EVM para SOL/XMR. Os nomes
  legados de caminhos permanecem no envelope comum V6, sem abertura desses
  recursos. A inicialização do comando `run` ainda precisa ser migrada.

## O que permanece aberto

1. Instalar a autoridade XMR e o bootstrap universal no `run_production_v1`.
   O bundle público por família do V11 ainda não tem todos os decodificadores
   de autoridade nem o fluxo de provisionamento com retomada após crash.
2. Generalizar F7 e os registros de autorização pós-âncora no Store. A emissão
   atual de autoridade DOM usada por `real_dom_contract_facts_v2` continua
   derivada do grafo V2 com BTC. O verificador novo não substitui essa emissão.
3. Integrar a rodada de refund adaptor ao produtor nativo e ao transporte com
   uma ordem de exposição segura. O produtor operacional existente ainda
   deriva o refund simples `PurposeV1::Refund`; a nova extração recusa uma
   transação cuja assinatura não corresponda à rodada adaptor autenticada.
4. Fechar a origem de revelação para a composição quando o claim observado é
   XMR. Um spend Monero normal não publica uma share como um HTLC. O segredo
   precisa de uma origem DOM/protocolo autenticada e ligada à perna correta.
5. Executar o binário com os processos DOM/XMR, funding unilateral, claim,
   refund, reinício e reorg. Nenhum desses swaps foi executado aqui.

### Por que não basta substituir o refund simples pelo adaptor

O Store atual produz e expõe o `FinalRefund` completo antes de autorizar
funding. Uma pré-assinatura adaptor pública **mais a assinatura final** permite
extrair U imediatamente, mesmo sem publicação na cadeia. A nova API de
extração torna essa propriedade diretamente testável. Distribuir ambos à
contraparte antes da hora pode entregar a chave compartilhada cedo demais.

Além disso, se a recuperação XMR depender de a outra parte publicar o refund
DOM, a ausência dessa publicação continua exigindo um caminho de recuperação
não cooperativo. Portanto, a integração precisa especificar e implementar a
ordem de exposição, a autorização durável e a recuperação unilateral; um
booleano de prontidão ou um timeout local não resolve isso. Esta entrega não
altera os gates atuais para afirmar uma garantia ainda não implementada.

A base dessa observação são o produtor
`prepare_operational_final_refund_transport_authority` no Contracts Store e
`VerifiedRefundPreSignatureV1::extract`. Não é alegação de exploração de um
deployment: o caminho produtivo de refund XMR ainda está incompleto.

## Executar no seu ambiente

Na raiz `dom-protocol` extraída:

```bash
python3 crates/dom-interopd/scripts/test_daemon_v10.py
```

O comando verifica os pré-requisitos e executa: codecs universais, criptografia
de refund DOM, adapter DOM, componentes XMR, testes do daemon, testes de
compatibilidade, build release e self-check. Mantém logs e relatório em
`artifacts/daemon-v10/`. Não instala dependências nem envia transações.

Para executar somente verificadores Python:

```bash
python3 crates/dom-interopd/scripts/test_daemon_v10.py --offline
```

Um resultado verde no modo offline não compila Rust. Foram acrescentados 13
métodos de teste Rust, incluindo as 16 combinações de configuração/credenciais,
ambos os papéis de share XMR, mutações de pré-assinatura, recipient no codec,
reabertura de storage e key images derivados dos bytes. Não são 16 swaps.

A validação disponível aqui é registrada nos relatórios do ZIP. A aprovação
Rust que você informou pertence às versões anteriores testadas em sua máquina.
