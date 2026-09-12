# Evidência nativa F7 por família — V11 em desenvolvimento

As APIs deste módulo fazem observações reais por transportes concretos. Não
aceitam eventos preenchidos pelo chamador nem uma implementação arbitrária de
trait para produzir evidência autenticada. BTC conserva a autoridade V2 e sua
política M.8; as outras famílias não são codificadas como Bitcoin.

| Família | Entrada concreta | Verificações |
| --- | --- | --- |
| EVM | `EvmFundingAuthorityV11::new/observe` | Registro, genesis, contrato, termos, txid exato, recibo, ancestralidade finalizada, `lockOf` integral ainda aberto em hashes canônicos e prazo pelo timestamp nativo. |
| SOL | `SolanaFundingAuthorityV11::new/observe` | Registro, genesis, programa imutável, setup DLEQ, assinatura completa, quorum estrito, instrução nativa, contas e vault, estado ainda Funded, âncoras finalizadas revalidadas. |
| XMR | `verify_xmr_funding_v11` | Registro, genesis, perfil e quorum assinados, txid/inclusão exatos, view scan autenticado via UDS, valor e chave pública compartilhada exatos, snapshots estáveis antes/depois. |

EVM e SOL retornam `Ok(None)` para ausência legítima. XMR usa
`F7FamilyAuthorityErrorV11::FundingAbsent`. Respostas não nulas com outro txid
ou assinatura são erros duros. Um erro de transporte não é evidência de ausência.

`verify_dom_xmr_anchor_evidence_v11` acrescenta a leitura DOM autenticada,
com C ainda não gasto no snapshot completo, e verifica:

- política de compensação comprometida em `terms.assurance_policy_hash`;
- política, sessão, papéis, templates e objeto canônico de prontidão;
- valor confidencial de C pela formação nativa `FrozenSharedOutputV1`, incluindo
  provas das shares, contexto, roster e o hash exato do statement;
- prova DLEQ de U, role 2, e a soma pública T + U do depósito XMR;
- graph nativo cancel/refund/compensação e sua janela de revelação;
- idade limitada da observação externa ao final da leitura DOM.

O resultado `VerifiedDomXmrAnchorEvidenceV11` é evidência linear e **não é uma
permissão de assinatura**. O Store ainda deve autenticar os dois votos, os rounds
ordinários de cancel/compensação, os destinatários dos outputs e a custódia
durável antes de emitir sua própria permissão. Um recibo V2 de M.8 não pode ser
reinterpretado como um registro V11. O campo de digest do objeto de prontidão
tem interpretação V11 somente dentro do novo consumidor versionado.

O módulo SOL produz evidência de funding. A decisão final de revelação ainda
precisa consultar o relógio nativo e aplicar a política temporal da rota. A
compensação em DOM é resultado econômico distinto do refund em XMR.

## Validação

Foram escritos testes Rust para identidade ausente versus substituída, todos
os campos ABI do lock EVM, recusa de escrows SOL terminais, vinculação de
snapshots, nonces XMR, quorum e opacidade das estruturas. O cliente SOL recebeu
testes da assinatura efetivamente retornada pelo RPC.

Os arquivos passaram pela análise sintática local. Não foi executado Cargo
neste ambiente. Os testes ainda precisam ser compilados e executados:

```sh
cargo test --locked -p f7-anchor-authority
cargo test --locked -p solana-rpc
```

Esses testes não demonstram swaps pelo binário ou aceitação das 16 rotas.
