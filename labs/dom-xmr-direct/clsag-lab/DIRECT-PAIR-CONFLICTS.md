# Conflitos nativos após entrega dos adaptors

Ensaios próprios offline, exclusivamente DOM↔XMR. Os parâmetros temporais
continuam condicionais, conforme `DIRECT-PAIR-REGTEST.md`. Não são uma prova
de segurança bilateral nem uma implementação integrada ao dom-interopd.

## Verificação antes da exposição

Uma assinatura adaptadora concluída revela o segredo a quem possui o adaptor
correspondente, mesmo sem inclusão em bloco. Verificar que a transação foi
rejeitada pela cadeia não apaga os bytes já entregues a uma contraparte.

`AssumedXmrRecoveryWindow::check_initial_claim_release` verifica, antes de
expor a primeira claim, que sua resolução ainda cabe estritamente antes da
recuperação adversarial assumida. XMR-first conta resolução XMR; DOM-first
conta resolução DOM, observação e resolução XMR. O exemplo repete o check
imediatamente antes de enviar a primeira transação ao nó. A verificação
posterior à inclusão permanece, mas não substitui a anterior.

A origem da janela é conservada. O teste de fronteira cobre igualdade,
tentativa posterior após uma preparação permitida, ordem das duas claims,
instante anterior à divulgação, custos inválidos e overflow. A função é
aritmética condicional: não autentica o relógio nem persiste a decisão.

Não usar esse check para abandonar uma obrigação já iniciada: uma claim da
contraparte devida após pagamento deve ser resolvida. Uma assinatura inicial
já exposta também exige reconciliação. O executor durável precisa distinguir
preparação privada, exposição possível e evidência canônica; esse executor
ainda não existe no laboratório. A barreira durável da primeira liberação
agora está em `INITIAL-RELEASE-JOURNAL.md`; ela conserva exposição possível
após falha, mas ainda não executa a reconciliação das cadeias.

## Cenários implementados

Os três cenários preparam e verificam ambos os adaptors antes da recuperação.
O processo conserva somente a share XMR local após a rodada de assinatura;
a share remota vem da abertura pública, é conferida contra seu ponto e recebe
o offset depois. A devolução resultante é uma transação nativa diferente da
claim, com o mesmo key image. Nonces e chave de transação são novos.

| Modo | Sequência exercitada |
| --- | --- |
| `direct-pair-claim-wins` | As claims são incluídas e gastas; a abertura pública permite assinar uma devolução XMR válida, rejeitada por key image gasto. A devolução DOM tardia também é rejeitada. |
| `direct-pair-refund-wins` | A devolução XMR vence após os adaptors; a liberação tardia da primeira claim é recusada; DOM é devolvido na altura prevista. Somente depois de ambas as devoluções, replays XMR e DOM válidos são expostos e rejeitados por inputs gastos. |
| `direct-pair-late-claim-audit` | Controle negativo: ignora deliberadamente a recusa e entrega à contraparte uma claim XMR válida que perdeu para a devolução. A contraparte tenta extrair o segredo desses bytes e tomar DOM antes da altura de devolução. |

O controle negativo entrega os bytes explicitamente a uma contraparte. Ele
**não** supõe que um RPC privado rejeitado seja retransmitido pelo monerod.
Se a tentativa de tomada DOM funcionar, isso demonstra por que a prevenção
precisa anteceder a exposição do segredo; não que o novo check tenha aprovado
a operação tardia.

Essas são ordens controladas de conflitos canônicos. Não cobrem seleção de
mempool entre mineradores adversariais, reorg, perda de confirmações, censura,
rollback de relógio ou recuperação após queda do coordenador. A mineração DOM
avança durante a abertura XMR nos cenários positivos. O controle negativo
não espera a altura de devolução: seu objetivo é verificar a perda antes dela.

## Reprodução

```sh
cargo build --offline --release --locked --example regtest_claim -j 2
target/release/examples/regtest_claim /caminho/absoluto/monerod \
  direct-pair-refund-wins /caminho/absoluto/direct-dlog-bridge
```

Trocar somente o modo para os outros cenários. O processo inicia nós próprios
com moedas de teste e inclui setup, saldos, cápsula, depósitos e verificações
no tempo total. Compilação é separada. Um controle negativo concluído significa
reprodução do contraexemplo, não aprovação do comportamento inseguro.

## Evidência preservada

O controle negativo reproduziu a perda em **118,846 s** totais. A checagem
recusou a liberação, mas o ensaio a ignorou deliberadamente: o monerod
rejeitou a claim XMR com `double_spend=true`; os bytes entregues à contraparte
permitiram extrair o segredo e incluir a claim DOM na altura 7, gastando sua
saída na 8. Essa parte já havia recebido e gasto sua devolução XMR. O dono do
DOM não recebeu XMR e não recuperou DOM. A altura prevista de devolução era
214, ainda não alcançada. Isso é um contraexemplo à exposição tardia, não à
recusa implementada. Resultado, fases, watchdog e hashes em
`DIRECT-PAIR-LATE-CLAIM-AUDIT-*`.

O cenário que respeita a recusa (`direct-pair-refund-wins`) passou em
**171,147 s**. A abertura/conferência levou 35,168 s. A devolução XMR foi
incluída e seus dois outputs foram gastos; DOM foi devolvido na altura 215
e gasto na 216. Nenhum byte da claim tardia foi exposto à contraparte antes
dessas devoluções. Depois, a tentativa XMR perdeu pelo key image gasto e a
claim DOM extraída dela perdeu pelo input gasto. O dono original de DOM
recuperou seu saldo, sem pagar XMR ao comprador. Evidência preservada em
`DIRECT-PAIR-REFUND-WINS-*`.

O cenário `direct-pair-claim-wins` passou em **168,811 s**, com ambas as
claims incluídas em **82,534 s**. As saídas DOM, XMR do comprador e troco do
dono original foram gastas. A abertura/conferência posterior levou 34,001 s
e permitiu assinar uma devolução XMR criptograficamente válida; o monerod
rejeitou-a com `double_spend=true`. Na altura DOM 214, a devolução DOM também
foi rejeitada. Evidência em `DIRECT-PAIR-CLAIM-WINS-*`.

Os 21 testes Rust e Clippy de todos os targets passaram nesta etapa. Os dois
cenários positivos acima incluem preparação e verificações posteriores no
total e ficaram abaixo de 180 s localmente. O controle negativo tem sucesso
como reprodução de perda, nunca como uma troca segura. Nenhum desses ensaios
estabelece limites temporais adversariais ou cobre retomada após falha.

A regressão `direct-pair-dom-first` com a nova checagem de liberação passou
em **168,676 s**, com as claims incluídas em 81,558 s. O segredo original foi
descartado antes de observar DOM; o pagamento XMR, os gastos posteriores e
a rejeição da devolução DOM tardia também passaram. Evidência preservada em
`DIRECT-PAIR-DOM-FIRST-RELEASE-CHECK-*`. Os hashes dos executáveis e fontes
conferem nos quatro conjuntos desta etapa, e seus processos terminaram.
