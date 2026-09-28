# Retomada da observação da contraparte em processo novo

Esta etapa do mecanismo novo DOM↔XMR remove do processo anterior a interpretação
da cadeia usada pelo observador de retomada. O worker recebe apenas o diretório
da operação e seu identificador esperado. Os dois nós e a mineração do ensaio
continuam no supervisor; não é um reinício completo do executor nem integração
ao `dom-interopd`.

## Dados originais e obrigação

Antes da primeira liberação, `operation.checkpoint` fixa operação, digest do
manifesto, identidades DOM/XMR e portas locais. A credencial do RPC DOM fica
nesse arquivo privado, criado exclusivamente com modo 0600 e sincronização do
arquivo/diretório. Nenhuma URL externa é aceita. O cliente DOM não usa proxy
nem segue redirects. O servidor usa a implementação nativa `dom-rpc` sobre o
DomNode próprio, sem mudar configuração global de token ou sinais.

O checkpoint tem versão, checksum, tamanho limitado e parser estrito. O
identificador esperado vem do agendamento da operação. O manifesto validado
pelo digest original contém os envelopes, a cápsula, a ordem e os instantes
originais da janela. Carregá-lo não reinicia o relógio nem reaplica o limite de
primeira liberação à contraparte já devida.

Esse modelo pressupõe armazenamento local confiável: checksum não autentica
um invasor com escrita no diretório nem detecta restauração de um backup
antigo inteiro. O checkpoint contém uma credencial e vínculo entre transações;
não deve ser publicado. O journal da contraparte ainda nasce após a primeira
inclusão, conforme `COUNTERPART-DELIVERY.md`.

## O que o processo novo verifica

1. Reconstrói os envelopes DOM/XMR a partir do manifesto original, valida os
   corpos e pré-assinaturas e verifica que as duas claims revelam o mesmo
   witness. Não recebe segredo, nonce ou chave de assinatura pelo IPC e não
   cria assinatura.
2. Consulta as identidades dos nós: cadeia e gênese DOM, gênese XMR e perfil
   offline/fakechain do monerod próprio. As identidades devem corresponder ao
   checkpoint. Esse worker é específico para o laboratório regtest.
3. Consulta a transação DOM por hash. Um índice auxiliar pode não reconhecer
   uma transação já incluída; nesse caso, localiza o bloco pelo kernel nativo,
   sem tratar a ausência no índice como autorização de reenvio. Para inclusão,
   busca um scan nativo
   autenticado de um único bloco, com âncora anterior, e exige o corpo canônico
   exato, posição de bloco, cadeia e tip esperados. Confere novamente o bloco
   canônico pela altura. Para pool, usa a consulta autenticada ao nó próprio e
   o hash do corpo que ele mesmo validou.
4. Busca a transação XMR no monerod, compara os bytes nativos exatos e, se
   incluída, consulta o bloco canônico da altura informada e exige seu hash de
   transação. Confere os tips DOM/XMR novamente ao final das consultas.
5. Exige que a primeira perna continue incluída. Reconstrói `DeliveryBinding`
   usando manifesto e primeira claim/bloco/altura observados por ele próprio;
   só então reabre o journal e confere exposição e bytes da contraparte.
6. Decide `MonitorPool`, `MonitorInclusion` ou `Reconcile`. Uma consulta
   desconhecida ou indisponível não autoriza reenvio. Este observador não
   despacha transações, não concede `AbsentAndUnspent`, não escolhe refund e
   não declara finalização permanente.

Os checks de tip detectam mudanças visíveis entre consultas; não criam um
snapshot atômico, prova de finalização, defesa contra reorg ABA ou autenticação
de um nó hostil. O nó local de consenso permanece a fonte confiável de cadeia.
Se a primeira inclusão mudar de bloco, a vinculação antiga do journal exige
reconciliação; este código não reescreve a obrigação automaticamente.

## Ensaio e verificações

Os modos `direct-pair-{xmr,dom}-first-ack-loss` agora executam três observadores
novos depois de o emissor receber EOF e morrer com exit 74: contraparte no
pool, contraparte no bloco e RPC DOM realmente desligado. Cada processo só
recebe diretório e operação. A última consulta deve voltar a `Reconcile`,
mesmo tendo havido uma inclusão válida na consulta anterior.

O pai também conserva suas verificações nativas independentes do ensaio, mas
não entrega suas observações ao worker. O mecanismo ainda não restaura o
coordenador anterior ao funding/disclosure, solver ou transporte dos pares.

Os 52 testes Rust desta etapa passaram, incluindo restauração dos instantes
originais, corrupção de cada byte do checkpoint, todas as truncagens, mistura
de operações e formato não canônico do manifesto. Clippy all-targets com
`-D warnings` e build separado também passaram. Os resultados dos ensaios
nativos devem ser consultados nos artefatos `DIRECT-PAIR-*-SETTLEMENT-RESUME-*`.
Tempos de moedas regtest não provam segurança ou prazo adversarial de produção.

O primeiro ensaio XMR-first desta etapa foi interrompido corretamente em
82,518 s: `/tx/{hash}` não reconheceu a inclusão, e o observador retornou
`Reconcile` em vez de presumir ausência. Evidência preservada no prefixo
`DIRECT-PAIR-XMR-FIRST-SETTLEMENT-RESUME-INDEX-MISS-*`. A correção no cliente
consulta o índice nativo de kernel e exige em seguida o corpo exato no scan;
não altera índices ou consenso do protocolo DOM existente.

Na repetição corrigida, XMR-first passou em **189,613 s** totais, com ambas as
claims em **101,893 s**. Os três processos independentes consumiram
**0,222 / 0,116 / 0,079 s** para pool, inclusão e RPC desligado. O segundo
usou de fato o caminho kernel + scan após ausência no índice de transação.
Todos os outputs foram gastos e a devolução DOM conflitante foi rejeitada.
O ensaio integral ficou **acima de três minutos**; o tempo menor das claims
não substitui esse resultado. Preparação individual levou 28,218 s e
verificação/preparação da cápsula 67,227 s nesta execução. Evidência
`DIRECT-PAIR-XMR-FIRST-SETTLEMENT-RESUME-*`.

DOM-first passou em **169,919 s** totais, claims em **83,693 s**, observadores
em **0,166 / 0,111 / 0,074 s**. Os dois primeiros tiveram de recuperar a
inclusão DOM pelo kernel e exigir o corpo nativo no scan; o terceiro retornou
`Reconcile` com o RPC desligado. Outputs gastos e devolução DOM conflitante
rejeitada na altura 214. Evidência
`DIRECT-PAIR-DOM-FIRST-SETTLEMENT-RESUME-*`.

Os dois ensaios corrigidos encerraram com exit 0; nenhum observador enviou
transação ou recriou assinatura. A divergência entre 169,919 s e 189,613 s
impede usar esses resultados como limite de três minutos. A meta permanece
aberta, assim como os limites temporais adversariais e a prova de segurança.

Próxima lacuna de restart: os arquivos `observed.tx` e `counterpart.tx` ainda
são escritos depois da primeira inclusão. O journal inicial tem política e
digest da primeira claim, mas não seus bytes completos. É necessário poder
descobrir a primeira inclusão e reconstruir a obrigação após queda anterior
a esses arquivos e ao journal da contraparte, preservando a operação original.
