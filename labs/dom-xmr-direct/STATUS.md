# Continuidade — 26/09/2026

Missão reiterada pelo operador e registrada em `../../AGENTS.md`: **criar um
mecanismo novo**, não melhorar o protocolo anterior. A perna DOM↔XMR deve
funcionar diretamente, sem BTC no fluxo, conforme correção explícita do
operador nesta sessão. O clone original permanece fora das alterações.

Esclarecimento de escopo após compactação: o protocolo completo contempla
Bitcoin, Solana, EVM e Monero como pernas ligadas a DOM. Esta missão é somente
DOM↔Monero; a perna DOM↔Bitcoin quase concluída não será modificada. O modelo
executado por padrão agora é bilateral, inclusive seu controle negativo. Os
testes anteriores de composição estão preservados em `historical/`.

## Evidência obtida

**Cenário que falhava por HTTP 429 agora passou com o burst padrão 100.**
O worker reutiliza o pai do cabeçalho como sugestão validada pelo scan nativo,
que lê âncora, identidade, bloco e transações sob um chain lock. A segunda
consulta de bloco foi removida; corpo exato, snapshot e checks finais de tips
permanecem. Não houve mudança no limitador/consenso do nó.

Somente GET com 429 e header de espera válido recebe repetição: até 2.000 ms
de espera solicitada compartilhada por worker. POST não é repetido, cancelamento
conta espera parcial, e erro persistente volta a Reconcile. Isso não é orçamento
global durável de tentativas. Passaram 38 testes relacionados, incluindo seis
novos de snapshot/HTTP/espera, Clippy e build. Notas em
`clsag-lab/RPC-READ-RECOVERY.md`.

As duas regressões nativas passaram com burst 100: DOM-first com retirada XMR,
**189,201 s** total / **103,184 s** claims / **0,946 s** recuperação; XMR-first
com reinclusão da primeira claim, **179,736 s** / **95,228 s** / **1,340 s**.
Tentativas públicas/autenticadas DOM dos workers: 82/31 e 62/16. Nenhum 429
nessas execuções; a política de espera é coberta pelos testes HTTP locais.
Outputs gastos e refunds conflitantes rejeitados, fontes/binário conferidos,
processos encerrados. Evidências `*-RPC-READ-RECOVERY-*`. Primeiro total acima
de três minutos; segundo sem margem suficiente para garantia de prazo.

Próximo avanço estrutural: retirar do supervisor a republicação da primeira
transação já exposta, com estado durável e verificação nativa independente.
Possível exposição sozinha não prova divulgação nem autoriza uma primeira
liberação tardia. A contraparte comprovadamente devida tem política distinta;
preservar essa distinção, a janela original e os bytes aprovados. Preparação
durável, participantes independentes, prova temporal/criptográfica e daemon
permanecem pendentes.

**Mesma primeira claim reincluída em outro bloco:** corrigida a rejeição do
journal por diferença de âncora. `DeliveryPayment` fixa manifesto, transação
exata e cadeia alvo; `open_for_payment` valida o registro completo e preserva
o bloco/altura históricos. O worker exige inclusão canônica atual antes dessa
abertura e verifica novamente corpo/witness da contraparte. A API de abertura
com binding completo continua estrita. Não há reset de prazo nem reescrita.

59 testes e Clippy passaram. `direct-pair-xmr-first-reinclude` passou com o
burst DOM padrão 100: **176,728 s** total, **90,383 s** até ambas as claims,
**1,180 s** para retirada/reinclusão/restauração. A claim mudou de 152 para
153; o journal e os registros de início permaneceram idênticos. Pool/ausência
recusaram envio; após reinclusão, o worker nativo publicou a contraparte,
outputs foram gastos e refund conflitante rejeitado. Fontes/binário conferidos,
processos encerrados. Detalhes em `clsag-lab/FIRST-PAYMENT-REINCLUSION.md` e
artefatos `DIRECT-PAIR-XMR-FIRST-REINCLUDE-*`.

Isso fecha a rejeição de uma primeira claim reincluída descrita abaixo. A
republicação da primeira transação no ensaio ainda é do supervisor; restart
integral, política/orçamento sob throttling, forks concorrentes, segurança
criptográfica/temporal e integração ao daemon permanecem pendentes.

**Retirada e reinclusão XMR reais no nó isolado:** o modo
`direct-pair-dom-first-xmr-detach` usa `pop_blocks`, verifica retorno ao pool,
retira somente essa transação do pool, minera substituição vazia e exige que
um worker novo consulte ausência/key image livre antes de reenviar os mesmos
bytes. Não é ainda escolha de fork entre peers. O ensaio padrão encontrou
HTTP 429 do DOM; o emissor retornou Reconcile sem tentativa de publicação.
Falhas em 108,376 s / 114,082 s preservadas em `*-INITIAL-FAILURE*` e
`*-DIAGNOSTIC-*`; a segunda localizou 429 em `/chain/identity` depois da retirada.

Com **DOM_RPC_RATELIMIT_READ=256**, explicitamente só no nó de laboratório,
o cenário passou: **173,427 s** total, **86,800 s** até claims/reinclusão,
**0,815 s** para retirada/evicção/reenvio/reinclusão. Mesmo journal, nova altura
152→153, todos os outputs gastos e refund conflitante rejeitado. Fontes/binário
conferidos e processos encerrados. Evidências
`DIRECT-PAIR-DOM-FIRST-XMR-DETACH-CAPACITY256-*`; detalhes e limites em
`clsag-lab/XMR-NATIVE-DETACH.md`. Não alegar que os defaults passaram: burst
100/reposição 1/s bloqueou a sequência de verificações. Tratar disponibilidade
do RPC no orçamento e testar reinclusão da PRIMEIRA claim são próximos passos;
hoje a âncora imutável da obrigação rejeita essa mudança mesmo com bytes iguais.

**Envio nativo pelo worker restaurado:** a etapa seguinte passou nos dois
sentidos; detalhes em `clsag-lab/NATIVE-SENDER.md`. O worker agora consulta
os RPCs e publica diretamente a contraparte persistida, após fsync de
exposição e nova consulta, sem encaminhamento inicial pelo supervisor.
Queda antes do RPC (77), queda após receber admissão nativa (76) e retomadas
preservam os mesmos bytes. A queda 76 não simula perda da resposta do nó.
Pedidos de envio em pool, bloco e RPC indisponível não despacharam transação.
57 testes, Clippy e build passaram. XMR-first: **183,011 s** totais / **93,891 s**
até claims; DOM-first: **200,772 s** / **111,636 s**. Ambos excederam 180 s.
Gastos posteriores e rejeição da devolução conflitante passaram. Fontes e
binários conferidos; ensaios encerrados. Artefatos `DIRECT-PAIR-*-NATIVE-SEND-*`.

A lacuna de encaminhamento descrita nas etapas históricas abaixo está fechada
nesse caminho de laboratório. Continuam abertos restart integral, persistência
anterior a depósitos/divulgação, solver, reorg nativo e concorrência, preparação
independente/autenticada, limites temporais e revisão criptográfica, além da
integração ao dom-interopd. Consultas sequenciais a nós próprios não provam
snapshot atômico ou segurança frente a nós hostis. A próxima validação deve
exercitar mudanças reais de cadeia e o orçamento integral de retomada sem
renovar o prazo original. O mecanismo segue experimental.

**Obrigação reconstruída antes de haver arquivos pós-inclusão:**
`clsag-lab/OBLIGATION-RECONSTRUCTION.md` descreve o novo caminho. Bytes da
primeira claim são persistidos antes do envio; o manifesto v2 preserva também
o orçamento original de candidatos. O worker restaura a política, confere o
journal de exposição inicial e consulta inclusão nativa antes de completar o
adaptor e criar o journal da contraparte. Journal existente é reaproveitado
sem nova assinatura; exposição nunca vira preparação privada. O pai ainda
hospeda os nós e encaminha o envio pela ponte do ensaio.
Passaram 54 testes, Clippy all-targets e build separado. XMR-first passou em
**167,841 s** totais, claims em **80,239 s**, três workers de queda/reconstrução/
reuso em **0,550 s**. A primeira claim apenas no pool foi recusada; houve
exit 75 antes de criar a obrigação, reconstrução sem `observed.tx` ou
`counterpart.tx`, reuso byte a byte e exit 74 no envio sem resposta. Pool,
bloco e RPC indisponível foram reconciliados; todos os outputs foram gastos
e a devolução DOM conflitante foi rejeitada. Evidência
`DIRECT-PAIR-XMR-FIRST-OBLIGATION-RECONSTRUCTION-*`. Isso não apaga as rodadas
anteriores acima de 180 s nem comprova limites de tempo ou atomicidade.
DOM-first também passou, em **205,188 s** totais, claims em **116,390 s** e
queda/reconstrução/reuso em **0,983 s**. Todos os controles funcionais passaram,
mas o total excedeu a meta. Preparação individual consumiu 44,455 s nessa
rodada, contra 16,721 s no sentido inverso. Evidência
`DIRECT-PAIR-DOM-FIRST-OBLIGATION-RECONSTRUCTION-*`; diagnóstico de relógios
em `OBLIGATION-RECONSTRUCTION-TIMING.json`. A folga observada entre inclusão
XMR e a recuperação adversarial condicional foi de 13 s / 5 s. Esses dados
não fundamentam as premissas de um segundo por etapa ou um limite global.

Próximo trabalho concreto: o worker já constrói a obrigação, mas o supervisor
ainda encaminha sua publicação pela ponte. Transferir envio/reconciliação ao
coordenador restaurado, preservando bytes/exposição e evitando tomar not-found
como prova de input livre. O custo completo de IO, retomadas e observações
precisa estar explícito no orçamento original; não fechar uma contraparte
devida pela expiração do gate de iniciação. Continuam faltando restart anterior
a funding/disclosure, solver, participantes independentes/autenticados,
reorgs nativos, fundamentação temporal/criptográfica e integração ao daemon.

**Observador de retomada independente:** a nova etapa em
`clsag-lab/SETTLEMENT-RESUME.md` persiste um checkpoint original antes da
primeira liberação. Depois de envio sem resposta, processos novos recebem
somente diretório e operação, restauram manifesto/envelopes e consultam os
RPCs nativos DOM/XMR. Reconstroem a vinculação da primeira inclusão e da
contraparte por conta própria, preservando os instantes originais. O pai
permanece como host dos nós e minerador do ensaio; não é restart completo.
Passaram 52 testes, Clippy all-targets e build separado. O primeiro ensaio
revelou ausência no índice auxiliar DOM após inclusão; foi preservado como
`DIRECT-PAIR-XMR-FIRST-SETTLEMENT-RESUME-INDEX-MISS-*`. A correção usa o kernel
para localizar o bloco e exige corpo exato no scan nativo, sem alterar o nó.
O novo XMR-first passou em **189,613 s** totais, claims em **101,893 s**:
pool, inclusão e RPC realmente indisponível foram consultados em processos
distintos (0,222 / 0,116 / 0,079 s). Não houve reenvio nem nova assinatura;
outputs gastos e devolução conflitante rejeitada. O total **ultrapassou três
minutos**; não selecionar apenas o tempo das claims como prova da meta total.
Evidência `DIRECT-PAIR-XMR-FIRST-SETTLEMENT-RESUME-*`.
DOM-first também passou, em **169,919 s** totais, claims em **83,693 s** e
observadores em 0,166 / 0,111 / 0,074 s, inclusive fallback kernel+scan para a
primeira perna e falha real de RPC após inclusão. Evidência
`DIRECT-PAIR-DOM-FIRST-SETTLEMENT-RESUME-*`. A observação restaurada ainda
depende de arquivos da primeira claim/contraparte gravados após a inclusão;
não cobre queda antes desses arquivos ou do journal da obrigação. Segurança,
limites de tempo e integração ao daemon permanecem em aberto.

**Envio da contraparte sem resposta:** `counterpart_delivery.rs` persiste os
bytes exatos e exposição antes do envio, vinculados ao manifesto original e
à primeira claim observada. Emissão ambígua mantém exposição e exige nova
consulta; pool/inclusão não geram retry; ausência com input não gasto permite
apenas os mesmos bytes, sem nova assinatura ou prazo. O manifesto de claims
agora também conserva operação, cápsula, janela original, ordem e custos antes
da primeira liberação. O pai ainda é necessário para autenticar contexto e
observações; não é reinício completo do coordenador. Notas
`clsag-lab/COUNTERPART-DELIVERY.md`. Passaram 49 testes e Clippy all-targets.
XMR-first com perda da resposta passou em **171,713 s**, claims em 83,788 s,
trecho de envio da contraparte em 0,166 s. A ponte admitiu a transação no nó e
fechou sem responder ao emissor (exit 74); o registro reaberto acompanhou pool
e bloco nativos. Evidência `DIRECT-PAIR-XMR-FIRST-ACK-LOSS-*`.
DOM-first com perda da resposta também passou em **168,896 s**, claims em
82,681 s, trecho de envio em 0,301 s; evidência
`DIRECT-PAIR-DOM-FIRST-ACK-LOSS-*`. Os dois cenários gastaram os outputs e
rejeitaram a devolução DOM conflitante; hashes conferidos e processos encerrados.

**Retomada da claim devida em outro processo:** `PreparedClaim` agora pode ser
consumido por `XmrClaimEnvelope`, descartando a abertura privada usada na
assinatura. XMR e DOM têm registros de retomada canônicos e limitados, fixados
pelo digest aprovado. O ensaio persiste ambos antes da primeira claim, paga a
primeira perna, descarta os objetos e o witness original, encerra um worker
com exit 73 e inicia outro para extrair/completar a contraparte. Os nós e o pai
permanecem em execução; a inclusão canônica é verificada pelo pai. Não é um
restart completo do executor/daemon. Detalhes em `clsag-lab/CLAIM-RESUME.md`.
Passaram 43 testes Rust e Clippy all-targets. A retomada XMR-first passou em
**170,142 s** (claims 83,299 s, workers 0,321 s), com gastos posteriores e
devolução conflitante rejeitada; evidência `DIRECT-PAIR-XMR-FIRST-RESUME-*`.
DOM-first também passou em **171,024 s** (claims 83,683 s, workers 0,289 s),
publicando o pagamento XMR produzido pelo processo restaurado e rejeitando
a devolução DOM na altura 215. Evidência `DIRECT-PAIR-DOM-FIRST-RESUME-*`.
Os dois processos principais e seus workers terminaram; hashes conferidos.

**Primeira liberação com registro durável:** `release_journal.rs` conserva o
vínculo à operação, cápsula, prazo original, ordem e transação exata. Grava e
sincroniza exposição possível antes de chamar a rede, verifica o relógio
novamente após o disco e exige reconciliação depois de falha/cancelamento.
O fechamento por prazo expirado é persistente. Reabrir não renova a janela.
Dez testes de integração e um teste de erro de escrita passaram: encerramento
de processo sem destructors, locks entre processos, corrupção/registro parcial,
RPC rejeitado, cancelamento, relógio recuado e tempo consumido por fsync.
Detalhes e limites em `clsag-lab/INITIAL-RELEASE-JOURNAL.md`.
Isso é uma barreira de primeira publicação, não a recuperação completa do
executor: persistência anterior ao funding/disclosure, sessões de assinatura,
reconciliação canônica, autenticação e integração ao dom-interopd permanecem
pendentes. Não aplicar o fechamento de iniciação a uma contraparte já devida.
As regressões nativas com a versão atual passaram: XMR-first em **166,429 s**
(claims 78,718 s) e DOM-first em **166,947 s** (claims 80,649 s), incluindo
gastos posteriores e devoluções conflitantes rejeitadas. Evidências
`DIRECT-PAIR-XMR-FIRST-JOURNAL-FINAL-*` e `DIRECT-PAIR-DOM-FIRST-JOURNAL-*`.
O XMR-first preliminar em 173,535 s foi preservado separadamente, com seu
binário anterior à sincronização também na reabertura e compilação concorrente.
São 32 testes Rust aprovados na verificação conjunta, além de Clippy all-targets.

**Exposição tardia após os adaptors:** o novo controle negativo reproduziu
perda em 118,846 s. Após recuperar XMR, a contraparte recebeu os bytes de uma
claim XMR tardia, rejeitada por key image gasto, extraiu o segredo e tomou DOM
na altura 7. A verificação temporal havia recusado essa exposição e foi
deliberadamente ignorada no controle. Respeitando a recusa, o cenário
`direct-pair-refund-wins` passou em **171,147 s**, devolvendo ambos os ativos
e rejeitando replays XMR/DOM depois das devoluções. Evidências
`clsag-lab/DIRECT-PAIR-LATE-CLAIM-AUDIT-*` e `DIRECT-PAIR-REFUND-WINS-*`.
O mecanismo agora revalida a primeira liberação antes de completar e publicar
a claim inicial; a confirmação posterior não substitui essa decisão.
São ordens controladas de conflito, não uma prova de seleção de mempool,
reorg ou transporte privado. Detalhes em `clsag-lab/DIRECT-PAIR-CONFLICTS.md`.
Passaram 21 testes Rust e Clippy de todos os targets nesta etapa.
O cenário oposto, `direct-pair-claim-wins`, também passou em **168,811 s**:
claims incluídas em 82,534 s e gastos posteriores; a recuperação pública
permitiu assinar uma devolução XMR válida, rejeitada por key image gasto.
A devolução DOM foi rejeitada na altura 214. Evidência
`clsag-lab/DIRECT-PAIR-CLAIM-WINS-*`.
A regressão DOM-first com esse check passou em **168,676 s**, claims em
81,558 s, com descarte do witness original e extração da transação DOM
canônica, gastos posteriores e rejeição da devolução tardia. Evidência
`clsag-lab/DIRECT-PAIR-DOM-FIRST-RELEASE-CHECK-*`. Os quatro conjuntos novos
conferem com os hashes dos fontes e binários executados; processos encerrados.

**Primeira composição completa DOM↔XMR aprovada:** XMR-first concluiu ambas
as claims em **82,206 s** e o ensaio inteiro em **168,836 s**, incluindo espera
pela altura 214 e rejeição da devolução DOM conflitante. Saída DOM, pagamento
XMR e troco XMR foram gastos posteriormente. Não houve abertura da cápsula no
caminho cooperativo. A mineração usou o modo regtest nativo sem carteira
de recompensas após preparar o saldo individual; nenhum limite de consenso
ou janela temporal foi reduzido. Resultado, fases, watchdog e hashes em
`clsag-lab/DIRECT-PAIR-XMR-FIRST-*`. Continua com `atomic_swap=false` e
`safe_bilateral_window_proven=false`; não é uma prova contra adversários.
DOM-first passou em **165,979 s**, claims em **79,088 s**, extraindo o segredo
da transação DOM canônica após descartar o witness original. Também gastou os
outputs e rejeitou a devolução na altura 214. Evidência
`clsag-lab/DIRECT-PAIR-DOM-FIRST-*`.

**Abandono dos dois depósitos também aprovado dentro de três minutos:**
`direct-pair-abandon` levou **173,551 s** totais, incluindo uma abertura
XMR de 35,499 s, devolução XMR observada aos 121,739 s, gasto de seus outputs
e devolução DOM na altura 216, gasta na 217. Durante a recuperação, DOM avançou
até 139; a devolução só foi publicada após alcançar 215. Evidência
`clsag-lab/DIRECT-PAIR-ABANDON-*`. A tentativa anterior serial foi correta,
mas demorou 204,880 s; permanece em `DIRECT-PAIR-ABANDON-SERIAL-*`.
O ensaio agora deixa a cadeia avançar durante o solve, sem mudar a altura
calculada ou o relógio. A devolução XMR é observada antes de aguardar DOM.
Passaram 20 testes Rust e Clippy de todos os targets após essa mudança.
A regressão nativa `height-dom-first` passou em 29,106 s, incluindo claims,
gastos posteriores e devolução conflitante rejeitada; evidência
`clsag-lab/HEIGHT-DOM-FIRST-MINER-*`. Todos os processos próprios terminaram.

Os três resultados acima são locais e condicionais, com preparação no total
e compilação separada. Não concluem a missão: as disputas ordenadas após entrega
dos adaptors foram acrescentadas depois e estão descritas acima; ainda faltam
preparação entre partes independentes, transporte autenticado,
persistência/reabertura, política de reorg/finalização, justificativa dos
limites temporais e análise criptográfica completa, além de dom-interopd.

**Tentativa anterior instrumentada, encerrada sem relatório final:**
`direct-pair-xmr-first` incluiu as claims DOM e XMR em **79,335 s**, incluindo
a preparação, e concluiu os gastos posteriores em **81,064 s**. Depois atingiu
o timeout interno de 240 s durante a mineração até a altura conservadora de
devolução DOM (214; último progresso registrado 176). Evidência
`clsag-lab/DIRECT-PAIR-XMR-FIRST-INSTRUMENTED-FAILURE.*`. Isso prova as
transferências dessa execução, mas não a rejeição tardia nem atomicidade.
A segunda tentativa sem instrumentação também expirou em 240 s e está
preservada em `DIRECT-PAIR-XMR-FIRST-SECOND-FAILURE.json`; a primeira falhou
antes de depositar XMR por consumir a janela de preparação. O ensaio novo
passa a usar o minerador regtest nativo sem carteira depois do saldo individual,
mantendo todas as validações e o mesmo prazo. Detalhes e limitações em
`clsag-lab/DIRECT-PAIR-REGTEST.md`.

DOM permanece central: a composição futura XMR↔BTC deve seguir XMR↔DOM↔BTC.
O trabalho atual é exclusivamente a nova perna DOM↔XMR. O laboratório usa
monerod externo e DomNode local; não está integrado ao dom-interopd.

**Saldo individual antes da cápsula, depósito nativo depois da verificação:**
o perfil direto T=10.000.000 passou em **131,917 s** totais, incluindo geração
do saldo (14,157 s), cápsula (66,445 s), depósito/maturação local (1,009 s),
recuperação (48,180 s), devolução e gasto dos dois outputs. A reserva recebeu
uma transferência nativa de 5 XMR de teste; não uma coinbase direta. O período
após receber a oferta foi **17,423 s**, e a abertura **48,179 s**. Esse intervalo
positivo local é evidência de viabilidade do próximo ensaio, não limite mínimo
adversarial ou atomicidade. Não se escondeu a preparação do saldo no total.
Resultados `clsag-lab/XMR-DIRECT-TRANSFER-10M-*`; watchdog sem timeout.
Ainda sem admissão temporal, DOM no mesmo ensaio ou adversário de rede.
Os três testes do cliente passaram após a separação, assim como Clippy de todos
os targets. A regressão financiada `height-dom-first` passou em 34,863 s:
claims DOM/XMR, gastos posteriores e rejeição da devolução DOM conflitante.
Resultados `clsag-lab/HEIGHT-DOM-FIRST-FUNDING-REGRESSION-*`. Esse ensaio de
regressão não inclui a cápsula direta e não substitui a composição pendente.
Próximo: integrar essa recuperação com claims concorrentes e altura DOM,
preservando a divulgação original e premissas explícitas sobre velocidade,
disponibilidade, transporte, persistência e finalização das cadeias.

**Perfil direto de 10 milhões de quadraturas, antes de separar saldo e
depósito:** a devolução financiada passou em 130,227 s totais. Setup público
31,658 s; geração 14,852 s; verificação 14,982 s; abertura 39,536 s. O intervalo
após receber a oferta foi 40,376 s, ainda maior que a abertura local. Resultado
`clsag-lab/XMR-DIRECT-RECOVERY-10M-*`; não comprova margem bilateral. A escolha
de T é conferida pelo receptor antes de aceitar o setup, rejeitando downgrade,
valores fora da lista e simples alteração de T sem alterar h. O parser legado
continua fixo em 200.000. Passaram os 21 testes Go e o teste adicional de
consistência do perfil longo; 19 Rust, Clippy e go vet passaram nessa etapa.

**Devolução XMR financiada com cápsula direta:** passou em 52,027 s totais,
incluindo preparação da cápsula (30,667 s), fundos locais (18,794 s), abertura
e recuperação Rust (0,673 s), inclusão e gasto dos dois outputs. Resultado
`clsag-lab/XMR-DIRECT-RECOVERY-REGTEST-RESULT.json` e watchdog sem timeout.
Não exercita DOM nem usa admissão temporal. Após receber a oferta decorreram
33,689 s antes da abertura, que levou 0,671 s: o perfil curto permanece sem
margem demonstrada. O novo orçamento `from_direct_costs` vincula uma abertura
à cápsula/roster/papel; a construção anterior conserva todos os 99 candidatos.
Passaram 19 testes Rust (12 prazos, quatro vínculo, três cliente) e Clippy de
todos os targets. Próximo: perfil temporal útil e composição com claims/altura
DOM; segurança bilateral, transporte autenticado e persistência pendentes.

**Cápsula direta entre processos e roster Rust:** `direct_recovery_bridge`
passou em 37,838 s, com setup conferido antes da oferta, produtor encerrado,
uma abertura pública e reconstrução da share individual esperada no Rust.
Geração 17,940 s; verificação 17,517 s; abertura 1,119 s. Hash dos bytes da
cápsula, escalar, ponto e término do processo são conferidos. O construtor
`XmrDirectRecoveryLink` rejeita contexto/chave de outro papel antes de abrir;
recuperação confere roster/papel/binding novamente. O offset vem depois.
Resultados `clsag-lab/DIRECT-DLOG-IPC-*`, incluindo ensaio inicial de 42,014 s.
Sem funding ou troca bilateral, sem margem temporal comprovada.

Passaram 20 testes Go distintos (incluindo cancelamento, replay, limites de
mensagem e regressões anteriores), 25 Rust (quatro do vínculo direto e 21 de
assinatura/recuperação), Clippy de todos os targets e `go vet`. O argumento
interno de extração/privacidade e suas premissas estão em
`recovery-audit/DIRECT-DLOG-AUDIT.md`. Próximo: orçamento temporal ligado ao
vínculo de uma abertura, margem após preparação e devolução financiada com
claims concorrentes; autenticação/persistência e auditoria continuam pendentes.

**Experimento de uma abertura com vínculo Ed25519:** a investigação em
`recovery-audit/direct_dlog.go` passou em um puzzle real. Prova de relação
experimental com 256 desafios de um bit, respostas inteiras limitadas,
contexto/chave esperados do chamador, framing e subgrupo primo. Setup/verificação
0,835 s; geração 17,433 s; verificação 17,236 s; abertura 0,740 s; total positivo
36,248 s. Quatro testes Go passaram, incluindo 19 mutações adversariais,
torsão/pontos não canônicos e replay; `go vet` passou. Resultado em
`recovery-audit/DIRECT-DLOG-RESULT.json`. Sem IPC, funding ou fluxo bilateral;
o perfil curto ainda não tem margem temporal. O backend antigo não foi trocado.

Oito testes do modelo algébrico passaram, incluindo duas falsificações quando
se retiram os limites de inteiros/representação assinada. Enumeração: 1.155
statements e 7.488 pares aceitos, nenhum abrindo para o ponto errado. Isso não
prova privacidade, soundness geral ou tempo. A proposta, argumento de extração,
limites e reprodução estão em `recovery-audit/DIRECT-PLAINTEXT-RESEARCH.md`.
Próximo: auditar esses argumentos, testar o vínculo com o roster/ponto Rust e
isolar produtor/verificador antes de considerar integração aos fundos locais.

**Medição integral do trabalho de busca:** o benchmark Go com partição fixa
processou 99 candidatos reais (98 valores `q+1` rejeitados e último válido).
Busca 64,716 s; preparação 35,862 s; total 100,578 s. É uma fixture de custo,
sem desafio Fiat-Shamir, Feldman/Rust, IPC ou funding; não comprova limite
honesto nem cápsula adversarial aceita. Relatório em
`recovery-audit/FULL-SEARCH-WORKLOAD-RESULT.json`. A multiplicação do trabalho
por até 99 continua mesmo aumentando T. Próxima investigação: prova direta
do vínculo ciphertext/ponto público, sem reduzir a garantia de recuperação.

**Setup antes da divulgação:** o cliente local passou a usar `open-staged` e
`prepare-session`. Primeiro verifica a relação sequencial do setup e confirma
seus bytes exatos; depois recebe puzzles/prova, confere aberturas e Feldman,
e só retorna uma cápsula pronta para o ensaio financiar. O mesmo verificador
público permanece vivo para a recuperação. Isso retira o custo sequencial de
setup do intervalo posterior à divulgação, sem retirá-lo do tempo total.
Doze testes Go passaram em 48,503 s, incluindo ordem real por pipes e rejeição
de substituições/aberturas falsas. Onze testes Rust de prazos e três do cliente
passaram; `go vet` e Clippy de todos os targets passaram. A conta nova
`from_prepared_costs` conserva 99 candidatos e o relógio original. Não cobre
restart nem demonstra atraso adversarial ou preparação distribuída justa.

O ensaio financiado passou com essa preparação: duas ofertas, índices `[1,2]`,
primeira abertura rejeitada, devolução XMR e gasto dos dois outputs. Recuperação
com reconstrução **5,288 s**, total **138,127 s**; watchdog externo sem timeout.
Resultados `clsag-lab/XMR-RECOVERY-STAGED-198-*`. A preparação das duas ofertas
consumiu 110,117 s; a prova/aberturas da oferta aceita, 14,272 s. O perfil curto
continua sem margem adversarial demonstrada. Esse teste isolado não comprova
o prazo nem a atomicidade do protocolo bilateral completo.

**Sessão pública de recuperação:** `solve-session` verifica a oferta uma vez,
conserva os parâmetros/puzzles e atende somente ao próximo índice autorizado.
O Rust confere cada share, fecha a sessão ao encontrar uma válida e exige a
contagem exata de resoluções e término bem-sucedido. `from_session_costs`
contabiliza verificação única mais todos os solves/conferências e overhead,
sem presumir paralelismo ou reduzir o orçamento de 99 candidatos.

Um teste com prova real aceitou plaintext `q+1`. A sessão agora rejeita esse
valor não canônico e continua no próximo candidato, registrando o custo.
Nove testes Go passaram, incluindo esse contraexemplo e a continuação na
mesma sessão; três testes Rust do cliente cobrem shares falsas, índices
trocados, inteiros não canônicos, esgotamento e custo. Dez testes Rust de
prazos passaram, incluindo a conta de verificação única.

O primeiro ensaio financiado desse cliente expirou após duas ofertas rejeitadas
e aceitação da terceira, antes de concluir funding. Registro preservado em
`clsag-lab/XMR-RECOVERY-SESSION-198-TIMEOUT.json`; ele não mede a recuperação.
O guard Tokio não interrompe a preparação síncrona no instante de vencimento;
novos ensaios precisam também de um limite externo para o grupo de processos.

O ensaio seguinte, com os binários atualizados e watchdog externo, **passou**:
duas ofertas geradas, índices `[1,4]`, rejeição de `[1]`, uma verificação pública,
devolução XMR e gasto posterior. Sessão completa 15,382 s; recuperação com
reconstrução 18,760 s; total 187,035 s. A preparação das duas ofertas consumiu
156,980 s. O total continua acima de três minutos; não declarar a meta atingida.
Relatórios `XMR-RECOVERY-SESSION-198-REGTEST-RESULT.json` e
`XMR-RECOVERY-SESSION-198-WATCHDOG.json`, dentro de `clsag-lab/`. `go vet`,
Clippy de todos os targets, formatação e checagens de whitespace passaram.

Próximas obrigações concretas: medir a busca inteira, sem fingir que 99 solves
custam duas tentativas, e estabelecer uma margem após a divulgação. Na sessão
anterior, os puzzles chegavam antes de `verifySetupRelation`, que faz T
quadraturas; a separação descrita acima corrige essa ordem no cliente local.
Aumentar T sozinho ainda não demonstra uma janela útil após verificação da
oferta, funding e entrega das assinaturas. Falta uma configuração temporal
segura e demonstrada para a composição DOM↔XMR.

**Busca completa e altura DOM:** `AssumedXmrRecoveryWindow` agora deriva a
quantidade de candidatos do desafio exato, conserva a divulgação original e
soma verificação/solve de todos os candidatos, com overhead explicitamente
assumido. Calcula a altura DOM estritamente após a recuperação e as margens
de claims; rejeita janela inicial esgotada, premissas invertidas e overflow.
Os quatro testes anteriores de altura e quatro novos testes de composição
temporal passaram; Clippy de todos os targets passou. Isso é cálculo sob
premissas, não autorização de depósito nem prova de atraso.

A conta exata em `recovery-audit/cut_choose_budget.py` mostra que, com 198
puzzles, Q=2^64 e alvo 2^-128 para esse componente, a busca ordenada precisa
admitir os **99 candidatos**. Dois solves bem-sucedidos não justificam um prazo
que omita os restantes. Dez testes de orçamento passaram, incluindo enumeração
exaustiva de posições adulteradas até oito puzzles. Resultado em
`recovery-audit/SEARCH-BUDGET-RESULT.json`.

O ensaio financiado com primeira abertura inválida passou também com 198
puzzles: índices `[1,2]`, rejeição de `[1]`, devolução e gasto posterior;
24,522 s de recuperação completa e 125,325 s totais. A execução anterior
expirou após três ofertas rejeitadas, sem demonstrar recuperação; ambos os
registros estão preservados em `clsag-lab/RECOVERY-SEARCH-AUDIT.md`. A busca
serial então repetia a verificação pública por candidato. O próximo passo de
custo apontado nessa etapa foi verificar a oferta imutável uma vez, já atendido
pela sessão acima, e avaliar resolução com paralelismo limitado, ainda pendente.

**Retomada após compactação — busca de share válida:** o ensaio
`xmr-recovery-bad-first` passou com uma cápsula real aceita na preparação,
primeira abertura rejeitada por Feldman e segunda aceita. O cliente agora
tenta os índices atrasados autorizados e contabiliza todas as verificações
e solves. Devolução XMR incluída e ambos os outputs gastos depois; seis
puzzles de fixture, uma oferta gerada, 20,293 s de recuperação e 122,918 s
totais. Dois testes unitários adicionais verificam fallback, esgotamento,
índice trocado e soma de custos. Relatório e limites em
`clsag-lab/RECOVERY-SEARCH-AUDIT.md`. Ainda falta demonstrar `L_XMR` e
`E_XMR`; o cálculo conservador de altura DOM foi preservado e seus quatro
testes passaram novamente. A suíte Python ativa agora tem 20 testes
bilaterais aprovados; os cinco testes de composição histórica passaram
separadamente, fora da execução padrão.
Verificação final desta etapa: **72 testes Rust da biblioteca/integração e
dois testes do cliente de exemplo passaram**, assim como Clippy de todos os
targets, formatação dos arquivos alterados e checagens de whitespace. Os
tempos de compilação e espera por locks de Cargo não entram na medição do
ensaio financiado.

**Prazos de preparação e velocidades diferentes:** `model.py` agora aceita
instantes absolutos de funding/ofertas e distingue abertura adversarial mais
cedo de recuperação honesta mais tarde. Cinco testes adicionais passaram:
troca efetiva sob margens explícitas, perda quando o honesto resolve mais tarde,
janela esgotada pela preparação, rejeição de tempos inválidos e ausência de
gastos antes dos inputs/ofertas. Total **22 testes Python aprovados**.
`timing_audit.py` reproduz os casos e
`PREPARATION-TIMING-RESULT.json` registra a perda: B inicia refund XMR em 7,
A vence a claim XMR em 8 e o refund DOM em 9. A hipótese anterior de velocidades
iguais escondia esse caso. O modelo continua sem provar preparação justa,
criptografia, maturidade ou disponibilidade real; suas unidades são ticks.

`clsag-lab/src/time_bounds.rs` calcula uma restrição DOM condicional com base
nas regras nativas de timestamp: `s + (H-h) - tolerância_futura - relógio_adiantado`,
limitada inferiormente a zero. Não multiplica alturas pelo intervalo alvo.
Quatro testes novos usam os validadores temporais reais, incluindo fronteiras,
altura mínima estrita e overflow. `AssumedDomAnchor` não autentica a cadeia
nem prova uma margem XMR, e essa conta não autoriza financiar. Referência
completa, premissas e fontes locais em `TIMING-BOUND-AUDIT.md`.

**Variante posterior ao contraexemplo:** a reserva DOM agora pode receber uma
devolução conjunta assinada antes do financiamento, com kernel nativo
`HEIGHT_LOCKED`, sem criar nem divulgar uma cápsula da share DOM. A API
`PreparedDomClaim::new_height_locked_refund` exige forma/altura exatas; o
construtor plain continua restrito. As regras de consenso não foram alteradas.
Testes rejeitam baixar a altura ou converter a transação assinada em plain.

`dom_height_refund` passou em dois nós DOM próprios: mesma devolução assinada
recusada antes da altura 12, incluída na 13 e gasta na 14 após abandono; na
outra cadeia, claim incluída na 6/gasta na 7 e devolução posterior rejeitada
por input consumido. Os objetos com o material de assinatura original foram
descartados antes da execução. Resultado `clsag-lab/DOM-HEIGHT-REFUND-REGTEST-RESULT.json`,
30,618 s, sem compilação. Artefatos
`clsag-lab/target/dom-height-refund-797619-1790448444985664997/`.
Suíte completa: **68 testes e dois doctests aprovados**. A altura do regtest
não é uma conversão de tempo real; falta a janela XMR e a atomicidade conjunta.
Detalhes e limites: `clsag-lab/DOM-HEIGHT-REFUND.md`.
Integrações bilaterais dessa variante passaram: `height-xmr-first` em 34,681 s
e `height-dom-first` em 34,943 s, incluindo preparação, gastos posteriores e
rejeição da devolução DOM vencida. Claims incluídas nas duas cadeias em 2,250 s
e 2,171 s desde sua preparação. Relatórios `clsag-lab/HEIGHT-XMR-FIRST-REGTEST-RESULT.json`
e `clsag-lab/HEIGHT-DOM-FIRST-REGTEST-RESULT.json`. Artefatos
`clsag-lab/target/regtest-798891-1790448640522290854/` e
`clsag-lab/target/regtest-798894-1790448640535882032/`. Compilação excluída,
mineração acelerada; não exercitam recuperação XMR conjunta. Clippy de todos
os targets e formatação aprovados.

**Contraexemplo real à composição sem proteção de prazo:** o novo modo
`regtest_claim ... early-dom-refund ... 198` abriu a cápsula DOM antes do
financiamento, entregou as duas claims adaptadas válidas, devolveu DOM e só
então incluiu a claim XMR. O recebedor gastou tanto a devolução DOM quanto o
XMR recebido. A claim DOM da contraparte passou na validação criptográfica,
mas foi rejeitada pelo nó por input já consumido. Não usou a share original
do peer para a devolução nem os fatores RSA para a abertura pública.
Relatório `clsag-lab/EARLY-DOM-REFUND-REGTEST-RESULT.json`, total 114,373 s;
abertura sequencial 1,072 s. Artefatos
`clsag-lab/target/regtest-796560-1790447847686568602/`.
O perfil curto atual fica rejeitado como configuração de swap seguro.
A auditoria não implementa a devolução XMR concorrente da parte honesta e
não refuta construções com margens corretas. Limites, reprodução e consequências
em `clsag-lab/EARLY-RECOVERY-AUDIT.md`. Clippy de todos os targets passou.
As regressões cooperativas após essa alteração passaram nos dois sentidos:
XMR→DOM em 37,084 s e DOM→XMR em 37,035 s, com gastos posteriores; executadas
simultaneamente. Artefatos `clsag-lab/target/regtest-796680-1790447967499145605/`
e `clsag-lab/target/regtest-796698-1790447967705557421/`. O laboratório preserva
os casos cooperativos, mas eles não anulam o contraexemplo adversarial.

Recuperação individual XMR implementada em `xmr_recovery`: aceita somente
shares originais aditivas 2-de-2, vincula roster ordenado/reserva/participante/
plano/cápsula/janela e restaura uma `ThresholdKeys` individual. O offset da
saída é aplicado depois da recuperação. Três testes adicionais cobrem assinatura
após descartar o peer nas duas posições, substituições de contexto/abertura e
rejeição de chaves inválidas ou já ajustadas. Suíte completa: **67 testes e
dois doctests aprovados**. Clippy de todos os targets também passou.

Ensaio `regtest_claim ... xmr-recovery ... 198` aprovado no monerod próprio:
cápsula verificada antes do financiamento; produtor encerrado; chave original
do peer descartada; solver público sem segredos do emissor. A share recuperada
permitiu devolver todo o input selecionado menos a taxa, em dois outputs sob
controle do participante restante. Ambos foram gastos após dez blocos locais.
Não houve reconstrução da chave agregada. Relatório
`clsag-lab/XMR-RECOVERY-REGTEST-RESULT.json`: cápsula 66,837 s, preparação de
140 blocos 24,196 s, verificação/recuperação 19,277 s, solve isolado 1,125 s,
devolução até inclusão 0,318 s, total 113,313 s. Compilação excluída.
Artefatos `clsag-lab/target/regtest-795115-1790447276585102735/`.
Esse ensaio não executa DOM; setup RSA centralizado e falta de garantia de
atraso adversarial continuam explícitos. O cliente Go usado pelos dois
ensaios de recuperação está em `examples/support/recovery_bridge.rs`.
Após compartilhar esse cliente e o helper de assinatura, as regressões também
passaram: DOM→XMR em 32,250 s e XMR→DOM em 32,533 s, ambas com gastos posteriores;
devolução DOM com seis puzzles em 62,225 s. Esses três ensaios foram executados
simultaneamente e não são medições comparáveis de desempenho. Os seis puzzles
servem somente à regressão, sem pretensão de segurança criptográfica.
Artefatos respectivos em `clsag-lab/target/regtest-795839-1790447424030991210/`,
`clsag-lab/target/regtest-795840-1790447424030674464/` e
`clsag-lab/target/dom-recovery-795838-1790447423988187979/`.

Prioridade de segurança seguinte: o prazo começa quando os bytes públicos
permitem resolver o puzzle, antes do financiamento. O solve local de cerca de
um segundo não protege a espera de preparação/maturidade. Não iniciar um
temporizador depois do depósito como se ele criasse essa proteção. Resolver
essa janela e a preparação justa, além da disputa claim/refund entre as pernas,
é necessário antes de qualificar o mecanismo como swap seguro.
O contraexemplo acima transforma esse ponto de uma hipótese pendente em uma
falha reproduzida da composição sem proteção. Uma nova admissão temporal deve
considerar toda a preparação desde a divulgação; não basta reagir à devolução
DOM depois de já ter liberado uma claim XMR que o peer pode reter.

Atualização mais recente: a direção DOM→XMR também passou com as duas reservas
financiadas nos nós próprios. `regtest_claim ... dom-first` descarta o segredo
original depois de concluir DOM; a conclusão XMR usa o escalar extraído da
transação DOM consultada no bloco canônico. Inclui gastos posteriores nas duas
moedas e rejeição de gasto conflitante DOM. Resultado:
`clsag-lab/DOM-FIRST-REGTEST-RESULT.json`, total 25,854 s, preparação XMR
13,402 s, preparação DOM 8,565 s, preparação das claims até inclusão nas duas
cadeias 1,623 s. Artefatos em
`clsag-lab/target/regtest-793665-1790446545968622101/`. Compilação excluída;
blocos gerados sob demanda. Esse ensaio ainda não exerce recuperação, setup
distribuído ou atomicidade completa. O default continua sendo XMR→DOM.
A regressão XMR→DOM também passou, em 24,400 s; preparação XMR 10,672 s,
DOM 9,456 s e preparação das claims até inclusão nas duas cadeias 1,713 s.
Relatório `clsag-lab/XMR-FIRST-REGTEST-RESULT.json`, artefatos
`clsag-lab/target/regtest-793781-1790446584162362475/`.

Recuperação individual DOM: `dom_recovery` verifica a ligação entre a share
secp256k1 da reserva e o polinômio Ed25519 por prova entre curvas no domínio
comum de 252 bits. Reserva, papel do participante, plano, desafio, janela e
prova entram no binding. A abertura precisa reconstruir os dois pontos exatos.
Três testes adicionais rejeitam substituições; suíte Rust da etapa passou com
64 testes e dois doctests. Clippy de todos os targets passou também depois da
adição da direção inversa.

Ensaio financiado `dom_recovery_bridge` aprovado com 198 puzzles, threshold 100:
o emissor `open-only` termina; verificador público valida a cápsula; o ensaio
financia DOM e descarta share original/chaves preparadas; um novo processo
`solve-public` recebe somente oferta pública e índice. A share recuperada
permite incluir uma devolução e gastar a saída. Resultado em
`clsag-lab/DOM-RECOVERY-REGTEST-RESULT.json`: preparação/verificação 92,454 s,
financiamento 8,059 s, recuperação/devolução/gasto 19,381 s, total 119,895 s.
Artefatos `clsag-lab/target/dom-recovery-792015-1790446053200646872/`.
Três testes principais Go e `go vet` passaram. Esse ensaio é DOM isolado:
não demonstra a recuperação atômica do par nem atraso mínimo contra adversários;
setup RSA continua centralizado. Cópias JSON/Go não têm garantia de apagamento.

Os registros abaixo preservam as etapas e suas limitações históricas.

- Modelo Python: 17 testes aprovados; última suíte levou 1,369 s nesta máquina.
- Exploração principal: 103 estados para o par, em três coligações; 15.327
  estados para a rota, em sete coligações. Nenhum contraexemplo nesses casos
  com margens estritas e nas premissas limitadas do modelo.
- Controles negativos encontram perda do intermediário com prazo BTC curto
  e perda bilateral se o participante deixa de reclamar sua entrada ao iniciar
  o refund. Um prazo local não revoga uma assinatura divulgada.
- Laboratório Rust: 49 testes e um doctest de rejeição de reuso aprovados,
  incluindo propagação direta DOM↔XMR com transações nativas e a validação
  da claim DOM contra adulterações e contra outra oferta válida.
  Formatação, Clippy de todos os targets e `go vet` do bridge aprovados.
  Isso não é medição de GitHub Actions nem de swap.
- CLSAG completada verificada por `monero-clsag` upstream, nas 16 posições
  do anel; extração e rejeição de adulterações verificadas.
- Propagação direta do segredo XMR→DOM e DOM→XMR usa a prova entre curvas
  existente. O experimento anterior com BTC foi retirado da suíte de assinaturas
  em atendimento à correção de escopo do operador.
- Novo `native_dom`: transação de um input/um output/um kernel plain;
  estrutura, prova de faixa, balanço e consenso nativo verificados. Extração
  exige o corpo integral aprovado, a rede e o adaptor correspondente. O teste
  direto serializa/lê transações DOM e XMR nos dois sentidos. Os inputs DOM
  e os anéis XMR dos testes offline continuam sintéticos.
- Ensaio anterior `examples/regtest_claim.rs`: XMR incluído em monerod isolado,
  segredo extraído da transação consultada e usado para concluir a claim DOM.
  DOM validado pelo consenso, mas seu input ainda é uma fixture sem fundos.
  Sem BTC. Resultado em `clsag-lab/DIRECT-DOM-XMR-REGTEST-RESULT.json`: preparação
  de 140 blocos 26,919 s; construção 1,034 s; construção até inclusão XMR
  1,594 s; conclusão/verificação DOM 0,058 s; total 33,821 s. Inclui também o
  gasto posterior do XMR após dez blocos de maturidade locais; exclui compilação.
  Esse resultado não demonstra atomicidade, financiamento DOM ou latência mainnet.
- O ensaio atual também financia DOM em um nó regtest próprio, usando mineração
  e admissão normais. Confere o corpo exato no bloco canônico, kernel indexado,
  consumo do input, output maduro, reenvio idempotente e gasto posterior.
  Uma transação diferente e corretamente assinada contra a reserva consumida
  deve ser rejeitada por input ausente. O nó não inicia listeners nem peers.
  O perfil regtest usa PoW rápido e maturidade coinbase de um bloco; setup
  centralizado descartável e recuperação ausente continuam explícitos.
  `wallet_spend` não preenche o índice auxiliar usado por `resolve_admitted_tx`;
  por isso o financiamento é conferido diretamente no bloco e no índice de kernel.
  Resultado final em `clsag-lab/FUNDED-DOM-XMR-REGTEST-RESULT.json`: preparação
  XMR 14,867 s, preparação DOM 8,430 s, construção até inclusão nas duas cadeias
  2,000 s, total 28,371 s com os gastos posteriores. Compilação excluída.
  DOM financiado na altura 4, claim na 5 e gasto posterior na 6. Os 49 testes
  Rust e um doctest, Clippy de todos os targets e formatação passaram novamente.
  Artefatos locais: `clsag-lab/target/regtest-784982-1790443895572089314/`.
- Assinatura conjunta CLSAG adaptada com duas shares separadas, operações
  upstream e estados consumidos por rodada; nenhuma reconstrução da chave
  agregada. Testes de contribuições falsas, mensagens fora de contexto,
  pontos inválidos, key image divergente e respostas de outra rodada aprovados.
- Transação XMR nativa completa com um input, destinatário padrão e troco:
  CLSAG, Bulletproofs+, compromissos, valores, taxas e serialização verificados.
  Scanner upstream identifica os outputs esperados. Anéis e contêineres dos
  testes offline são sintéticos; não comprovam inclusão ou maturidade.
- Ensaio em `monerod` 0.18.4.0, offline/fakechain próprio, **aprovado**:
  claim conjunta incluída em bloco, extração da transação consultada no daemon,
  recebimento de 1 XMR de teste e gasto posterior incluído após minerar dez
  blocos de maturidade. Preparação de 140 blocos: 14,313 s; construção da claim:
  0,127 s; construção até inclusão local: 0,308 s; ensaio total: 15,701 s.
  O tempo exclui compilação e não mede finalidade da rede principal ou swap.
  Relatório: `clsag-lab/REGTEST-RESULT.json`; logs locais preservados em
  `clsag-lab/target/regtest-708373-1790401235275144527/`.
- `cargo clippy --offline --locked --release --all-targets ... -- -D warnings`
  aprovado naquela etapa do laboratório. Até ali nenhum arquivo rastreado
  anterior fora alterado; a integração da reserva abaixo exigiu uma correção
  mínima na dependência `dom-scriptless-bulletproof`.
- Auditoria de `primefactor-io/vtc` na revisão
  `b18a1c7153abcff407d6d8469de1f6278fabaa1e`: teste de exploração aprovado em
  38,960 s. Uma cápsula aceita pela verificação recupera um escalar que não
  corresponde ao ponto público comprometido. Resultado documentado em
  `recovery-audit/README.md`; essa implementação fica rejeitada como backend
  direto da recuperação.
- Novo módulo `recovery` no `clsag-lab`: compromissos Feldman das shares,
  verificação `share * G == commitment(index)`, reconstrução pelos índices
  reais abertos, checagem `recovered * G == committed_point` e bindings de
  plano/janela para a rota. Seus dez testes rejeitam share forjada, delayed
  share fora da janela, índices duplicados/fora do intervalo e pontos públicos
  inválidos.
  `cargo clippy --offline --locked --release --all-targets ... -- -D warnings`
  aprovado depois da alteração.

Esses tempos são de experimentos locais. Não demonstram uma operação completa
em dois minutos. Não foi publicado branch nem executado workflow remoto.

Integração adicional: `JointPlan::new_with_recovery` verifica o domínio da
sessão e a igualdade entre a chave recuperável e a chave pública do input XMR.
O transcript conjunto inclui o binding da janela validada. Testes completam e
extraem a assinatura nesse caminho e rejeitam outro input, sessão, janela ou
peer sem binding de recuperação. O caminho antigo de laboratório continua
disponível; o exemplo de daemon ainda não usa recuperação. Essa integração é
para recuperação da chave inteira do input, não para uma share individual.
Não comprova a existência, correção prévia ou atraso de uma cápsula temporizada.
O consumo da janela também revalida campos públicos alterados após a construção.

## Próximas obrigações técnicas

Assinatura conjunta DOM implementada em `clsag-lab/src/dom_joint.rs`: duas
shares, provas de posse vinculadas ao plano, dois nonces por peer, fatores
vinculados à rodada, verificação de cada parcial e agregação pelo desafio DOM
nativo. O exemplo financiado usa essa API e soma apenas os pontos das shares
do kernel. Não reconstrói seu escalar completo. A rodada DOM vincula também a
transação XMR contraparte. Naquele ensaio o helper ainda conhecia a abertura
inteira da reserva DOM. A etapa seguinte, descrita abaixo, já usa prova de
faixa compartilhada sem somar as aberturas. Falta ligar recuperação antes do
depósito e distribuir/autenticar o setup entre processos independentes.
Provas de posse não autenticam identidades. Nonces ainda não são persistidos.
Os seis testes adicionais e o doctest DOM passaram: total de 55 testes Rust e
dois doctests. Clippy de todos os targets e formatação aprovados depois da
integração. Ensaio com as duas claims conjuntas aprovado em 38,090 s,
incluindo preparação XMR 22,898 s, DOM 11,209 s e gastos posteriores. Construção
até inclusão nas duas cadeias: 1,574 s. Sem compilação e com mineração local
controlada. Relatório `clsag-lab/JOINT-DOM-XMR-REGTEST-RESULT.json`, artefatos
em `clsag-lab/target/regtest-786979-1790444489912515249/`. Atomicidade permanece
falsa no relatório; recuperação ausente e setup centralizado explícitos.

A biblioteca `dom-scriptless-bulletproof` foi integrada em `dom_reserve` para
provar a nova reserva compartilhada. A abertura total não é construída; os
participantes publicam pontos e provas de posse e executam a prova MPC com
nonces privados independentes. O helper financia a reserva por transação nativa
conjunta e depois gasta pelo segredo observado no XMR. As tentativas de assinar
a claim com cada contribuição isoladamente são rejeitadas. O processo ainda
hospeda ambos os participantes e distribui a seed comum localmente.

O ensaio `SHARED-RESERVE-DOM-XMR-REGTEST-RESULT.json` passou em 26,459 s:
preparação XMR 13,077 s; preparação DOM 9,408 s; construção até inclusão das
duas claims 1,788 s. DOM reserva na altura 5, claim na 6, gasto posterior na 7.
Inclui gastos posteriores, exclui compilação; blocos gerados sob demanda.
Artefatos em `clsag-lab/target/regtest-788032-1790445156730197549/`. Total atual
61 testes Rust e dois doctests aprovados. Ainda sem recuperação no ensaio,
atomicidade completa ou medição no GitHub/rede principal.
Clippy de todos os targets e formatação do laboratório aprovados. A suíte
própria de `dom-scriptless-bulletproof` passou nos 25 testes em 81,72 s,
incluindo conformance com o nó e mil provas diferenciais; compilação 1m12s
separada. Formatação da dependência também aprovada.

Correção necessária da dependência: o finalizador MPC chamava o verificador
com dados extras mesmo quando `extra_commit` era vazio. Outputs plain corretos
falhavam. Agora escolhe o verificador plain nesse caso; o caminho não vazio
mantém a obrigação dos mesmos dados. Consenso, nó e executor não foram
alterados. O teste positivo falhou antes e passou depois; o teste não vazio
verifica que retirar ou trocar esses dados continua invalidando a prova.
Inspeção dos nonces e limitações: `clsag-lab/RESERVE-MPC-AUDIT.md`.

Novo módulo Rust `recovery_challenge`: transcript com framing e binding do
plano, setup, puzzles ordenados e prova de faixa; seleção de metade dos índices
por Fisher–Yates e amostragem por rejeição. Quatro testes aprovados em 0,08 s:
reconstrução da janela selecionada, rejeição de índices/shares/plano divergentes,
determinismo e partição exaustiva nos tamanhos 2, 6, 132, 166, 198 e 512,
alteração de campos/limites de framing e rejeição de formas inválidas.
Os payloads desses testes unitários são sintéticos. O exemplo agora conecta
bytes reais do Go e deriva o desafio antes de solicitar aberturas. Ensaio com
198 puzzles aprovado em 80,396 s: 99 aberturas verificadas no produtor e
verificadas de novo por um processo público separado que recebe somente setup,
puzzles, prova, escalares abertos e nonces. A chave Ed25519 foi recuperada e
os controles negativos de prova, nonce e share foram rejeitados. Relatório:
`clsag-lab/RECOVERY-CHALLENGE-BRIDGE-RESULT.json`. O binding entrou no plano
conjunto na etapa descrita abaixo. Falta provar setup sem confiança: o produtor local ainda
conhece todos os segredos durante a geração, e o formato de rede não está
auditado. A derivação do desafio não verifica sozinha a
validade da cápsula.

Integração da cápsula à assinatura: `JointPlan::new_with_capsule` revalida
plano/janela e inclui `RecoveryChallenge.binding()` no transcript conjunto.
Quatro testes adicionais verificam conclusão/extração e rejeitam outra cápsula
com os mesmos índices, peers sem binding, mutações de plano/janela e tentativa
de contornar o vínculo falsificando os identificadores das mensagens.
O bridge público real com 198 puzzles passou em **68,453 s**, incluindo 99
aberturas verificadas, checagem pública de `h = g^(2^T) mod N`, recuperação da
chave e CLSAG conjunta (1,422 s) ligada à cápsula. Relatório:
`clsag-lab/RECOVERY-CAPSULE-JOINT-RESULT.json`. Chaves centralizadas descartáveis,
anel sintético, sem financiamento ou transação DOM/BTC; compilação excluída.
O Go agora rejeita campos incompletos, provas com número errado de rodadas,
elementos não invertíveis, respostas fora dos limites e parâmetros de atraso
inconsistentes. Dois testes principais, incluindo 22 casos de parser,
aprovados em 1,594 s. Isso não prova módulo RSA adequado/sem trapdoor nem atraso
mínimo. A prova upstream ainda usa concatenação de inteiros sem framing em seu
desafio interno; a segurança desse transcript permanece pendente de auditoria.

Auditoria adicional da recuperação: a tentativa de corrigir somente o solver
VTC por interpolação dos índices abertos falhou. A geração de shares upstream
depende de um prefixo fixo; as shares da cauda contêm informação redundante.
Verificar a chave após abrir não restaura uma share indispensável cifrada de
forma errada. O teste de auditoria passou a registrar também essa rejeição.
Um puzzle LHTLP isolado de 200.000 quadraturas abriu corretamente em 1,358 s
no primeiro ensaio local; não demonstra atraso mínimo adversarial nem swap.
Detalhes e limitações em `recovery-audit/README.md`.

Novo ensaio `recovery-audit/polynomial_puzzle_test.go`: polinômio de grau dois,
compromissos Feldman e seis puzzles LHTLP reais com 200.000 quadraturas.
Recuperação por índices fora do prefixo rejeitou um puzzle com share falsa e
recuperou o segredo com a próxima share: teste aprovado em 2,181 s, dos quais
1,649 s na recuperação. Usa secp256k1, setup local e subconjunto aberto fixo;
falta prova prévia da recuperabilidade e integração Ed25519/Rust. Esse resultado
substitui a estrutura de shares rejeitada somente no experimento, não cria um
backend autorizado para financiar reservas.

Integração Ed25519 posterior: `examples/recovery_puzzle_bridge.rs` passou
shares descartáveis criadas pelo módulo Rust a `recovery-audit/lhtlp_bridge.go`.
As aberturas LHTLP reais retornaram ao `RecoveryWindow`: share falsa rejeitada,
chave correta recuperada com índices 2, 5 e 3, binding preservado. Total local
2,460 s (setup 0,127 s, cifra 0,386 s, abertura 1,934 s), fora compilação.
Clippy de todos os targets aprovado. Ainda não é backend pré-verificável;
não há fundos, autenticação entre processos ou garantia de atraso adversarial.

Parâmetros pré-depósito: `recovery-audit/cut_choose_budget.py` calcula com
aritmética exata o limite condicional Q/binomial(n,n/2). Para <=2^-128 são
necessários 132, 166 ou 198 puzzles nos cenários Q=1, 2^32 ou 2^64. Cinco testes
aprovados, incluindo enumeração de todas as posições corrompidas até n=8.
A conta assume desafio uniforme e provas de setup/faixa válidas; não comprova
segurança do backend atual. Os tempos de seis shares não permitem alegar
desempenho nesses parâmetros. Fonte e premissas em `recovery-audit/README.md`.

1. Completar o setup autenticado de shares, provas de posse e key images.
   Medição adicional do bridge com 198 shares e threshold 100 aprovada em
   40,943 s: cifra 12,460 s, prova de faixa (160 rodadas) 9,899 s, verificação
   10,754 s e duas aberturas 1,955 s. Rejeitou prova adulterada e share falsa.
   Relatório: `clsag-lab/RECOVERY-BRIDGE-RESULT.json`. Não mede o pior caso de
   abrir todos os puzzles. O subconjunto aberto ainda é fixo, setup descartável
   centralizado; range proof upstream sem auditoria completa. Não é cápsula
   pré-verificável nem prova de 128 bits de segurança do sistema completo.
   O assinante conjunto já existe, mas seus testes assumem um roster acordado.
   Rótulos de sessão não são autenticação. Persistência de nonces, proteção
   contra rollback/fork e reinício ainda não estão implementadas.
2. A transação DOM financiada agora é completada pelo segredo extraído do
   monerod isolado e incluída no nó DOM próprio (`examples/regtest_claim.rs`).
   Ambas as direções agora têm inclusão nas duas cadeias locais; a direção
   inversa e seus resultados estão registrados na atualização acima.
   Falta ligar setup distribuído e recuperação a esse ensaio. O exemplo inicia seu
   próprio monerod offline, exige fakechain e gera suas próprias moedas.
   Não aceita RPC remoto ou carteira existente. As primeiras tentativas
   revelaram que `--no-sync` impede o core de ficar pronto mesmo com
   `--offline`; a opção foi removida. A seleção de coinbase deve verificar
   seu timelock por altura, e não descartá-la como output sem timelock.
   A submissão usa `do_not_relay=true` para inclusão na rede isolada; desabilita
   a heurística RPC de sanidade dos decoys, como o helper upstream, mantendo
   a validação de consenso do daemon. A preparação usa taxas próprias da
   emissão inicial fakechain, com limites explícitos de moedas de teste.
3. Conectar a recuperação a uma cápsula temporizada real. A camada Feldman já
   rejeita shares erradas depois que são abertas. Há agora puzzles reais ligados
   separadamente a devoluções financiadas DOM e XMR, mas ainda falta o backend
   que garanta o atraso necessário sem confiar em relógio local. Resolver parâmetros,
   trapdoor, custo adversarial, início do prazo, disponibilidade e restart.
4. Provar preparação justa e composição contra coligações, persistir material
   antes de divulgá-lo e testar falhas/reabertura. O modelo atual começa depois
   da preparação e assume limites de inclusão/finalidade.
5. Medir o mecanismo completo e seus componentes, com critérios separados para
   preparação, execução, confirmação e recuperação. Uma reserva nova Monero
   continua sujeita às regras de maturidade da rede.

A proposta DXP1 permanece experimental. A assinatura isolada não autoriza
financiar uma reserva e o objetivo ativo não está concluído.
