# Reconstrução após primeiro pagamento, antes do journal da contraparte

Esta etapa do mecanismo novo DOM↔XMR elimina a dependência de `observed.tx` e
`counterpart.tx` escritos depois da primeira inclusão. O material necessário
para descobrir a primeira claim fica no disco **antes de enviá-la**. Um novo
worker consulta os nós nativos e cria a obrigação a partir da inclusão que ele
mesmo verificou. O supervisor e os nós permanecem vivos no ensaio; não é o
reinício completo do daemon.

## Persistência anterior ao envio

`journaled_initial_send` grava os bytes exatos em `initial-claim.tx`, com
create_new, modo 0600 e fsync de arquivo/diretório. Só depois cria/reabre o
journal de primeira liberação e permite a chamada de rede. O digest aprovado
no journal fixa esses bytes. O arquivo contém uma transação assinada que,
junto com os envelopes, permite extração: é material privado dos participantes.
Não vai para os relatórios públicos.

O manifesto passou a v2 para guardar também o número original de candidatos.
O parser não converte manifestos v1 antigos nem inventa esse campo. Os
artefatos históricos continuam preservados, mas não autorizam automaticamente
o novo caminho de reconstrução. A política reconstituída conserva operação,
cápsula, candidatos, três instantes, ordem, custos e digest da primeira claim.
A reabertura exige que esses valores coincidam com o journal original e que
o evento durável indique exposição possível. Não fabrica um evento ausente.

Restaurar a política não abre novamente o limite da primeira liberação e não
usa o horário atual como nova divulgação. Essa política serve para verificar
o histórico; o prazo de iniciação não cancela a contraparte já devida.

## Reconstrução independente

O worker recebe somente diretório, operação esperada e ação. Ele:

1. Carrega checkpoint, manifesto v2, envelopes, bytes iniciais e journal de
   exposição. Registro ausente, truncado, inválido ou de outra operação não
   é tratado como autorização para começar de novo.
2. Valida a primeira claim contra o envelope aprovado e extrai seu witness.
   Consulta a primeira cadeia pelo RPC nativo e exige inclusão canônica dos
   bytes exatos. Uma claim ainda no pool não cria a obrigação. Identidades e
   tips dos dois nós são consultados, conforme `SETTLEMENT-RESUME.md`.
3. Só após essa verificação completa o adaptor fixado e cria o journal com os
   bytes exatos da contraparte e o vínculo ao manifesto/primeiro pagamento.
   Não há nova rodada de assinatura, nonce, destino ou prazo.
4. Se o journal já existe, reabre-o estritamente e verifica corpo, assinatura
   e witness contra os envelopes e a primeira claim. Não completa novamente
   o adaptor, não substitui arquivos parciais e não restaura privacidade.
5. Se o journal existente indica possível exposição, reconstruir retorna
   `Reconcile`, nunca `CounterpartPrepared`. Consultas novas de pool/bloco
   seguem separadamente; o worker de reconstrução não despacha transações.

Criar a obrigação ainda depende do armazenamento local confiável. Não há
defesa contra remoção hostil do journal ou rollback de backup completo.
Concorrência usa os locks e create_new do journal; uma falha de gravação que
deixe registro parcial exige reconciliação, não reparo automático. Uma falha
após criar o registro pode deixar a obrigação durável: o relatório não afirma
que nenhuma assinatura foi completada quando esse resultado é desconhecido.

## Quedas e controles exercitados

Os modos `direct-pair-{xmr,dom}-first-ack-loss` agora seguem esta sequência:

- Primeiro pagamento no pool: worker novo recusa criar o journal, com
  `first payment not canonical`.
- Primeiro pagamento incluído: outro worker verifica a cadeia e encerra
  realmente com exit 75, antes de criar qualquer registro posterior à inclusão.
- Worker novo reconstrói a contraparte e sincroniza seu journal. Os arquivos
  `observed.tx` e `counterpart.tx` permanecem ausentes.
- Mais uma retomada reutiliza exatamente o journal, sem completar outra
  assinatura. O teste compara seus bytes antes/depois.
- O emissor abre essa obrigação já preparada, persiste exposição e entrega a
  transação ao nó pela ponte local. A ponte omite a resposta depois da admissão;
  emissor encerra com exit 74.
- Retomadas independentes consultam pool/bloco e RPC indisponível. Uma nova
  reconstrução após exposição mantém `Reconcile` e o journal byte a byte.
- As verificações de gastos posteriores, maturidade, altura conservadora e
  rejeição da devolução conflitante continuam no ensaio.

O pai valida o resultado para o teste e continua fazendo a admissão por sua
ponte; esse envio ainda não foi movido para um coordenador autônomo completo.
Não declarar restart de preparação/funding/solver ou prova de atomicidade.
Reorgs reais, autenticação entre participantes, limites de tempo fundamentados
e integração ao `dom-interopd` continuam pendentes.

`OBLIGATION-RECONSTRUCTION-CHECKS.json` registra 54 testes Rust aprovados,
Clippy all-targets com `-D warnings` e build separado. Os dois testes novos
verificam a reconstrução da política original, rejeição de outros bytes,
alteração de prazo/candidatos e premissas temporais inválidas. Os resultados
nativos desta etapa ficam em `DIRECT-PAIR-*-OBLIGATION-RECONSTRUCTION-*`.

XMR-first passou em **167,841 s** totais, claims em **80,239 s**, sequência de
queda/reconstrução/reuso em **0,550 s**. O controle com primeira claim no pool
recusou criar a obrigação. Depois da inclusão, um processo morreu com exit 75,
outro criou a obrigação e o seguinte a reabriu sem completar nova assinatura.
No envio sem resposta, o emissor morreu com exit 74; novas consultas observaram
pool, bloco e endpoint indisponível. A reconstrução após exposição conservou
`Reconcile` sem modificar o journal. Outputs gastos e refund conflitante
rejeitado na altura 215. Os arquivos pós-inclusão permaneceram ausentes.
Evidência `DIRECT-PAIR-XMR-FIRST-OBLIGATION-RECONSTRUCTION-*`.

DOM-first passou em **205,188 s** totais, claims em **116,390 s** e sequência
de queda/reconstrução/reuso em **0,983 s**. A primeira claim no pool não criou
journal; o crash 75 precedeu a criação; o journal existente foi reutilizado e
a exposição persistiu após o envio sem resposta. Outputs gastos, refund DOM
conflitante rejeitado em 214. Os arquivos pós-inclusão continuaram ausentes.
Evidência `DIRECT-PAIR-DOM-FIRST-OBLIGATION-RECONSTRUCTION-*`.

O tempo integral DOM-first **excedeu três minutos**. A preparação individual
levou 44,455 s nessa rodada e 16,721 s na inversa; a comparação não demonstra
causa do aumento nem um limite de pior caso. Não foram repetidas execuções
somente para selecionar um tempo menor. Fontes/binários conferidos e processos
próprios encerrados nos dois ensaios.

`OBLIGATION-RECONSTRUCTION-TIMING.json` preserva instantes originais e custos.
A inclusão XMR ficou 13 s / 5 s antes do limite adversarial **assumido**. No
DOM-first, passaram cinco segundos inteiros entre o timestamp do evento de
possível exposição e a observação da inclusão XMR. Esse timestamp antecede o
fsync e a checagem final do gate: não mede precisamente o instante de envio.
O valor zero do XMR-first reflete resolução de um segundo, não latência zero.
Nenhum desses números prova os custos de um segundo por etapa usados na
fixture. IO, queda/reabertura e todos os probes consomem a mesma janela original;
precisam constar do orçamento completo, sem selecionar só a tentativa rápida.

A obrigação já é criada no worker novo, mas a publicação continua na ponte
do supervisor. Transferir esse envio/reconciliação ao coordenador restaurado
é o próximo passo de integração; não usar o fim do prazo inicial para cancelar
uma contraparte devida. As demais lacunas de segurança e restart seguem abertas.
