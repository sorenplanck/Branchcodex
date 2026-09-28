# Envio nativo pelo coordenador restaurado

Os modos `direct-pair-xmr-first-native-send` e
`direct-pair-dom-first-native-send` fazem o worker restaurado publicar a
contraparte diretamente nos RPCs nativos: `/tx/submit` do DOM e
`send_raw_transaction` do monerod próprio. O supervisor não recebe os bytes
para encaminhar essa admissão. Ele ainda hospeda o DomNode, mantém o monerod
externo próprio e controla a mineração do ensaio. Isso não é integração ao
`dom-interopd` nem restart completo da preparação/funding/solver.

## Decisão de envio

O worker recebe apenas diretório, operação e ação. Restaura checkpoint,
manifesto v2, primeiro envio e exposição original; verifica inclusão da
primeira perna e abre o journal da contraparte. Confere novamente o corpo e o
witness contra os envelopes. O payload publicado é exclusivamente o que foi
persistido nessa obrigação, sem nova assinatura, destino, preço ou nonce.

Para autorizar tentativa, exige ausência da transação exata e input livre:

- DOM: índice de transação sem entrada, kernel sem inclusão e UTXO nativo
  correspondente ao input, maduro, não coinbase e situado até o tip observado.
  Repete a consulta de transação para detectar aparecimento visível no pool.
- XMR: `missed_tx` exatamente correspondente ao hash esperado, resposta sem
  transações conflitantes com esse resultado, status OK e key image com
  `spent_status=[0]`. Estado gasto ou pendente não autoriza tentativa. Resposta
  incompleta ou marcada como não confiável não autoriza tentativa.

Essas consultas são feitas nos nós isolados próprios, com o minerador do
supervisor parado nessa fase e sem outro produtor no ensaio. Checks de tip
detectam mudanças visíveis; **não** constituem snapshot atômico entre RPCs,
defesa contra reorg ABA, nó hostil ou prova de input livre sob escritores
concorrentes. A admissão nativa continua sendo o árbitro de conflitos reais.
Esse adaptador de laboratório não deve ser promovido a evidência autenticada
de uma rede pública sem resolver essas limitações.

Antes do POST, o journal sincroniza exposição possível. Depois do fsync, o
worker consulta novamente transação/input e tips; falha ou mudança não apaga
exposição e não usa a observação anterior. Pool e inclusão apenas acompanham;
estado desconhecido exige reconciliação. A expiração do gate de primeira
liberação não é reaplicada à contraparte já devida.

O sender distingue início de tentativa e resposta de admissão recebida. Se
ocorre erro/timeout após iniciar o POST, `transaction_sent` é desconhecido,
não falso. Nada interpreta falta de resposta como rejeição definitiva ou
autorização para gerar outra transação.

## Quedas e retomadas

O ensaio conserva a queda antes da criação da obrigação (exit 75) e seu
restauro, descritos em `OBLIGATION-RECONSTRUCTION.md`, e acrescenta:

1. Um emissor restaura e valida a operação, sincroniza exposição e encerra com
   **77 antes de chamar o RPC de publicação**. A tentativa pode ter sido exposta
   segundo o journal, mesmo sem ter sido transmitida neste ponto do teste.
2. Outro processo consulta as cadeias por conta própria, verifica ausência e
   input livre e retorna `RetryExactBytes`, sem enviar nem limpar exposição.
3. Um emissor novo repete as verificações e envia os mesmos bytes diretamente
   ao nó. Recebe admissão nativa com sucesso e encerra com **76 antes de
   comunicar o resultado ao supervisor ou guardar um receipt de admissão**.
4. Novos processos observam pool e bloco. O supervisor também solicita `send`
   novamente nos estados pool, incluído e RPC indisponível. Nessas três
   situações, o worker deve decidir por não enviar e preservar o journal.

O caso 76 é perda de estado do processo **após receber a resposta nativa**,
não uma resposta de RPC que o nó deixou de enviar. O teste antigo de resposta
omitida pela ponte continua disponível nos modos `*-ack-loss`, sem ser
renomeado como falha do monerod. A comparação do journal depois de 77/76
exige bytes idênticos: só o primeiro evento de exposição deve existir.

O helper DOM mantém sua checagem diagnóstica de replay somente **depois da
confirmação**, para verificar a idempotência nativa. Isso não é a admissão
inicial da contraparte nem um reenvio enquanto pendente. O campo de evidência
`counterpart_host_forwards_payload=false` descreve a admissão inicial neste
caminho; os nós e demais verificações do ensaio ainda pertencem ao supervisor.

## Verificação e limites

Os dois ensaios nativos terminaram com exit 0 em 26/09/2026:

| Ordem | Total do ensaio | Claims incluídas | Queda/reconstrução/reuso | Entrega nativa com quedas |
| --- | ---: | ---: | ---: | ---: |
| XMR primeiro | 183,011 s | 93,891 s | 0,689 s | 0,604 s |
| DOM primeiro | 200,772 s | 111,636 s | 1,184 s | 1,706 s |

Ambos excederam 180 segundos, e portanto também a preferência do operador
por aproximadamente dois minutos. O total inclui preparação e a espera
minerada até a altura 215 para testar a devolução conflitante. Compilação foi
separada. O tempo até as claims não substitui o total nem prova um prazo de
produção. Os watchdogs mediram 183,125 s e 200,827 s.

Nos dois sentidos, os exits 75/77/76, a reconstrução sem arquivos posteriores
à inclusão, a consulta independente de ausência/input livre e a supressão de
envio em pool/bloco/RPC indisponível passaram. Todos os outputs foram gastos
posteriormente e a devolução DOM conflitante foi rejeitada. BTC não participou;
`full_coordinator_restart_exercised=false`. Hashes dos fontes/binários foram
conferidos contra os dois arquivos de proveniência. Os PIDs registrados dos
ensaios e workers já terminaram. Evidências completas nos artefatos citados
abaixo; esses resultados demonstram o caminho funcional isolado, não segurança
bilateral ou prontidão de produção.

`NATIVE-SENDER-CHECKS.json` registra **57 testes aprovados**, Clippy all-targets
com `-D warnings` e build separado. Os três novos testes rejeitam UTXO de
outro input/altura, resposta de ausência ambígua e key image gasta/pendente,
incluindo metadados malformados. Os ensaios completos ficam nos artefatos
`DIRECT-PAIR-{XMR,DOM}-FIRST-NATIVE-SEND-*`.

Todos os probes, reinícios, consultas e fsync consomem o prazo original.
Nenhum tempo regtest é garantia de latência mainnet ou prova dos custos de um
segundo por etapa da fixture. Permanecem a fundamentação temporal e
criptográfica, reorgs reais, concorrência adversarial, preparação independente
autenticada, persistência anterior ao funding/disclosure e integração ao daemon.
