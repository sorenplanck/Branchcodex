# Reconciliação após desfazer inclusão XMR

O modo `direct-pair-dom-first-xmr-detach` estende o envio nativo da contraparte
com uma alteração real do estado do monerod próprio. Usa somente a fakechain
recém-criada pelo ensaio, sem URL externa nem carteira existente.

Depois de DOM e XMR confirmados e observados por processos novos:

1. O supervisor chama `pop_blocks` para remover exatamente o bloco da claim
   XMR e confere que a altura diminuiu em um. O coordenador restaurado deve
   observar a transação no pool e recusar outro envio.
2. O supervisor chama `flush_txpool` somente para o hash dessa claim. Minera um
   bloco vazio que substitui o removido e confere a ausência da transação.
3. Um processo novo precisa verificar ausência exata e key image livre antes
   de retornar `RetryExactBytes`. Outro processo repete a verificação, mantém
   exposição durável e publica os mesmos bytes no RPC nativo.
4. O supervisor minera a reinclusão, agora em outro bloco e altura, e um
   processo novo deve acompanhar a inclusão sem reenviar.
5. O journal deve permanecer byte a byte idêntico. O restante do ensaio gasta
   os outputs da nova inclusão e testa a rejeição da devolução DOM conflitante.

A reinclusão precisa ocorrer antes do limite adversarial **original assumido**
da fixture. Tempo de retirada, observações, processos e reenvio não recebe uma
janela nova. Esse assert verifica a premissa do ensaio, não fundamenta o limite.

`pop_blocks` altera o armazenamento/pool nativos. É mais forte que fornecer
um enum de observação simulado, mas não exercita escolha de cadeia entre peers,
fork com maior trabalho, reorg ABA ou concorrência entre consultas e mineração.
A primeira claim DOM permanece canônica neste cenário. Uma primeira claim que
reapareça em outro bloco ainda colide com o binding imutável da obrigação no
worker atual; essa limitação deve ser corrigida e exercitada separadamente.

Reprodução após build separado:

```sh
target/release/examples/regtest_claim /home/leonardov/.local/bin/monerod direct-pair-dom-first-xmr-detach "$PWD/target/recovery-research/direct-dlog-bridge"
```

Resultados e medições serão registrados em `DIRECT-PAIR-DOM-FIRST-XMR-DETACH-*`.
Verificações de compilação/testes ficam em `XMR-DETACH-CHECKS.json`.

## Falha de capacidade de consultas preservada

A primeira execução terminou com exit 101 em 108,376 s, com erro de status
DOM insuficientemente detalhado. Artefatos `*-INITIAL-FAILURE*`. O diagnóstico
adicionado registra status e rota, sem token nem corpo da resposta, e distingue
HTTP 429 de outros erros. Uma segunda execução, `*-DIAGNOSTIC-*`, retirou o
bloco XMR, confirmou retorno ao pool e retirou a transação exata desse pool.
A inspeção seguinte autorizou somente `RetryExactBytes`, mas o novo emissor
recebeu **429 em `/chain/identity`** antes de tentar publicar. Retornou
`Reconcile`, `transaction_send_attempted=false`, `signature_created=false`.
Não houve conclusão do cenário nessa configuração.

O middleware existente de leitura do DOM usa `burst_size(100)` e
`per_second(1)`: pico de 100, reposição de uma consulta por segundo, embora o
comentário diga 100 req/sec. O novo cenário lança vários processos de falha e
retomada, cada um fazendo verificações completas; não pode pressupor capacidade
infinita do RPC. O mecanismo conservou o journal e não tratou throttling como
ausência nem como rejeição da transação.

Um ensaio separado `*-CAPACITY256-*` usa explicitamente
`DOM_RPC_RATELIMIT_READ=256` somente no processo que hospeda o nó isolado, sem
alterar o código/configuração padrão do daemon. Serve para exercitar a retirada
e reinclusão nativas sem o bloqueio anterior de capacidade. Essa capacidade
maior não prova funcionamento com os defaults, não resolve a limitação de
disponibilidade e não altera a janela temporal original. O valor e seus tempos
devem acompanhar qualquer citação desse resultado. A política de reconciliação
sob throttling e seu orçamento integral continuam pendentes.

## Resultado com capacidade explícita de 256 consultas

O ensaio `*-CAPACITY256-*` (PID 915028) terminou com exit 0 em **173,427 s**;
claims, incluindo a reinclusão XMR, em **86,800 s**. O trecho de retirada,
evicção do pool, consulta independente, reenvio e reinclusão levou **0,815 s**.
A claim saiu da altura 152 e reapareceu na 153, com outro hash de bloco e os
mesmos bytes transacionais. O journal permaneceu idêntico. Novas tentativas
nos estados pool/inclusão/RPC indisponível foram suprimidas; todos os outputs
foram gastos e a devolução DOM conflitante foi rejeitada na altura 214.

A reinclusão precedeu o limite adversarial **assumido** por nove segundos
inteiros. Isso não prova atraso mínimo adversarial nem pior caso de IO/restart.
O total ficou abaixo de três minutos nesta configuração, mas o cenário com
capacidade padrão falhou. As execuções anteriores acima de três minutos não
são substituídas por esta medição. Não há garantia de prazo de produção.

Os hashes dos fontes/binários foram conferidos; os PIDs registrados e o grupo
do ensaio terminaram. Clippy, onze testes relacionados e build separado passaram
antes das alterações de diagnóstico, que também receberam build separado.
O exame final de Clippy está registrado separadamente em
`target/xmr-detach-final-clippy.log`. Não houve alteração no consenso ou no
limitador do daemon para obter o resultado.
