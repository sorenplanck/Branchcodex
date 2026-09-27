# Leituras nativas, capacidade e espera por HTTP 429

O cenário DOM-first com retirada da contraparte XMR encontrou HTTP 429 com
o burst padrão 100 do RPC DOM. Essa falha permanece em
`DIRECT-PAIR-DOM-FIRST-XMR-DETACH-DIAGNOSTIC-*`. O sucesso anterior com burst
256 é uma configuração diferente, não evidência de funcionamento nos defaults.

## Evidência canônica sem leituras redundantes

O worker continua verificando transação, cadeia, altura e hash. Ao localizar
uma inclusão pelo kernel, o cabeçalho obtido já contém o hash do pai. Usa esse
hash apenas como sugestão de âncora para o scan nativo, em vez de buscar o pai
por altura em outro RPC. O endpoint `/chain/scan/scriptless/v1` verifica a
âncora, lê identidade/tip e devolve bloco/transações sob um único chain lock
(`NodeHandleImpl::scan_chain_full_v1_with_budget`).

O worker exige resposta canônica completa na altura solicitada, identidade/tip
iguais ao snapshot inicial, âncora e bloco esperados e corpo transacional exato.
A consulta posterior `/block/{height}` repetia uma afirmação já coberta por
esse snapshot; foi removida. Os checks finais dos tips DOM/XMR permanecem,
inclusive depois do fsync e antes de publicar. Não há cache de confirmação
entre processos. Uma âncora incorreta ou snapshot diferente continua rejeitado.

Isso reduz duas leituras públicas em cada observação que usa kernel+scan.
Não muda consenso, limitador do daemon ou regras de confirmação. Um snapshot
DOM individual é coerente; a operação com vários RPCs e duas cadeias **não**
vira uma transação distribuída atômica, defesa contra ABA ou prova contra nó
hostil. O ensaio ainda confia em nós próprios e mantém o minerador parado nas
observações do worker.

## Política de espera

Somente GET com HTTP 429 pode ser repetido automaticamente. Exige indicação
inteira e limitada em `Retry-After` ou no `x-ratelimit-after` nativo. Este último
é arredondado para baixo pelo middleware, portanto soma um segundo antes de
esperar. Metadados ausentes, duplicados, malformados ou acima do teto recusam
essa repetição. O maior valor é respeitado quando ambos os headers são válidos.

Cada processo compartilha **2.000 ms de espera solicitada** entre todas as
rotas, permitindo no máximo duas repetições. Uma rota nova não reinicia esse
orçamento. Há também o timeout externo de recuperação de dez segundos já
existente. A resposta da nova leitura é verificada normalmente, e os checks
de tip detectam mudanças visíveis ocorridas durante a espera.

POST nunca é repetido por esse transporte. Falha ou resposta ambígua depois
de iniciar publicação preserva exposição e requer reconciliação. Outro status,
como 503, não é tratado como ausência ou como HTTP 429. Persistência de limite
esgotado entre processos e escalonamento global de tentativas ainda não foram
implementados: o teto é por worker, não uma prova do custo de reinícios
arbitrários nem garantia de disponibilidade. Nenhuma espera renova os instantes
originais da operação ou cancela uma contraparte já devida.

## Medição e testes

Cada worker informa tentativas de leitura pública/autenticada e de publicação
DOM, repetições por throttling e espera solicitada/decorrida. A espera decorrida
também é contada se o timeout cancela a future durante o sleep. Escalonamento
pode fazer o tempo real ultrapassar o solicitado; não chamar o teto de espera
solicitada de limite de latência garantido. Workers com exits 75/77/76 registram
métricas no stderr antes de encerrar, sem token ou corpo privado. Os contadores
não incluem supervisor nem RPC XMR.

`RPC-READ-RECOVERY-CHECKS.json` registra 38 testes relacionados aprovados e
Clippy all-targets `-D warnings`. Os seis novos testes cobrem snapshot adulterado,
headers de espera, repetição real de GET, orçamento compartilhado entre rotas,
cancelamento no sleep e recusa de repetir POST/503/espera excessiva. Usam servidor
HTTP loopback descartável para conferir requisições reais do cliente; não são
substitutos dos ensaios nativos ou prova de segurança temporal.

As regressões nativas usam explicitamente `DOM_RPC_RATELIMIT_READ=100`:
`direct-pair-dom-first-xmr-detach` e `direct-pair-xmr-first-reinclude`. Resultados,
falhas, proveniência e métricas ficam em `*-RPC-READ-RECOVERY-*`.

## Resultados nativos

Ambos os ensaios terminaram com exit 0 e burst padrão 100:

| Cenário | Total | Claims incluídas | Trecho de recuperação | Leituras DOM públicas/autenticadas |
| --- | ---: | ---: | ---: | ---: |
| DOM-first, contraparte XMR retirada/reincluída | 189,201 s | 103,184 s | 0,946 s | 82 / 31 |
| XMR-first, primeira claim retirada/reincluída | 179,736 s | 95,228 s | 1,340 s | 62 / 16 |

O primeiro cenário que antes encontrava 429 passou sem aumentar o limitador.
Nenhum worker recebeu 429 nessas duas execuções; a política de espera foi
exercitada nos testes HTTP locais, não por uma falha injetada nesses nós.
Os contadores incluem tentativa de leitura em RPC posteriormente desligado;
não equivalem a requisições atendidas pelo servidor. A publicação DOM da
contraparte no segundo cenário teve uma tentativa; o primeiro publica XMR,
que não entra nesses contadores DOM.

Os journals, identidades de operação e prazos foram preservados, gastos de
todos os outputs passaram e as devoluções DOM conflitantes foram rejeitadas
nas alturas 213 / 212. As folgas observadas até o limite adversarial ASSUMIDO
foram seis / sete segundos inteiros. Checksums de fontes/binários foram
conferidos; processos e grupos próprios encerrados. Verificação consolidada
em `RPC-READ-RECOVERY-VERIFICATION.json`.

O total DOM-first excedeu 180 s. O XMR-first ficou abaixo por menos de um
segundo; não há margem confiável para anunciar a meta cumprida. Preparação e
espera pela devolução estão incluídas, compilação separada. Resultados anteriores
mais rápidos ou mais lentos permanecem válidos; esta etapa resolve a carga de
consultas observada nesse cenário, não garante disponibilidade ou latência sob
concorrência arbitrária. Integração ao daemon e fundamentação criptográfica e
temporal do mecanismo continuam abertas.
