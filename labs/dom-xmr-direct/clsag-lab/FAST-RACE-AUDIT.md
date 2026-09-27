# Corrida de recuperação XMR antecipada

**Resultado:** o perfil temporal experimental de 10 milhões de quadraturas
perdeu a atomicidade no regtest controlado. A devolução XMR foi incluída e seus
dois outputs foram gastos de novo; o claim XMR honesto foi rejeitado por input
gasto; a assinatura completa que havia sido divulgada permitiu ao outro lado
incluir e gastar o claim DOM. O participante que divulgou o claim não recebeu
XMR nem recuperou DOM. Isso reproduz o risco de uma share XMR recuperável
antes do mínimo adversarial de 30 segundos assumido pelo perfil.

O cenário preservou a preparação da cápsula e a verificação pública completa
**antes do funding**. Depois de entregar ambos os adaptors, descartou o
segredo original do claim. O adversário obteve a outra share por abertura
pública Montgomery da mesma cápsula, manteve apenas sua share local e assinou
uma devolução XMR nativa. A abertura recebeu somente N, U e T públicos; o
verificador Go usou V público e conferiu o ponto Ed25519 original. Não houve
fatores RSA, share fornecida ao avaliador ou redução do número de passos.

Antes de divulgar o claim, o participante honesto consultou `monerod` e viu
transação ausente com key image livre. Seu relógio aceitou o claim XMR-first.
O `PreparationGate` exigiu a operação original em `ExchangePossible`; o
`InitialClaimJournal` gravou os bytes exatos, fez `fsync` e marcou
`ExposurePossible` **antes** de executar a chamada de envio. O escalonamento
adversarial do ensaio entregou esses bytes completos ao peer, incluiu primeiro
a devolução XMR no `monerod` e então enviou o claim honesto, que recebeu
rejeição por gasto duplo. A extração do witness foi feita a partir dos bytes
divulgados do claim perdedor; o DOM nativo aceitou o claim e o gasto posterior.

Essa ordem de entrega entre peer e daemon é **modelada** pela callback de envio.
Os nós são offline e o ensaio não mediu propagação P2P, interceptação de uma
chamada RPC privada ou relay automático de uma transação rejeitada. A aceitação,
inclusão, rejeição e gastos posteriores são verificações nativas. A conclusão
é um contraexemplo de atomicidade **sob esse escalonamento de divulgação**,
não uma medição da probabilidade da corrida numa rede pública.

| Marco | Valor observado |
| --- | ---: |
| Cápsula recebida (`d`) | Unix 1790526437 |
| Ambos os adaptors prontos | `d + 10 s` |
| Abertura pública completa | 7,369 s |
| Verificação honesta de relógio e input livre | `d + 17 s` |
| Claim divulgado; devolução XMR observada | `d + 18 s` |
| Mínimo adversarial assumido | `d + 30 s` |
| Resolução nativa XMR após divulgação | 0,080 s |
| Claim DOM / gasto posterior | alturas 7 / 8 |
| Ensaio inteiro, incluindo preparação e funding local | 83,273 s |

O prazo de 1 segundo para resolução XMR do fixture foi respeitado na medição.
O total de 83 segundos é de um regtest local; não mede confirmações nem
maturidade de fundos recém-criados na mainnet. O setup da cápsula foi
centralizado no laboratório e a fonte do relógio de primeira divulgação não
foi autenticada entre participantes independentes.

Os artefatos `FAST-RACE-AUDIT-1790526373283002881-{RESULT,PHASES,PROVENANCE,WATCHDOG,VERIFICATION}.json`
guardam o relatório, tempos, hashes das fontes/binários efetivamente
executados, PIDs e verificação do grupo de processos encerrado. O log completo
permanece local em `FAST-RACE-AUDIT-1790526373283002881.log`. O binário Go de
auditoria foi separado do helper normal. A versão executada rotulava esse
cenário como `negative_control` em um checkpoint intermediário, embora tenha
usado todos os guards honestos; esse rótulo e campos explicativos do relatório
foram corrigidos no fonte depois da medição, sem alterar a sequência de
transações medida.

O mínimo adversarial de 30 segundos já havia sido refutado por dois ensaios
independentes de abertura da mesma cápsula anterior em
[`FAST-OPEN-AUDIT.md`](../recovery-audit/FAST-OPEN-AUDIT.md). O presente teste
acrescenta a consequência financiada sob a ordem de divulgação especificada.
Não se pode substituir 30 por 8 nem aumentar T por regra de três: 8 segundos
é um teto observado, não um limite inferior adversarial. Sem novo fundamento
para recuperação, preparação e janelas entre redes, este perfil não pode
autorizar uma operação real. A missão de uma perna DOM↔XMR segura e rápida
continua aberta.
