# Verificação limitada a duas rodadas concorrentes

A cápsula direta experimental conserva suas 256 rodadas Sigma, o transcript
Fiat-Shamir, limites inteiros, verificações de pontos e parâmetros. A mudança
agenda somente as equações independentes de verificação em pares ordenados.
Não modifica geração de prova, formato criptográfico, setup sequencial,
abertura ou dificuldade; não fornece uma prova de segurança da construção.

Cada par termina antes de começar o seguinte. O primeiro erro em ordem de
índice permanece determinístico, todos os workers terminam antes do retorno,
e uma prova inválida custa no máximo uma equação adicional em relação à
interrupção sequencial. O número de workers é fixo em dois, independente da
entrada recebida. O modo interno com um worker é somente controle de teste.

Os parâmetros são decodificados privadamente. A rotina upstream fixada
`GeneratePuzzleWithCustomNonce` usa receivers `big.Int` novos; os operandos
compartilhados são somente lidos. Os temporários Edwards são próprios de cada
rodada. O chamador não deve alterar statement/proof durante a verificação.
Não se alega proteção contra mutação concorrente pelo próprio chamador.

O teste real compara aceitação e cápsula resultante entre um e dois workers,
rejeição das mutações anteriores e falhas nas equações finais. Alterar somente
respostas preserva o desafio, permitindo verificar que a última equação não
foi ignorada. Falhas simultâneas em um par devem identificar o menor índice.
Passaram 21 testes Go, incluindo os controles do backend anterior, em
136,109 s (`DIRECT-PARALLEL-CHECKS.json`). Na mesma prova real de perfil curto,
a verificação com dois workers levou 7,422 s e o controle sequencial 14,646 s.
Geração 14,646 s e abertura 0,665 s. A medição fez primeiro a verificação
concorrente e depois a sequencial; é uma observação local, não limite temporal.
O total positivo de 38,091 s inclui explicitamente as duas verificações.

O teste real, incluindo as 19 mutações anteriores e os dois casos de falha
em equações específicas, também passou com `go test -race` em 80,192 s,
sem alerta do detector (`DIRECT-PARALLEL-RACE.json`). Isso verifica esta
execução concorrente, sem provar ausência de toda possível corrida.

Motivação: o primeiro ensaio da republicação inicial encerrou antes das claims
por expiração da janela após financiar as reservas. Ver
`../clsag-lab/INITIAL-NATIVE-REPLAY.md`. Essa falha permanece preservada e os
prazos não foram ampliados para acomodar o custo da preparação.

`go vet` e build passaram (`DIRECT-PARALLEL-BUILD.json`). O novo helper foi
usado no ensaio nativo com dificuldade longa de 10.000.000 quadraturas,
GOMAXPROCS=2 e o mesmo Rust da tentativa falha. A prova foi verificada em
7,499 s, ambas as claims incluídas em 78,972 s, e o ensaio completo passou
em 172,394 s, incluindo retirada/republicação da primeira XMR, reinicializações,
gastos posteriores e rejeição de devolução conflitante. A abertura temporizada
não foi executada nesse cenário. Evidência e limitações completas em
`../clsag-lab/INITIAL-NATIVE-REPLAY.md`. A variação de setup/funding impede
atribuir toda a diferença entre ensaios ao paralelismo; não há SLA provado.
