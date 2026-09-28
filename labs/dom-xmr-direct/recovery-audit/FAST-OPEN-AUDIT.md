# O mínimo adversarial de 30 segundos foi refutado

**O perfil temporal atual de 10 milhões de quadraturas não sustenta a premissa
de que um adversário só recupera a share XMR após 30 segundos.** A mesma cápsula
foi aberta com parâmetros públicos em **7,475 s e 7,492 s**, incluindo extração
do plaintext e conferência independente da chave pública Ed25519. Não foram
usados fatores RSA, segredo do produtor, nova cápsula ou redução do trabalho.

Isso impede tratar o perfil atual como base segura de funding/publicação.
Os ensaios anteriores continuam demonstrando assinaturas, consenso e retomadas
nos cenários executados. Não demonstram atomicidade contra esse avaliador.

## Método

Ao preparar retomada no meio do solve, a leitura do `SolvePuzzle` da dependência
fixada `lhtlp@a7a6b10bacf3` mostrou uma exponenciação genérica e um contador
big.Int novo em cada quadratura. Um mínimo adversarial não pode ser inferido
da velocidade dessa implementação específica.

`direct_fast_open_audit.go` usa math/big com temporários reutilizados e exatamente
T multiplicações/quadraturas módulo N. O modo separado `direct-restore-fast-audit`
reutiliza apenas a aceitação local do setup, como o worker já existente, e
reverifica a prova pública inteira ANTES da abertura. Não recebe configuração
de avaliador pela mensagem do peer. O backend normal conserva `SolvePuzzle`;
o helper nativo anterior não foi substituído.

`direct_montgomery_audit.c` é um avaliador independente: recebe somente N, U e
T, converte U para domínio Montgomery, faz exatamente T quadraturas usando
OpenSSL e converte de volta. Não recebe V, share, autoridade local ou fatores.
O runner usa o V público para extrair o representante de plaintext (o perfil
verificado exige Y=2); confere divisibilidade exata, normaliza a representação
e compara scalar*G com o ponto original usando libsodium. O resultado secreto
e o elemento atrasado não são escritos nos artefatos de medição.

Os custos medidos abaixo incluem execução do processo C, extração e comparação
do ponto; o laço sozinho foi ainda mais curto. Não há um atalho matemático ao
número de passos. Montgomery é apenas outra implementação da aritmética modular.

## Resultados na mesma cápsula

Cápsula do cenário encerrado PID1580411: o binding exato é registrado nos
JSONs, não inferido de uma oferta nova. Todos os outputs desse cenário já
estavam gastos. O relógio
original foi preservado para conferir o comprovante local; não foi renovado
nem usado para autorizar uma transação. Nenhum nó/funding foi chamado.

| Avaliador | Abertura | Processo + verificações adicionais |
| --- | ---: | ---: |
| Go reutilizando temporários, rodada1 | 29,284 s | 36,769 s com verificação de prova |
| Go upstream, referência | 32,167 s | 39,705 s com verificação de prova |
| Go reutilizando temporários, rodada2 | 32,852 s | 40,388 s com verificação de prova |
| OpenSSL Montgomery, rodada1 | 7,375 s no laço | 7,475 s com extração e ponto |
| OpenSSL Montgomery, rodada2 | 7,390 s no laço | 7,492 s com extração e ponto |

Todos fizeram 10.000.000 quadraturas. A igualdade de escalar entre os três
processos Go foi conferida sem publicar o escalar. OpenSSL 3.0.13 e libsodium
locais, sem hardware especial. Pressão de CPU/IO/memória registrada por rodada.
A verificação da prova não protege o mínimo adversarial: quem quer abrir uma
cápsula honesta não precisa esperar por essa verificação antes de calcular.
A variação das duas rodadas Go também impede apresentar um benchmark como SLA.

## Verificação

26 testes Go passaram, incluindo todos os 24 anteriores e dois novos:
avaliação diferencial com representantes 1, -1, q-1, q+1 e rejeição de política
inválida. Vet/build passaram; `FAST-OPEN-AUDIT-CHECKS.json`. O callback de
auditoria só é selecionado localmente depois da verificação existente.

C compilado com `-O3 -Wall -Wextra -Werror -lcrypto`. Resultados para 1, 2, 17 e
200.000 passos coincidiram com exponenciação modular independente em Python.
Seis entradas inválidas foram recusadas. As duas rodadas de 10 milhões
terminaram com o ponto Ed25519 original, conferido por outra biblioteca.
`FAST-OPEN-AUDIT-RESULT.json` e `MONTGOMERY-OPEN-AUDIT-RESULT.json` conservam
tempos, versões, hashes, PIDs e escopo, sem segredos.

O teste Rust em `tests/recovery_time_bounds.rs` mostra a consequência na
aritmética do guard: o perfil antigo admite início em d+10, apesar de o
avaliador observado poder concluir antes de d+8; também admite offers-ready
em d+28. O mesmo prefixo é recusado ao modelar essa possibilidade de recuperação
antecipada. É um contraexemplo da premissa/janela, não um roubo financiado
reproduzido **neste primeiro ensaio**; assinatura/envio adversarial e corrida
nativa foram medidos posteriormente no
[`FAST-RACE-AUDIT.md`](../clsag-lab/FAST-RACE-AUDIT.md), sob escalonamento de
divulgação explícito. A altura conservadora do refund DOM não corrige esse mínimo XMR.
Passaram os 11 testes Rust desse módulo, incluindo o contraexemplo. Hashes,
comandos e PIDs encerrados foram conferidos em `FAST-OPEN-AUDIT-VERIFICATION.json`.

## Consequência para a missão

Não substituir 30 por 8: oito é um teto observado de conclusão deste avaliador,
não um novo mínimo adversarial. Não aumentar T por regra de três e declarar
segurança. Falta fundamentar a diferença entre capacidade adversarial e custo
honesto integral, além do instante de primeira divulgação, preparação entre
participantes, rede e reorgs. É preciso revisar/calibrar ou substituir a
recuperação temporizada antes de adotar qualquer perfil de operação.

A retomada durante o solve não foi integrada: primeiro foi necessário expor
esta falha de premissa. Persistência/assinaturas existentes são reutilizáveis.
A missão de um mecanismo novo, seguro e rápido DOM↔XMR continua incompleta;
voltar a otimizar o grafo antigo ou inserir BTC não cumpre essa missão.
