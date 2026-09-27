# Republicação inicial pelo processo restaurado

O modo `direct-pair-xmr-first-native-replay` retira do supervisor a republicação
da primeira claim após retirada do bloco XMR. O worker recebe apenas diretório,
operação e ação, restaura os registros privados e consulta os dois nós por conta
própria. O supervisor ainda prepara/financia a operação, faz o primeiro envio,
hospeda os nós e minera; não é restart completo nem integração ao dom-interopd.

## Evidência e permissão

`ExposurePossible` pode ter sido gravado antes de qualquer chamada de rede.
Por isso, sozinho não autoriza uma republicação. O worker exige também o
`counterpart-delivery.wal` original, criado pelo coordenador somente depois
de verificar inclusão canônica da primeira claim. Reabre com manifesto, digest
dos bytes iniciais e cadeia alvo esperados; valida assinatura/corpo/witness
da contraparte contra os envelopes aprovados. Não cria esse histórico quando
está ausente e não reconstrói uma obrigação para justificar seu próprio envio.

Esse journal é evidência histórica **no modelo de escritor/armazenamento local
confiável**. O checksum não autentica um escritor hostil nem prova sozinho que
a transação foi divulgada. A âncora histórica permanece imutável; não é tratada
como confirmação atual após retirada do bloco.

O diário inicial permanece bloqueado durante a republicação e os dois diários
são abertos/sincronizados estritamente. A decisão usa observações nativas novas:

| Primeira claim | Contraparte | Decisão |
| --- | --- | --- |
| No pool | Qualquer observação obtida | Acompanhar, sem republicar |
| Incluída | Qualquer observação obtida | Acompanhar, sem republicar |
| Ausente com input livre | Ausente/input livre ou no pool | Republicar somente na janela original |
| Ausente com input livre | Claim exata da contraparte canônica | Pagar a obrigação, mesmo após a janela inicial |
| Desconhecida/conflitante, ou contraparte desconhecida no caso ausente | — | Reconciliar, sem envio |

Ausência não é inferida apenas de not-found. Os observadores existentes exigem
UTXO nativo correspondente ou key image livre, além de corpos, identidades e
tips coerentes. Antes de publicar, o worker repete as observações das duas
pernas e os checks de tip, e confere a janela original depois desse custo.
Não usa a expiração para cancelar uma dívida com contraparte já paga.

`InitialClaimJournal::check_exposed_replay_deadline` verifica somente tempo,
nunca autoriza envio sozinho. Restaura o instante de possível exposição do
evento já existente, recusa tempo anterior a ele e conserva o limite original.
Não muda o formato do arquivo nem reabre `release_once`, que continua recusando
novas liberações quando o estado é ExposurePossible. O relógio local continua
uma premissa: isso não cria relógio monotônico durável nem proteção contra
rollback hostil de relógio/backup entre processos.

## Ensaio e limites

O novo cenário conserva os controles anteriores e acrescenta:

1. Primeira claim no pool e só ExposurePossible: tentativa de republicação
   sem histórico canônico retorna Reconcile, sem enviar ou criar obrigação.
2. Depois de inclusão, criação da obrigação e possível exposição da contraparte,
   `pop_blocks` retira a primeira claim. No pool, o novo emissor apenas acompanha.
3. O supervisor retira esse hash do pool e minera uma substituição vazia.
   Novo processo verifica ausência/input livre nas duas pernas e a janela
   original; outro republica diretamente no monerod os bytes iniciais persistidos.
4. O emissor recebe admissão nativa e morre com **exit 79** antes de informar o
   supervisor. Outro processo encontra a claim no pool e não duplica o envio.
   Isso é perda de estado após ACK, não resposta omitida pelo monerod.
5. Após reinclusão, pedidos explícitos de republicação só acompanham a inclusão.
   Os registros originais permanecem byte a byte idênticos. O ensaio continua
   com envio independente da contraparte, gastos posteriores e conflito de refund.

`INITIAL-NATIVE-REPLAY-CHECKS.json` registra 67 testes Rust, Clippy all-targets
e build aprovados. Os dois testes novos verificam a janela após reabertura,
regressão abaixo do evento de exposição, manutenção do bloqueio de release_once
e decisões sob estados conhecidos/desconhecidos ou pagamento da contraparte.

O caso nativo foi desenhado para exercitar republicação XMR dentro da janela
original, mas a primeira execução **não chegou a essa etapa**. PID 975550
terminou com exit 101 em 99,989 s: depois do financiamento/maturação XMR,
o gate recusou liberar as ofertas porque a janela original já havia expirado.
As duas reservas de teste já estavam financiadas; não houve execução dos
workers de recuperação. A falha está preservada em
`DIRECT-PAIR-XMR-FIRST-NATIVE-REPLAY-INITIAL-FAILURE-*` e no resumo JSON de
mesmo prefixo. Os testes unitários não substituem essa validação nativa.

Após validar a verificação com duas rodadas concorrentes da cápsula direta,
o novo ensaio **passou**: PID 1018508, exit 0, total 172,394 s (watchdog
172,424 s), claims incluídas em 78,972 s. A mudança conserva as 256 equações,
o trabalho sequencial de abertura e a janela original. A verificação da prova
levou 7,499 s nesse ensaio; preparação/verificação da cápsula 51,618 s.

O trecho completo de retirada/reinclusão levou 2,002 s; inspeção/republicação/
queda exit 79/reabertura no pool 0,452 s. Reinclusão XMR da altura 152 para
153, com registros originais idênticos. O novo processo publicou diretamente
no monerod e recebeu ACK antes de morrer; outro apenas acompanhou o pool.
A contraparte DOM foi enviada por worker restaurado, os outputs foram gastos
e a devolução conflitante foi rejeitada na altura 221. A abertura temporizada
da cápsula não foi exercitada nesse cenário cooperativo.

Artefatos: `DIRECT-PAIR-XMR-FIRST-NATIVE-REPLAY-PARALLEL-*` e
`INITIAL-NATIVE-REPLAY-VERIFICATION.json`. Burst DOM 100 e GOMAXPROCS=2
explícitos; workers fizeram 86 leituras públicas/28 autenticadas DOM, um
POST DOM, zero 429. Fontes e binários conferidos; todos os PIDs/grupo próprios
encerrados (session 14306 exit 0). Não atribuir toda a diferença entre rodadas
à alteração: a preparação/funding também variou. O controle com a mesma prova
e um/dois workers está em `../recovery-audit/DIRECT-PARALLEL-CHECKS.json`.
Uma execução abaixo de 180 s não é garantia de prazo/repetibilidade.

O ramo DOM
e o repagamento depois da janela com contraparte canônica ainda precisam de
ensaios nativos próprios. Permanecem fora do modelo fork-choice entre peers,
snapshot atômico entre cadeias, ABA, armazenamento hostil, participantes
independentes/autenticados e a prova temporal/criptográfica completa. O custo
de todos os probes continua no prazo e no total do ensaio.
