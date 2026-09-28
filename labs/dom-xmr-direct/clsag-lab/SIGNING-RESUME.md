# Retomada após abertura e durante a gravação da assinatura

A etapa anterior repetiria a verificação/abertura se o signer caísse depois
de recuperar a share XMR, consumindo novamente a maior parte do prazo. O novo
checkpoint `refund-opening.record` guarda a abertura já concluída sob a decisão
privada `RecoveryOnly`, antes de criar nonces de assinatura.

## Estado sensível e autorização

O registro contém **uma share original recuperada**, identidade original do
job e métricas da abertura. É material secreto, em diretório privado e arquivo
0600. Buffers de share/encoding usam Zeroizing. Não contém chave agregada,
offset aplicado ou nonces. Não é exportado em relatório ou resposta pública.
O pai compara apenas digest para verificar imutabilidade; ele continua no
mesmo domínio de storage confiável que já contém a share local original.

Antes de persistir, o signer verifica a relação escalar/ponto e restaura o
participante original. Depois de uma queda, confere identidade do job,
checksum, tamanho, escalar canônico e ponto esperado; restaura novamente o
roster/vínculo original, offset e key image. A cápsula e o job continuam ligados
ao recebimento e deadline originais. O checksum não autentica peers e não
protege contra rollback ou writer hostil no storage local.

Não refaz a prova ou a abertura ao carregar esse registro local já aprovado.
Isso é reutilização de resultado secreto validado, não uma prova pública de
abertura nem uma nova permissão para iniciar recuperação. O lock e o job exato
continuam obrigatórios. Um checkpoint parcial de abertura é recusado, sem
fallback silencioso que repita o solve ou invente tempo novo.

## Gravação interrompida da assinatura

Os bytes completos são gravados e sincronizados em `refund-signed.pending`.
A promoção usa hard link sem sobrescrita para `refund-signed.tx`, fsync do
diretório e remoção da entrada pending. Em uma retomada, bytes completos são
conferidos contra a intenção original e promovidos sem nova assinatura.

Uma staging parcial ainda privada pode ser descartada sob lock e a assinatura
refeita com nonces novos, a partir da abertura persistida. Isso só é permitido
sem arquivo final e sem `refund-send.intent`. O publisher nunca usa staging.
Arquivo final inválido é recusado, jamais consertado por nova assinatura.
Final ausente com intent de publicação falha ANTES de shares/solver; existência
de intent é possível exposição, não recibo de aceite.

## Cenário e limites

O cenário nativo injeta saída82 após abertura persistida, saída83 depois de
gravar metade da assinatura, saída84 depois de sincronizar a assinatura
completa e antes da promoção. Os três signers seguintes recebem caminho de
solver inexistente, para comprovar que não dependem de outra abertura. Depois
executa as saídas80/81 do publisher e a reconciliação pool/inclusão anterior.
O tempo integral de todos esses processos permanece na medição original.

Isso cobre quedas APÓS uma abertura completa e durante staging, não pausa no
meio do cálculo sequencial nem perda parcial do checkpoint de abertura.
Também não cobre queda antes do job após funding, corrupção de arquivos já
publicados, orçamento global de tentativas, peer independente ou recuperação
pós-exposição. Custos e segurança temporal ainda são hipóteses laboratoriais;
integração ao dom-interopd e prova completa de atomicidade continuam pendentes.

## Verificações

Passaram 22 testes do exemplo, Clippy all-targets -D warnings e build, com
hashes em `SIGNING-RESUME-CHECKS.json`. Os quatro testes novos cobrem share
canônica/identidade/ponto, truncamento e corrupção, promoção sem sobrescrita,
abertura parcial que não vira ausência, e recusa do worker quando falta uma
assinatura possivelmente publicada, antes de shares ou solver.

O primeiro ensaio nativo falhou em 16,021 s (PID1580165/session17841), ANTES
da cápsula e do funding compartilhado: `hit decoy selection round limit`
na preparação do saldo individual. Sem mudança de código ou prazos; essa
tentativa foi preservada em `*SIGNING-RESUME-INITIAL-FAILURE-*`, com hashes e
grupo encerrado conferidos. É uma fragilidade observada do fixture de decoys,
não evidência sobre as quedas da recuperação que ainda não tinham sido executadas.

O cenário novo, com as MESMAS fontes/binários, passou (PID1580411/session86359,
exit0): **186,557 s totais** e **45,737 s** de recuperação integral, incluindo
os signers e publishers reiniciados. A abertura única levou31,866 s; conjunto
de processos de recuperação/assinatura43,773 s; última retomada0,780 s.

Worker1582656 abriu e saiu82;1582755 gravou metade e saiu83;1582757 recuperou
a abertura, usou nonces novos, gravou uma assinatura completa e saiu84;
1582758 promoveu os MESMOS bytes sem assinar de novo. Em seguida publishers
1582759/1582760 saíram80/81;1582761 encontrou pool sem POST e1582762 confirmou
inclusão sem POST. Checkpoint da abertura permaneceu com o mesmo digest.

Recebimento1790485218, início1790485253 (+35), XMR observado1790485299 antes
do limite1790485318. DOM lock220/refund221; outputs de ambas devoluções gastos.
Registros de entrada, assinatura e intent inalterados; nenhuma abertura nova
nos três processos com caminho de solver inválido. Hashes/PIDs/grupo ausentes
conferidos em `*SIGNING-RESUME-*`/`SIGNING-RESUME-VERIFICATION.json`.

A recuperação ficou dentro dos65 s assumidos, mas **o total excedeu180 s em
6,557 s**. A primeira falha de decoys e o ensaio anterior196,115 s continuam
válidos. Não são prova de SLA, tolerância ilimitada a quedas ou segurança
completa do protocolo. Nenhum ensaio ficou pendente.
