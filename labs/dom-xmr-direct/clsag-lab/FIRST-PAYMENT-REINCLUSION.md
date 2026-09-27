# Primeira claim reincluída e obrigação preservada

## Problema corrigido

O worker calculava `DeliveryBinding` com o bloco/altura atuais da primeira
claim e exigia igualdade completa ao reabrir o journal. Depois de uma retirada
e reinclusão nativas da mesma transação em outro bloco, a obrigação correta
ficava presa em `Reconcile`, mesmo com prova nativa atual e bytes iguais.

`DeliveryPayment` separa a identidade estável (manifesto, digest da primeira
transação, cadeia alvo) da localização histórica. `open_for_payment` abre e
bloqueia o mesmo arquivo, valida formato/checksum/evento completo e exige
essa identidade. O bloco/altura originais permanecem no registro imutável,
inclusive cobertos pelo checksum. Não há migração de formato, reescrita,
reparo de cauda ou criação automática. A API `open` que recebe o binding
completo permanece estrita quanto ao bloco/altura originais.

O worker usa a nova abertura somente **depois** de verificar a primeira
transação exata contra o envelope aprovado e obter sua inclusão nativa
canônica atual, com os checks de identidade/tip existentes. Verifica ainda
o corpo e witness da contraparte guardada. Campos de resposta distinguem
`original_first_block/height` de `first_block/height` atuais. Uma nova inclusão
não renova o prazo original, não substitui bytes e não completa outro adaptor.

Nenhum checksum ou `DeliveryPayment` prova inclusão ou autentica armazenamento
hostil. As obrigações de verificar cadeias permanecem no chamador. Se a primeira
claim estiver no pool ou ausente, o worker retorna `Reconcile` antes de abrir
para envio; não apaga nem fecha a obrigação existente. Esse comportamento não
resolve sozinho a atomicidade diante de reorgs profundos nas duas pernas.

## Ensaio nativo

O modo `direct-pair-xmr-first-reinclude` conserva o setup e a janela original:

1. Paga XMR e reconstrói a obrigação DOM depois da queda anterior ao journal.
2. Sincroniza possível exposição da contraparte e provoca exit 77 antes de RPC.
3. Remove o bloco XMR por `pop_blocks`. Processos novos solicitam `send` e
   `reconstruct`; ambos devem recusar envio enquanto a primeira claim só está
   no pool, sem mudar a obrigação.
4. Retira apenas o hash aprovado do pool e repete esses controles com a claim
   ausente. Minera uma substituição vazia.
5. O supervisor republica os bytes originais XMR já expostos e minera sua
   reinclusão em outra altura/bloco. Isso ainda **não** é recuperação autônoma
   do emissor da primeira perna.
6. Novo worker restaura a obrigação, verifica inclusão atual e preserva a
   âncora original, o payload, a exposição e os registros de início/prazo.
7. O caminho nativo existente envia a contraparte DOM, reconcilia pool/bloco e
   RPC indisponível, gasta os outputs e rejeita a devolução conflitante.

O ensaio força `DOM_RPC_RATELIMIT_READ=100`, o mesmo burst padrão atual, para
registrar explicitamente a capacidade usada. Não pretende apagar a falha 429
do outro cenário documentada em `XMR-NATIVE-DETACH.md`. Todas as etapas entram
no total e a reinclusão precisa preceder o limite adversarial original ASSUMIDO.
Os checks não demonstram segurança temporal adversarial nem finalização pública.

## Verificação

`FIRST-REINCLUSION-CHECKS.json` registra 59 testes Rust aprovados e Clippy
all-targets com `-D warnings`. Os dois testes novos cobrem abertura do mesmo
pagamento sem mudança do histórico/exposição, bloqueio exclusivo, identidades
estranhas, cada byte corrompido, truncamento e recusa de envio sem observação.
Resultados nativos ficam em `DIRECT-PAIR-XMR-FIRST-REINCLUDE-*` após execução.

O ensaio nativo PID 931558 terminou com exit 0 em **176,728 s**. Ambas as
claims foram incluídas em **90,383 s**; o trecho de exposição, retirada,
evicção, reinclusão da primeira claim e restauração levou **1,180 s**.
O novo bloco XMR estava na altura 153, contra 152 originalmente. A obrigação
continuou com a âncora 152, byte a byte idêntica, e os workers seguintes
verificaram a nova âncora 153 sem outra assinatura. A reinclusão ficou dez
segundos inteiros antes do limite adversarial ASSUMIDO.

Pool e ausência da primeira claim bloquearam envio/reconstrução; os controles
posteriores de pool/inclusão/RPC indisponível da contraparte passaram. Todos
os outputs foram gastos, e a devolução DOM conflitante foi rejeitada na altura
214. Os registros originais de início e manifesto permaneceram intactos.
Hashes dos fontes/binários conferidos; PIDs registrados e grupo próprio
encerrados. `FIRST-REINCLUSION-VERIFICATION.json` registra essa verificação.
Build separado e os 59 testes/Clippy passaram antes da execução.

Esta medição usou o burst padrão 100 e ficou abaixo de três minutos, mas não
invalida a falha 429 do cenário DOM-first ou resultados anteriores acima da
meta. Não estabelece SLA, confirmação mainnet ou segurança bilateral provada.

Continuam fora do ensaio fork-choice entre peers, reorg ABA, escritas nativas
concorrentes entre RPCs, restart completo de funding/divulgação/solver,
preparação independente autenticada e integração ao dom-interopd.
