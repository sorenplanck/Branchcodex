# Publicação independente da devolução privada XMR

`refund_delivery.rs` acrescenta processos de observação/publicação ao worker
de assinatura existente. Eles recebem apenas diretório, identidade original
do job e ação; não recebem shares, solver ou interpretações de cadeia do pai.
O supervisor continua hospedando os nós e minerando a fakechain. Este não é
um reinício completo do coordenador nem integração ao dom-interopd.

## Autorização e bytes originais

O job v2 fixa também o digest de `refund-network.record`: porta loopback,
genesis, altura e hash de um bloco original após financiamento/maturidade.
A porta nunca vem de uma mensagem posterior. Os checkpoints anteriores v1
continuam documentando execuções antigas; não há migração de operações ativas.

O processo exige `RecoveryOnly` para o job exato e mantém o lock da barreira
durante observação e envio. Carrega a intenção unsigned original e os bytes
assinados, verifica a assinatura, o corpo e a serialização. Não contém caminho
para solver, nova assinatura ou substituição de arquivo faltante/corrompido.

Antes de publicar, consulta o daemon original: identidade offline/fakechain,
genesis, bloco de referência, anel completo de chaves/commitments e outputs
desbloqueados; observa a transação exata no pool/bloco ou sua ausência junto
com key image não gasta. Resposta desconhecida, não confiável ou contraditória
não autoriza envio. Compara a ponta antes/depois das leituras.

Uma nova publicação exige ausência e input livre dentro do prazo original.
Antes do POST sincroniza `refund-send.intent`, ligado ao job e ao hash dos
bytes assinados. A presença desse arquivo não prova aceite pelo nó. Reconsulta
transação/key image/ponta e relógio depois de persistir. Há um POST por processo;
erro ambíguo exige nova reconciliação, nunca retry HTTP cego. Pool ou inclusão
suprimem reenvio, inclusive em retomadas. A inspeção não renova o prazo.

Os testes nativos injetam saída80 depois do intent/before-RPC, saída81 após
aceite nativo e antes do relatório, reabertura que encontra o pool e depois
outro processo que verifica inclusão. O pai confere que assinatura e intent
permanecem idênticos. Todas as consultas e retomadas entram nas medições;
não há exclusão desse custo da recuperação.

## Limites

Mantém as premissas de storage/relógio/nó locais confiáveis e writers que
respeitam o lock. Checagens de ponta detectam mudanças visíveis, não ABA/reorg
invisível nem mentira do daemon. A validação final continua no consenso nativo.
`do_not_relay` e blocos gerados são exclusivos da fakechain própria; a espera
de maturidade na rede real não é demonstrada por estes tempos.

O timeout de oito segundos é por processo; o prazo de publicação continua
original. Ainda não há orçamento global persistido de tentativas. Quedas antes
de salvar a intenção unsigned após funding ou durante assinatura continuam
pendentes; arquivo de assinatura parcial falha sem reparo automático. Este
caminho só trata abandono privado, nunca recuperação após exposição de
adaptors. Preparação independente, provas criptográficas/temporais e
integração ao daemon completo continuam abertas.

## Evidência desta rodada

Passaram 18 testes do exemplo, Clippy all-targets com -D warnings e build:
`REFUND-DELIVERY-CHECKS.json`. Dois testes novos exercitam respostas ausentes,
ambíguas/não confiáveis/spent, limites do relógio, e mutações de cada byte do
checkpoint da rede sob digest original. Os testes anteriores de job,
recuperação, exposição e observações cooperativas continuam passando.

Ensaio `direct-pair-abandon-local-receipt`, session98733/PID1528381, exit0:
**196,115 s totais**, **42,163 s** para recuperação/assinatura/publicação com
quedas e retomadas. Assinatura worker1529477:41,097 s. Primeira saída80 do
publisher1529592 após intent durável; segundo publisher1529593 saiu81 depois
do ACK; terceiro1529594 observou InPool e NÃO enviou. Após mineração pelo pai,
worker1529595 verificou inclusão em152 e NÃO enviou. Tx e intent inalterados.

Recebimento1790484240, início1790484275 (+35), XMR incluído e observado pelo
worker1790484317 antes do limite1790484340. DOM devolvido na altura221 após
lock220; outputs de ambas as devoluções gastos. Nenhuma publicação XMR refund
pelo pai, nova prova/produção ou exportação de shares. Não houve mudança nos
seis registros protegidos de entrada. Artefatos
`DIRECT-PAIR-ABANDON-REFUND-DELIVERY-*` e `REFUND-DELIVERY-VERIFICATION.json`.

O resultado funcional passou e a recuperação ficou dentro dos 65 s assumidos;
**o total excedeu 180 s em 16,115 s**. A preparação de saldos consumiu40,452 s,
verificação da cápsula chegou a98,322 s, XMR incluído166,187 s, e o restante
incluiu espera da altura e devolução DOM. Não apresentar este ensaio como
atendimento da meta total nem reduzir os prazos de segurança para fazê-lo caber.
Hashes de fontes/binários conferidos; pai, workers e grupo encerrados.
