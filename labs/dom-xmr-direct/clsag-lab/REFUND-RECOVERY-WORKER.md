# Recuperação e assinatura XMR em processo novo

O modo `direct-pair-abandon-local-receipt` agora entrega a recuperação e a
assinatura da devolução a um processo Rust novo. O pai descarta suas duas
shares originais e encerra o verificador Go antes de iniciar esse processo.
O worker recebe apenas caminhos e um digest aprovado; não recebe share,
interpretação de abertura ou prazo calculado a partir do instante atual.

## Intenção sem assinatura

`PreparedClaim::to_recovery_bytes/from_recovery_bytes` conserva corpo exato,
anel, key image, pseudo-output, hash de assinatura e aberturas dos commitments.
Não contém spend shares ou nonces de assinatura. Buffers privados são Zeroizing.
Como o formato de transação nativo exige espaço para CLSAG, o codec usa um
marcador fixo com respostas/challenge zero e exige que NÃO seja uma assinatura
válida. Recusa assinatura completa inserida no registro, mesmo com digest novo.

A restauração verifica digest previamente aprovado, tamanho limitado, forma
canônica, anel, commitments, pseudo-output, offsets, corpo nativo, range proof e
balanço. Só depois permite criar uma nova sessão de assinatura para esse corpo.
Não reconstrói outputs, taxas ou chave de transação. Não verifica maturidade,
input livre ou autorização externa dos destinatários: essas obrigações não são
substituídas pelo checksum ou pela consistência criptográfica interna.

## Trabalho persistido e processo

Depois dos depósitos, antes da espera para recuperação, o supervisor constrói
a devolução sem assinatura e grava `refund-recovery.job`: identidade do estado
local, binding da cápsula e do vínculo, recebimento/limite originais, offset e
intenção sem assinatura. Arquivo privado 0600/create_new/fsync; diretório
durável estabelecido pelo cenário. Storage local confiável continua premissa.
A intenção depende do output financiado e por isso NÃO é persistida antes dos
depósitos; queda antes dessa gravação ainda exige reconstrução a partir da rede.

O novo worker confere a identidade do arquivo, a cápsula original e o vínculo
com a reserva/share local. Restaura o Go usando o comprovante local de setup,
reverifica a prova inteira, abre e confere a share remota. Aplica o offset só
então, confere a chave do input e key image, gera nonces novos e assina o corpo
congelado. Devolve apenas `refund-signed.tx` e métricas, nunca spend shares.
O perfil é explicitamente o laboratório com limite original = recebimento+100;
esse check não fundamenta a hipótese temporal nem autoriza criar novos prazos.

O supervisor confere novamente a assinatura e o corpo, publica no monerod
próprio, observa inclusão e testa os gastos posteriores. Conserva o papel de
host dos nós e minerador DOM. Isso é recuperação/assinatura por worker novo,
NÃO reinício integral do coordenador, publicação pelo worker ou dom-interopd.
O worker não recebe uma devolução pronta que permita gastar antes de abrir a
cápsula. Os cinco registros de entrada são comparados antes/depois; permanecem
iguais. Não há produtor novo, prova nova ou renovação da janela.

## Verificação e limites

Na primeira versão passaram 30 testes Rust (12 nativos, quatro de estado local, 14 do exemplo),
Clippy all-targets -D warnings e build. Três testes novos do codec cobrem
roundtrip/assinatura, corrupção/truncamento/mutações com digest recalculado e
inserção de uma assinatura completa. Um teste do job cobre substituição,
create-only e tentativa de renovação do limite. Evidência
`REFUND-RECOVERY-WORKER-CHECKS.json`. Não houve alteração nem novo teste Go.

O primeiro ensaio financiado falhou em **136,145 s**, após os depósitos e o
início da recuperação: o worker usava SHA-256 simples para a intenção, mas o
codec exige `claim_resume::digest` (domínio + comprimento + corpo). Os testes
do codec já usavam o digest correto; faltava testar a chamada no job. O worker
recusou antes de abrir a cápsula ou assinar. PID1331232/filho1331589 encerrados,
grupo ausente e hashes conferidos. Evidência `*REFUND-WORKER-INITIAL-FAILURE-*`.

A chamada foi corrigida sem alterar formato ou prazos. Um novo teste constrói
uma intenção nativa real, grava/carrega o job e passa pela mesma chamada do
worker; inclui a recusa explícita do hash simples. Não retomar a operação
expirada renovando seu prazo; o novo ensaio usa outra reserva de teste.
Depois da correção passaram 31 testes (12 + quatro + 15), Clippy e build;
evidência `REFUND-RECOVERY-WORKER-CHECKS.json`. A rodada anterior permanece em
`REFUND-RECOVERY-WORKER-INITIAL-CHECKS.json`.

Ainda faltam observação/publicação independente pelo worker, persistência de
resultados de envio e retomada após queda no meio da assinatura/publicação,
orçamento global de reinícios, preparação entre participantes independentes,
fundamentos criptográficos/temporais e integração ao daemon. Os nonces deste
worker são novos; este ensaio não retoma uma sessão cooperativa interrompida.
O cenário é abandono ANTES de entregar adaptors. O job sozinho não registra
uma barreira durável dessa entrega e não autoriza generalizar a assinatura ou
publicação para uma operação com claims possivelmente expostas. Essa distinção
deve ser ligada aos journals originais antes de ampliar o worker.

## Resultado financiado corrigido

PID1346571 terminou exit0: **168,992 s** totais / parede **169,012 s**.
Recuperação integral no supervisor **39,318 s**, worker **39,229 s**,
restauração Go **7,517 s**, abertura **31,467 s**. O custo integral inclui
queda do verificador antigo, criação do Rust, leitura/revalidação/abertura,
assinatura, escrita da transação e conferência pelo pai.

Recebimento original1790481710, início1790481745 (+35); XMR refund observado
1790481784 antes do limite1790481810. DOM lock221/refund222/gasto223.
Todos os outputs de devolução foram gastos. Os cinco registros de entrada
permaneceram iguais; nenhum segredo de spend foi devolvido ao pai.
Passou nas metas observadas <=65 s de recuperação e <=180 s totais.
Isso não demonstra repetibilidade, mínimo adversarial ou segurança bilateral.

Rust worker1346866, Go antigo1346649/novo1346867. Fontes/binários conferidos,
PIDs/grupo ausentes; session23347 terminou. Evidências
`DIRECT-PAIR-ABANDON-REFUND-WORKER-*` e `REFUND-RECOVERY-WORKER-VERIFICATION.json`.
A falha inicial e os resultados anteriores mais lentos continuam preservados.

A regressão cooperativa `height-dom-first` também passou: PID1348011,
**32,265 s** totais, claims/gastos nas duas cadeias e devolução conflitante
recusada. Prefixo `HEIGHT-DOM-FIRST-REFUND-WORKER-REGRESSION-*`. Fontes/binários
conferidos, processo/grupo ausentes, session69362 exit0. Não há ensaio pendente.
