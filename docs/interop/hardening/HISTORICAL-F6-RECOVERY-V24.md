# Retomada histórica F6 sem funding novo

`run` em modo `ReopenExisting` distingue admissão nova de recuperação econômica.
A exceção histórica exige o RouteStore original, checkpoint de admissão
autenticado e replay completo de ações sob custódia externa. Pelo menos uma
perna deve ter funding `Externalized`, `Final` ou finalidade invalidada por
reorg; apenas `Committed`, `RecoveryOnly` ou um checkpoint vazio não bastam.
Além disso, o replay deve já estar em `RecoveryOnly`, ou o loader autenticado
deve informar que a ancestralidade temporal corrente não está pronta. Uma rota
financiada saudável, com ancestralidade válida, mantém o caminho F6 corrente,
`Running` e a possibilidade de claim normal. Falhas no caminho corrente de F6,
inventário ou serviços não acionam fallback histórico.

Com essa prova, o startup deixa de consultar o inventário XMR independente do
solver. Mantém os arquivos e assinaturas F6 originais, autentica os status
exatos no histórico completo dos dois stores e não reinstala observações,
não altera o saldo observado nem retrocede o relógio. A posse local dos stores
continua exigindo lease válida. Arquivos ausentes, scope divergente e históricos
corrompidos são recusados; a retomada não completa uma criação incompleta.

Essa abertura aceita somente recibos F6 já persistidos, byte a byte. Novas
reservas, novas capacidades de execução F6 e nova autoridade de status/tempo
são recusadas. Antes do primeiro tick, o runtime registra `RecoveryOnly` com
identidade estável e mantém a janela transitória de funding fechada. Claim,
refund e reconciliação continuam sujeitos às provas econômicas originais e às
restrições do estado de recuperação. Ancestralidade vencida degrada explicitamente
para saída segura; não concede autorização para continuar claim normal.
Todo reinício deriva novamente a restrição do mesmo replay; não há opção CLI
para fabricar essa capacidade ou reabrir a janela de funding.

Uma fronteira adicional é o crash depois do POST XMR e antes da externalização
do agregado DOM/XMR. `Committed` continua insuficiente por si só. O novo caminho
exige o plano e journal completos do coordenador, efeito/fence/semântica e
agregado originais, além do descritor nativo exato (transação, destino compartilhado,
valor, custódia e intent). Em seguida, `verify_xmr_funding_v11` deve comprovar a
inclusão final do output original através do quorum real e do sidecar autenticado.
Ambos os journals são revalidados antes de emitir a capacidade apenas de saída.
O agregado permanece `Committed`: nenhum evento `Final`/`Externalized` é fabricado.
O owner de enrollment é aberto uma única vez e transferido para o child; não
se abrem stores/sidecars duplicados para essa observação.

A verificação histórica de status retorna apenas `Result<()>`: não retorna
capacidade `Active`. Uma assinatura válida nunca instalada no store é recusada.
A expiração dos envelopes Relay nunca aceitos permanece inalterada e segue
[a limitação normativa existente](RELAY-EXPIRY-RECOVERY-LIMIT-V23.md).

Regressões escritas: checkpoint sem funding não habilita a exceção; intent
`Committed` é insuficiente; replay com externalização habilita apenas a mesma
rota/composição quando há motivo de recuperação; restart financiado saudável
mantém `Running` sem capacidade histórica; expiração ou `RecoveryOnly` retido
selecionam somente saída; `RecoveryOnly` é idempotente e impede voltar a `Running` com
fundos abertos; status expirado retido autentica historicamente, mas não gera
`Active`, não instala outro status e não retrocede o relógio. Os testes desta
alteração ainda não foram executados.

Limite da evidência de cenário: avançar alturas nativas na fixture não prova
expiração de F6 pelo relógio. O cenário não cooperativo verifica confirmação
nativa e saída segura após o prazo nativo; a seleção histórica por expiração
tem regressões separadas. Não se altera um objeto assinado para simular expiração.
