# V22 — interoperabilidade sem alteração de consenso

## Validado no cenário conjunto: contexto de compromisso e custódia

Duas frentes integradas. O Store fixa um contexto imutável na revisão 17
OutputFinalized: chain/rota/sessão/termos, registro/transcript iniciais,
identidades, roster, evidências e digest da proposta. Isso ainda não emite
mensagem 0x18 nem concede assinatura/acordo bilateral. A reconstrução interna
agora pode ser executada sob o lock do Store, sem auditoria recursiva.

Na custódia, Cancel e Compensation exigem a sessão nativa e chave local;
RefundAdaptor tem extração isolada, sem mover Funding/Claim. O cenário
combinado ganhou negativos de Store vazio/Created/termos divergentes e novas
PoPs para demonstrar que a recusa não consome as cinco shares. A extração
positiva ainda depende da origem nativa GraphV23, não implementada.
Compilação conjunta passou: 59,84 s na fase anterior; nesta fase 58,71 s,
92 warnings de lib-test. Diff e L1 passaram. A rodada conjunta desta
ampliação passou: 1 teste, zero falhas, 502 filtrados, 687,14 s;
compilação crypto-test 4 min 29 s. Wallets: 133,39 s; C: 381,00 s;
D: 585,50 s (acumulados). Execução serial, sem outra carga pesada.
A revisão identificou que a auditoria histórica do contexto ainda precisa
comparar explicitamente rota e digest da proposta com evidências/pin.
O contexto não concede autoridade; o reforço deve preceder a emissão 0x18.

## Validado no cenário conjunto: evidências duráveis e escopo de assinatura

O pin agora retém também termos, política, duas ofertas e journals públicos
C/D em arquivo separado, imutável e limitado. A leitura de startup confere
formato/escopo, não concede autoridade. A operação de reconstrução revalida
termos, ofertas, identidades, provas C/D e a proposta contra o pin local.
O teste de formato passou (1 teste, zero falhas, 459 filtrados, 0,00 s;
compilação 3 min 01 s), antes de adicionar a reconstrução desde o arquivo.

Em paralelo, bind/tick/conclusão dos rounds passaram a exigir as chaves
individuais corretas para Cancel/Refund/Compensation. O cenário combinado
agora inclui reconstrução após reabertura, positivos e trocas inválidas de
etapa, participante, papel e chain. A compilação conjunta passou (59,84 s;
92 warnings na biblioteca de testes). A execução conjunta passou: 1 teste,
zero falhas, 502 filtrados, 559,96 s; compilação crypto-test 4 min 23 s.
Wallets prontos em 97,14 s, C em 298,97 s e D em 500,98 s (acumulados).
Foram exercitados o arquivo público persistido, sua reconstrução após
reabertura e os escopos de chaves reais de Cancel/Refund/Compensation.
Não há acordo bilateral admitido, sessões auxiliares produzidas nem
assinaturas finais/funding liberados. Nenhuma alteração na L1.

## Validado no cenário combinado: reconstrução dos cinco templates pelo Store

A formação V23 dos cinco templates foi compartilhada entre daemon e política.
Antes de reter o pin local, o Store agora decodifica as ofertas canônicas no
escopo do roster auditado, reconstrói os templates com as provas C/D reabertas
e exige igualdade byte a byte da proposta reconstruída. Tip e U continuam
entradas da proposta, não autoridade de tempo ou setup; isso ainda não constitui
acordo bilateral, assinatura ou funding.
A checagem de todos os alvos passou (37,64 s; 94 warnings na biblioteca de
testes), assim como diff e proteção da L1. O cenário combinado passou:
1 teste, zero falhas, 501 filtrados, 638,43 s; compilação 4 min 30 s.
Execução serial no perfil crypto-test, com wallets prontos em 129,63 s,
C em 343,55 s e D em 580,66 s (tempos acumulados). A reconstrução da
proposta pelo Store foi exercitada em duas reaberturas por participante.
Isso não comprova acordo bilateral, admissão do setup XMR ou o swap completo.

## Validado: reconstrução pública compartilhada das ofertas

A montagem pública das duas ofertas foi extraída do runtime para
`XmrGraphPublicMaterialV23::from_offers`, preservando a validação de escopo,
provas de posse, payouts e cinco contribuições de kernel. Isso prepara o
reuso pelo Store; não admite acordo bilateral nem libera assinatura/funding.
A checagem de todos os alvos de produção passou em 1 min 36 s. A regressão
dos dois wallets passou: 1 teste, zero falhas, 501 filtrados, 202,59 s
(recompilação 4 min 46 s), com perfil crypto-test e execução serial.
Esse teste exercita reabertura e material público, mas não forma C/D;
não substitui o cenário combinado descrito abaixo.

## Validado no cenário combinado: proposta local V23 e reabertura

O runtime agora persiste um pin imutável da proposta local após revalidar
os proprietários C/D, política, grafo e identidades. Não é acordo bilateral
nem autorização de assinatura/funding. O acesso passa por uma operação
estreita do proprietário, sem expor o Store.

Passaram o teste de integridade/conflito (0,03 s), a recuperação de escrita
interrompida após corrigir o cadastro do nome (7,07 s) e a checagem de todos
os alvos de produção (1 min, 94 warnings na biblioteca de testes).
O cenário ampliado falhou primeiro com Conflict em 3017,03 s. O perfil
opt-in crypto-test preserva assertions e overflow e reduziu a execução para
564,90 s (1 passou; compilação inicial 14 min 19 s), sem retirar verificações.
A revisão encontrou ordens distintas no transporte e nos termos. A persistência
agora associa direções por ID na ordem dos termos; os dois testes determinísticos
de ordem e integridade passaram (0,00 s; 457 filtrados).
Após essa correção, o cenário integrado passou novamente: 1 passou, zero falhas,
501 filtrados, 559,55 s; recompilação 5 min 17 s. Preparação: 79,35 s;
C pronto: 282,25 s; D pronto: 497,66 s (tempos acumulados).
Provas nativas, dois wallets, cinco templates sem assinatura, persistência e
reabertura dos Stores reais foram exercitados. Não comprova acordo bilateral,
setup XMR admitido, assinatura, funding ou recuperação do swap completo.
Cada execução foi serial. O resultado abaixo é histórico e anterior à ampliação.

## Validado: formação combinada C/D e wallets, ainda sem assinatura

A mesma cerimônia agora alimenta o teste de provas C/D com reabertura a cada
tick e os dois wallets, usando a função de formação compartilhada com o
runtime. O primeiro teste terminou com Relay(Sender(AlreadyExists)) em
1606,15 s: o binário continha o nome antigo de sender compartilhado. A fixture
agora deriva os três caminhos uma vez para ambos os usos; o teste rápido
de separação C/D passou após recompilação (0,00 s; compilação 1 min 28 s).

O cenário completo passou na reexecução: 1 teste, zero falhas, 501 filtrados,
em 2899,62 s, com uma execução pesada e uma thread de teste. Os dois
participantes formaram os mesmos cinco templates nativos sem assinatura e
a mesma identidade de compensação V23 a partir de provas C/D e wallets reais.
Setup XMR, assinatura, acordo persistido e funding não estão comprovados
por esse teste. Nenhuma mudança na L1.


## Progresso: formação do grafo no proprietário C/D

O Stage 12 agora chama o construtor dos cinco templates a partir das ofertas
bilaterais e das provas reabertas pelos proprietários nativos de C/D. Confere
política V23, setup, U, pin do template de refund e chaves/offsets de cada
participante. O resultado ainda é somente material público sem assinatura,
em memória. O cenário combinado acima valida a função de formação compartilhada;
a admissão de setup e a integração completa do laço ainda estão pendentes.

A suíte inteira do actuator foi repetida após a correção F7: 99 passaram,
zero falhas, em 583,42 s, serialmente. Isso não inclui os binários de
integração do daemon. A checagem de todos os alvos do daemon passou
(28,44 s, 95 warnings na biblioteca de testes). Formatação, diff e guard
da L1 passaram. Não houve commit, publicação ou implantação.

A recusa XmrRecoveryGraphRequired ainda se propaga no laço composto.
Acordo durável, sessões auxiliares de assinatura, custódia e prontidão
precisam ser conectados antes de liberar funding. Nenhuma flag de
prontidão foi forçada e nenhum consenso foi alterado.


## Em andamento: ligação V23 de wallet e rounds

A derivação validada da sessão V23 agora é compartilhada pelo grafo,
construtor e binding do participante. O wallet confere termos persistidos,
template, propósito Refund sem adaptor, roster e chave local antes de mover
a share. O runtime de rounds usa V23 e confere os termos retidos antes de
assinar. Entradas V22 continuam recusando compensação; custódia e funding
seguem fechados. A composição bilateral e seus testes ainda estão pendentes.

Passaram 15 testes nativos (22,94 s), o teste novo de binding V23 e a checagem
de todos os alvos do daemon (23,78 s). O guard da L1 passou. A execução de
98 testes do actuator terminou com 96 passando e duas falhas F7 (558,61 s).
As duas reproduziram isoladamente: o marcador de preparação usava o ID da
operação e violava a auditoria estrita de eventos de conclusão na reabertura.

Corrigido o ID do marcador, com domínio próprio derivado do escopo; escritor
e leitor usam a mesma derivação. Auditoria, schema e L1 foram preservados.
Quatro testes direcionados passaram (17,93 s), incluindo dois reinícios
sucessivos e recusa de outro dono/ausência de custódia. A suíte inteira foi repetida
na atualização acima; bancos antigos inconsistentes não são migrados nem apagados. Não houve commit, push ou implantação.

## Progresso: vínculo da auditoria Store ao grafo V23

A auditoria e sua revalidação agora recebem a política econômica, conferem
C/T contra o papel autenticado e exigem os IDs auxiliares exatos derivados
do grafo V23, além dos termos do pai nos dois históricos. O driver e o F7
passam a política correspondente. Os controles de identidade, custódia,
assinaturas e ausência de funding nas sessões auxiliares foram preservados.

Passaram 15 testes nativos (22,89 s), dois testes direcionados do Store
(0,00 s; compilação 1 min 04 s) e a checagem de todos os alvos do daemon
(30,29 s, warnings existentes). Guard de consenso, formatação e diff passaram.
Não é prova de um fluxo completo com dois Stores. O runtime de rounds ainda
usa o caminho legado; custódia/funding continuam fechados até a migração
coerente da autorização de wallet e dos históricos. Nenhuma mudança na L1.

## Progresso: assinatura nativa da compensação V23

Os termos econômicos foram movidos para xmr-compensation-policy, biblioteca
sem assinatura, RPC ou persistência. O caminho público anterior reexporta os
mesmos tipos. Os 10 testes econômicos movidos e os 19 testes restantes de
xmr-refund-policy passaram; nenhum teste foi retirado da cobertura.

A entrada begin_bounded_compensation_v23 exige a política opaca validada,
envelope V23 e vínculo exato de sessão/termos/prazos/taxas/destinatários.
Usa sessão auxiliar V23 com hash da política e completa somente parciais
ordinárias nativas. O construtor do grafo usa essa entrada e exige a mesma
sessão ao montar o resultado. Entradas legadas e witness local continuam
recusados. Não é autorização de wallet, Store ou funding.

A suíte nativa xmr_recovery_graph_v11 passou com 14 testes, zero falhas,
em 21,41 s (compilação 13,60 s). Inclui compensação ordinária válida no
consenso original e recusa de política legada/onze trocas de binding.
A checagem de todos os alvos do daemon passou em 45,54 s, com warnings
existentes. Guard de consenso, formatação e diff passaram; execuções seriais.
Não houve broadcast real, commit, push nem implantação. Persistência e
assinatura bilateral autenticada pelo daemon continuam pendentes.

## Atualização autorizada: política V23 de compensação com disponibilidade limitada

O operador autorizou compensação em DOM, mesmo com XMR original bloqueado,
sob a obrigação de atuação honesta dentro do prazo. A proibição de mudar L1
permanece. Não houve liberação de funding, assinatura de compensação,
commit, push ou implantação nesta etapa.

A política econômica ganhou a opção explícita bounded_availability_v23:
quatro limites em blocos DOM para indisponibilidade total (incluindo reinícios),
atraso de observação, inclusão de cancel e inclusão de refund. A versão usa
DOMXCM23 e domínio de hash V23; sem a opção, bytes e hash V11 são preservados.
A validação exige reservas separadas para as duas transações e finalidade.
Não é garantia de inclusão da chain nem autorização automática por um witness
local. Políticas antigas não passam a autorizar a nova recuperação.

Os 29 testes da biblioteca xmr-refund-policy passaram, incluindo cinco novos
casos V23, em 1,69 s. Checagem de todos os alvos do daemon de produção passou
em 55,08 s, com warnings existentes. Guard de consenso e verificações de
formatação/diff passaram. Integração bilateral do grafo, custódia e recuperação
pelo daemon ainda pendentes; ver a revisão detalhada abaixo.

## Estado atual: extensão de consenso retirada por ordem do operador

L1 intocável. Após a autorização explícita para remoção, o kernel XMR
`0x04`, seu campo adicional em transações, verificações, regras de peso,
restrição de agregação, tratamento no mempool e seleção no minerador foram
retirados. Nenhum kernel substituto ou ativação de rede foi criado.

A comparação com `38dd70536f088a467f2b7175978c5a6ebb4e5bd4` não apresenta
diferenças em dom-consensus, dom-core, dom-crypto, dom-pow, dom-pmmr,
dom-serialization, dom-mempool, dom-node/src/miner.rs e
dom-scriptless-consensus. As diferenças P2P preexistentes em node.rs e
dom-wire/src/handshake.rs não foram revertidas nesta remoção seletiva.
Não se afirma que toda a árvore do nó coincide com a base.

Também foram retirados o produtor de atestados, os caminhos de envio e
persistência por certificado, a configuração funding_intent_v22/certificate_file
e a construção/retomada/compromisso do grafo dependente da extensão.
O leitor de framing de caches antigos não reconstrói nem admite esse grafo.
Foram preservados formação de shares, provas nativas C/D, transporte e
mudanças independentes das outras famílias.

Compensação pré-assinada continua recusada, inclusive pela antiga entrada V22
com testemunha local. O broadcaster não a substitui por pagamento
incondicional. DOM↔XMR e recuperação não cooperativa pelo daemon continuam
incompletos; testes históricos do grafo retirado não provam sua conclusão.
A especificação de interoperabilidade, §P.3.6, exige evolução acima do consenso.

Cópia recuperável local: `/tmp/dom-l1-removal-LIqVs3CD/`.
Contém affected-files.tar.gz, os fontes exclusivos retirados e o executável
antigo target/debug/xmr-compensation-v22, movido sem ser executado.
Não houve commit, push ou implantação desta remoção.

Verificações após a remoção, executadas sequencialmente com um job:

- Varredura original dos 256 identificadores de kernel: 1 teste passou,
  incluindo recusa de 0x04; 54,05 s, compilação 37,74 s.
- Nó, todos os alvos: cargo check passou em 3 min 05 s.
- Camada criptográfica, todos os alvos: cargo check passou em 40 s.
- Daemon de produção, todos os alvos: primeira checagem passou em 2 min 33 s,
  com warnings; anterior às últimas regressões e ajustes de formatação.
- Integração criptográfica xmr_recovery_graph_v11: 10 testes passaram em
  15,60 s, compilação 48,83 s. Inclui recusa antes dos nonces, mesmo com
  testemunha local, e validade dos pagamentos legados sob o consenso existente.
- Regressão de rejeição dos campos de configuração retirados: 1 teste passou
  em 0,00 s, compilação 4 min 33 s, com 93 warnings em lib test.
- Guard de fontes de consenso: aprovado; sintaxe shell e git diff --check
  também aprovados. Em cópia temporária com índice Git separado, a referência
  intacta passou; arquivo novo e remoção de fonte protegido foram recusados;
  a cópia restaurada e a árvore real passaram novamente. Nenhum fonte real
  de consenso foi modificado para executar esses cenários negativos.
- Integração relay_worker/prepared_operational (assinatura, BP, templates,
  refund e reinício): 4 testes passaram, zero falhas, em 414,97 s;
  compilação 4 min 54 s, com warnings. Inclui os dois casos anteriormente
  relatados com Quarantined; nenhuma causa das falhas antigas é atribuída
  a esta remoção. Todos os comandos próprios foram acompanhados até o fim.

O CI passa a comparar os caminhos de consenso acima com a referência fixa,
incluindo arquivos novos. É uma verificação de fontes, não de binários ou
deployments. O objetivo integral do projeto não está concluído.

## Análise posterior: recuperação sem alterar L1

Duas regressões nativas novas comprovam que a janela local não expira claim ou
refund já assinados, e que U pode ser extraído de uma assinatura de refund sem
confirmação. A suíte xmr_recovery_graph_v11 agora passou com 12 testes, zero
falhas, em 18,78 s; compilação 1 min 47 s, um job/uma thread, quatro warnings
preexistentes. O guard de consenso e git diff --check passaram novamente.

[Revisão de recuperação sem L1](docs/interop/XMR_RECOVERY_WITHOUT_L1_REVIEW.md)
separa indisponibilidade da contraparte de indisponibilidade prolongada da
parte honesta, mapeia os orçamentos temporais existentes e documenta os riscos
de exposição de assinatura e compensação econômica. O grafo ordinário é
somente candidato sob premissas ainda não provadas; nenhuma recusa de funding,
assinatura ou broadcast foi removida. Não é evidência de swap pelo daemon.

## Histórico anterior à retirada — não descreve a arquitetura atual

### Validações históricas em 2026-09-10

Contexto local do compromisso XMR adicionado em `xmr_graph_commit_context_v22.rs`, ligado ao Stage12 após retenção do candidato. Exige evidência opaca de auditoria C/D, bytes do candidato idênticos, journal C atual, identidades nativas, BP finalizado/OutputFinalized, ausência de funding e ausência de autoridade de templates legada. Fixa chain/sessão/termos, revisão/head/transcript, autoridade BP, candidato, proposta, participantes/direções e sequências em digest de domínio próprio. A instância aberta é verificada separadamente: reabrir invalida o objeto antigo, mesmo que uma nova auditoria reproduza o digest.

Esse tipo não emite requisição DSC1, assinatura ou transição; prepara apenas o contexto inicial, antes dos dois compromissos. A classe de emissão, recepção e validação do prefixo bilateral continuam pendentes e 0x18 permanece recusado. O teste nativo foi ampliado para exigir retenção prévia, recusar chain/Store errados, recusar o contexto antigo após reabrir e exigir digest igual na preparação nova. A execução passou: 1 aprovação, 0 falhas, 132,21 s; compilação 4 min 17 s, dois warnings no Store, saída 0. Prioridade 19, um job/uma thread. Checagem de todos os alvos do daemon aprovada: saída 0, 5 min 57 s, 93 warnings em lib test. Todos os comandos foram acompanhados até o término, sem reinício nem testes pesados simultâneos. Formatação e checagem do diff passaram.

A checagem de todos os alvos do daemon com a fixture nativa C/D e o helper BP parametrizado passou: saída 0, 1 min 39 s, 93 warnings em lib test. A regressão nativa ampliada e as seis regressões anteriores abaixo estão aprovadas; não há teste ou check próprio em andamento. O próximo elo pendente é o compromisso bilateral assinado do grafo, não a reconstrução do candidato unsigned.

Adicionado teste positivo do candidato com dois Stores reais e 34 mensagens DSC1 early/BP nativas. C e D usam sessões derivadas distintas, identidades canônicas e shares/provas separadas; os offers econômicos usam escalares conhecidos apenas na fixture. O teste grava o candidato por meio da evidência opaca auditada, verifica imutabilidade/head inalterado, descarta ambos os Stores e objetos de grafo/chaves, reabre C com D fechado e exige igualdade dos cinco templates e da proposta. Depois reabre D, recusa a evidência da instância anterior e exige nova auditoria idêntica. Rota/U trocados são recusados; 0x18 segue sem autoridade.

A primeira execução desse caso passou: 1 aprovação, 0 falhas, 73,33 s; compilação 1 min 24 s, saída 0. Foi ampliado para adulterar os cinco componentes públicos com checksum externo recalculado e para trocar um spend_digest ainda canônico, que o construtor sozinho normalizaria. A repetição ampliada passou: 1 aprovação, 0 falhas, 89,11 s; compilação 44,29 s, dois warnings no Store, saída 0. O helper BP conserva o wrapper de valor 42 dos testes anteriores e admite o valor econômico nos novos casos. As seis regressões anteriores de BP/cache/staging/registros passaram com o mesmo binário: 6 aprovações, 0 falhas, 46,85 s, saída 0, uma thread e prioridade 19. Nova checagem dos alvos do daemon em andamento. Formatação e `git diff --check` passaram. Isso valida o Store e reconstrução pública, não wallets/nonce vaults, admissão DLEQ do setup, daemon bilateral ou execução nas chains.

A checagem de todos os alvos do daemon após persistência/retomada do candidato unsigned passou: saída 0, 1 min 07 s, 93 warnings em lib test. Este resultado encerra a checagem indicada como em andamento abaixo. Não substitui um teste positivo do fluxo completo com dois Stores reais e cinco templates; acordo bilateral e autorização de assinatura continuam pendentes.

Candidato unsigned XMR agora possui dossiê público canônico limitado a 256 KiB: dois offers, journals assinados C/D, condição de funding, tip histórico, U e proposta exata. O decoder confere framing/checksum, não autoridade. A reconstrução exige chain/rota/termos/política/roster/U externos, revalida assinaturas/PoPs/BP, reconstrói os cinco templates e compara proposta e condição exatas (inclusive spend_digest). A auditoria nativa confere esse roundtrip.

O Stage12 foi ligado à gravação imutável do candidato auditado e à tentativa de reconstrução do candidato retido antes de exigir offers em memória. A retomada ainda exige setup autenticado, condição de funding igual à admissão atual, hash de refund admitido e nova auditoria dos dois Stores reais. O novo arquivo `.xmr-graph-candidate-v22` é cache não assinado; a abertura do Store verifica apenas framing/escopo desse cache, e nenhuma autoridade de assinatura/funding o consulta. A recuperação matemática exige o journal C idêntico ao Store atual. Não é acordo bilateral, nem recuperação de nonce/vault D, nem prova de claim/refund nas chains. DSC1 0x18 continua recusado.

O teste inicial de framing passou (1 teste, 0 falhas, 0,03 s; compilação 1 min 25 s, 2 warnings no Store). A primeira execução dos três testes de codec/cache/staging encontrou duas falhas: faltava registrar o nome final e staging na camada Linux de componentes permitidos. Adicionados somente os nomes exatos de sessão, além do registro de inventário/auditoria do Store e da regressão de nomes. A repetição passou: 3 testes, 0 falhas, 11,94 s; compilação 1 min 11 s, saída 0. O mesmo binário passou depois nos dois testes de registros de nomes/payloads em 0,00 s. Formatação e `git diff --check` passaram. Execuções sequenciais, prioridade 19, um job e uma thread; checagem da ligação atual no daemon em andamento. Esses testes usam framing sintético para o cache: não provam o roundtrip integral com duas cerimônias reais e cinco templates, nem o ramo de retomada pelo daemon.

A checagem de todos os alvos do daemon com o rebuild nativo dos cinco templates terminou com saída 0 em 1 min 16 s, com 93 warnings em lib test. É a conclusão da execução indicada como pendente no registro abaixo.

A reconstrução unsigned foi separada do objeto de chaves previamente vinculado: `XmrGraphKeyMaterialV22::rebuild_graph_v22` revalida offers e reconstrói templates, enquanto o wrapper de chaves mantém a comparação com o grafo original. Isso permite reconstruir após descartar os objetos anteriores, mas não autentica U nem concede autoridade de assinatura. O teste foi ampliado para descartar offers/chaves/grafos, reconstruir dos pacotes públicos e comparar a proposta retida; também exige recusa de uma proposta com U substituído. Os sete testes passaram, zero falhas, 5,52 s, compilação 31,15 s, saída 0; formatação e `git diff --check` passaram. A nova checagem de todos os alvos passou, saída 0, 44,68 s, 93 warnings em lib test. As execuções foram sequenciais, prioridade 19/um job/uma thread quando aplicável. Persistência e admissão bilateral no Store continuam pendentes.

Reconstrução nativa dos cinco templates adicionada em `graph_rebuild_v22.rs`: os dois offers canônicos são decodificados e revalidados, funding/payouts/contribuições são reconstruídos, e o resultado precisa coincidir com os hashes e o binding completo originais. O construtor conserva agora o tip histórico de negociação; ele não substitui uma observação de chain atual. A auditoria do Store reconstrói objetos Frozen/Verified de C/D a partir dos journals públicos e chama esse rebuild antes de emitir a evidência local.

A regressão do journal passou novamente com a reconstrução dos objetos nativos: uma aprovação, zero falhas, 164,71 s, compilação 3 min 14 s e dois warnings no Store, saída 0. Isso ainda não executava o rebuild do grafo inteiro. O novo teste matemático do grafo compilou, mas recusou o primeiro offer: a fixture usava offsets individuais zero, inválidos para offers reais. Foram usados offsets não nulos e os excessos ajustados pela subtração nativa, sem mudar a validação de produção. A repetição dos sete testes de chaves/proposta/rebuild passou: sete aprovações, zero falhas, 3,83 s, compilação 16,28 s, saída 0. O teste novo usa aberturas locais conhecidas e provas matemáticas nativas, não simula um wallet/Store ou uma execução nas chains; comprova igualdade dos cinco templates e recusa de offer, condição de funding e prazo trocados. Checagem do daemon após essas alterações em andamento; assinatura/persistência bilateral ainda não implementadas.

O vínculo de rota das chaves/proposta agora é rechecado explicitamente pelo driver contra o proprietário de Contracts. A suíte `graph_signing_keys_v22::tests` passou: seis testes, zero falhas, 0,13 s, compilação 2 min 23 s, saída 0. O caso novo recusa rota/chain/sessão/termos/participantes/direções trocados; não autoriza assinatura.

Representação pública limitada a 64 KiB dos 17 passos early/BP adicionada em `xmr_graph_output_journal_v22.rs`. O decoder apenas lê a forma; a verificação exige roster autenticado fornecido pelo proprietário, chain/sessão/termos/valor/output esperados, assinaturas e sequência/transcript completos, PoPs e provas BP nativas. A auditoria C/D retém esses bytes sem persistir ou assinar um compromisso. O teste ampliado passou: uma aprovação, zero falhas, 64,68 s, compilação 2 min 18 s, dois warnings no Store, saída 0. Inclui verificação após fechar o Store, alteração de cada mensagem assinada, truncamento e trailing, além das recusas de output/valor/termos e reabertura anteriores. Não é o verificador independente prometido no objetivo, não autentica por si só estado privado de nonce nem substitui a admissão bilateral. A checagem posterior de todos os alvos do daemon com a representação pública e o vínculo explícito de rota passou: saída 0, 3 min 11 s, 93 warnings em lib test. Testes e checagem executados sequencialmente, prioridade 19 e um job/uma thread quando aplicável. DSC1 `0x18` continua recusado no Store até a ligação da autoridade, emissão e persistência do acordo.

A regressão nativa `graph_output_audit_requires_exact_completed_native_proof_and_survives_reopen` passou: um teste, zero falhas, 98,11 s, saída 0; compilação 4 min 53 s e dois warnings no Store. O mesmo binário recém-compilado executou depois o teste do registro de payloads do Store: uma aprovação em 0,00 s, preservando a recusa de `0x18`. Não é a suíte inteira nem teste de acordo bilateral C/D. A primeira checagem do daemon encontrou E0616 por acesso ao Store privado. A ligação foi movida para uma operação específica do driver de bootstrap, que valida o vínculo DOM e a sessão derivada/rota/participantes do proprietário D, sem expor o Store. A repetição de `cargo check --offline --locked -j1 -p dom-interopd --no-default-features --features production --all-targets` passou: saída 0, 1 min 03 s e 93 warnings em lib test. Todas as execuções foram sequenciais, prioridade 19; a missão DOM↔XMR ainda não está concluída.

A checagem de todos os alvos do daemon após a extensão de transporte `0x18` terminou com saída 0, 10 min 18 s e 93 warnings em lib test. Esse resultado antecede a ligação da auditoria nativa C/D abaixo e não a valida.

Adicionada auditoria nativa da proposta unsigned em `session_store/xmr_graph_proposal_v22.rs`: reconstrói early/BP dos Stores C e D separados, compara outputs/provas/cápsulas exatos, identidades/roster/direções, escopo das chaves e condição de compensação. Stage12 exige essa auditoria antes de cachear a proposta. A evidência é local ao processo, sem codec nem autorização de assinatura/funding; sua reauditoria rejeita troca da instância aberta dos Stores. O Store continua recusando DSC1 `0x18`: admissão assinada e persistência bilateral permanecem pendentes.

O teste novo de proveniência usa mensagens early/BP nativas e verifica output exato, Store incompleto, mutações de prova/cápsula/valor/termos e reabertura sem alterar o head. A primeira compilação encontrou E0432: faltava reexportar o tipo de evidência em `runtime.rs`; corrigido. A repetição compilou em 4 min 53 s, com dois warnings no Store, e executa somente a regressão nova, prioridade 19/um job/uma thread. Formatação e `git diff --check` passaram. Ainda não há resultado desse teste nem checagem de todos os alvos após a nova auditoria.

A suíte unitária completa do transporte passou com o mesmo binário que contém `0x18`: 19 testes, zero falhas, 0,36 s, saída 0, prioridade 19/uma thread. Inclui codecs, assinatura, replay/equivocação, Abort, EVM, readiness V12 e Noise. Após o encerramento iniciou-se somente a checagem de todos os alvos do daemon com a nova variante; resultado ainda pendente. Esses resultados não demonstram emissão/admissão do compromisso pelo Store.

A checagem dos alvos do daemon com a proposta unsigned passou: saída 0, 2 min 55 s, 93 warnings em lib test. É anterior à extensão de transporte abaixo.

DSC1 agora possui o envelope tipado `XmrGraphTemplateCommitV22` (`0x18`), com payload estritamente igual a um digest não nulo de 32 bytes. Não reutiliza `0x17` nem altera o ready-to-fund. O envelope exige fase-alvo TemplatesCommitted e vincula tipo, chain, sessão, remetente, sequência, transcript e digest pela assinatura nativa. O Store ainda recusa `0x18` no parser e na aridade derivada: não há emissor nativo de requisição, recepção autorizada ou persistência do novo compromisso. Seu teste de registry explicita essa diferença temporária.

Os dois testes novos do envelope passaram: duas aprovações, zero falhas, 0,01 s; compilação 2 min 40 s, prioridade 19/um job/uma thread, saída 0. Incluem comprimentos/zero, fase fechada e mutações canônicas dos campos assinados, inclusive transposição para `0x17`. Iniciou-se depois, com o mesmo binário e uma thread, a suíte unitária completa do transporte. O teste ajustado do Store e a checagem do daemon com o novo enum permanecem pendentes.

Os cinco testes de chaves/proposta passaram: cinco aprovações, zero falhas, 0,13 s, compilação 1 min 21 s, saída 0, prioridade 19/um job/uma thread. Incluem sensibilidade aos 30 campos de origem e recusa de cada um dos 704 bytes alterados, comprimentos truncados e trailing. Após o término confirmado iniciou-se nova checagem de todos os alvos do daemon com a proposta atual; resultado ainda pendente. Não há compromisso assinado nem sessão de assinatura autorizada por esses testes.

A checagem de todos os alvos do daemon após a ancestralidade das cinco chaves passou: saída 0, 4 min 16 s, 93 warnings em lib test, prioridade 19/um job. Esse resultado antecede a proposta de acordo descrita a seguir e não executa a integração Noise ampliada.

Proposta unsigned do grafo adicionada em `graph_proposal_v22.rs`, derivada do vínculo nativo de chaves/templates e produzida no Stage12. Seus 704 bytes fixam chain/rota/sessão/termos, roster/direções, hashes dos dois pacotes canônicos, cinco templates, seis pontos do grafo (incluindo T e U), seis parâmetros de recuperação e hash da política de compensação. O digest tem domínio próprio; a conferência do peer exige igualdade com os bytes reconstruídos localmente. Não há construtor público de proposta a partir de bytes alegados pelo peer. Isso não autentica identidades nem substitui o compromisso bilateral assinado.

O registro DSC1 permanece inalterado: a nova proposta ainda não é transmitida nem assinada pelo runtime. Dois testes adicionais verificam tamanho/formato, alteração de cada byte, truncamentos/trailing e sensibilidade a 30 mutações dos campos de origem. A execução dos cinco testes `graph_signing_keys_v22::tests` está em andamento, um job/uma thread, prioridade 19. Formatação passou; a ligação da proposta ao daemon requer checagem após essa execução.

As três regressões `graph_signing_keys_v22::tests` passaram: 3 testes, zero falhas, 0,01 s; compilação 56,95 s, saída 0, prioridade 19, um job/uma thread. A primeira tentativa havia encontrado E0308 apenas na fixture (`Amount::from_noms` retorna Result); a taxa agora é validada antes de construir os templates de teste. Após o término confirmado, iniciou-se somente `cargo check --offline --locked -j1 -p dom-interopd --no-default-features --features production --all-targets` para validar a ligação Noise/Stage12, ainda pendente.

Ancestralidade pública de cinco chaves adicionada em `xmr-refund-policy::graph_signing_keys_v22`: revalida os dois offers em ordem de roster, chain/rota e direções complementares, preserva os pacotes canônicos/PoPs e as chaves individuais, e agrega os cinco excess/offsets no módulo nativo. `bind_templates` exige escopo chain/sessão/termos e igualdade de kernel/offset em cada transação unsigned, fixando os cinco hashes canônicos. A consulta de chave exige participante, etapa e hash exatos. Esses tipos são evidência de construção, não identidade autenticada nem autorização do Store.

Noise usa agora esse material nativo, em vez de descartar as contribuições individuais depois de calcular as somas. Stage12 vincula as chaves aos templates produzidos pelo construtor C/D e guarda ambos num único objeto de cache. A guarda de grafo completo continua ativa. O teste Noise nativo foi ampliado para conferir os dois pacotes canônicos nas duas visões; sua execução ampliada ainda está pendente.

Três testes unitários novos cobrem seleção de participante/etapa/template, recusa de mutações de excess/offset/assinatura/número de kernels e recusa de template econômico modificado. A fixture privada não possui prova BP nem autoridade de identidade e valida apenas esse mapeamento. Formatação e checagem do diff passaram; `cargo test --offline --locked -j1 -p xmr-refund-policy --lib graph_signing_keys_v22::tests -- --test-threads=1` está em andamento, prioridade 19. A ligação atual no daemon ainda requer checagem própria após esse teste.

O módulo completo `production_child_router::route_tests_v4` passou com o binário atual: nove testes, zero falhas, 124,97 s, prioridade 19/uma thread, saída 0. Inclui as 16 combinações com filhos instrumentados e os 32 casos de reabertura do coordenador SQLite (duas posições por combinação), além dos três casos recebidos. Nenhum trace foi exportado e nenhum teste pesado foi iniciado em paralelo.

Para a próxima ligação de assinatura XMR, a ancestralidade V18 também não pode ser usada diretamente: `BootstrapKeyAuthorityV18::key` possui três slots (Funding, ClaimAdaptor, Refund) e a reconstrução exige `DOM_NATIVE_BOOTSTRAP_POLICY_V17`. As cinco contribuições do grafo V22 precisam de compromisso bilateral próprio e de revalidação nativa C/D; aceitar RefundAdaptor somente no match genérico não resolveria ancestralidade, proveniência nem sessões auxiliares. Esse trabalho permanece pendente, sem autorização de funding antecipada.

A execução conjunta filtrada de lib/bin terminou com saída 0: os três testes adaptados de mesma-família passaram e os dois testes de usage (V3 e V4) passaram, todos em 0,00 s. Compilação 7 min 09 s, 49 warnings na lib e 92 em lib test. Os totais foram separados por binário: 3 casos na lib, 2 em main; não é execução da suíte completa. Em seguida iniciou-se, isoladamente e com o mesmo binário recém-compilado, todo `production_child_router::route_tests_v4`, incluindo a reabertura real do coordenador com filhos instrumentados.

A leitura da fronteira de assinatura confirmou lacunas ainda ativas no grafo XMR: `require_operational_refund_template_provenance` exige input igual ao output BP da própria sessão, e `validate_operational_signing_inputs` admite apenas Funding/Refund simples e ClaimAdaptor com ponto. O binder genérico usado por `production_xmr_round_runtime_v12` não autoriza RefundAdaptor. O suporte do agregador a RefundAdaptor não equivale a admissão nativa desse round. Nenhuma dessas proteções foi relaxada; faltam as autoridades próprias do grafo para completar a ligação ao daemon.

A repetição dos testes de rede com a preparação de identidades/bancos anterior aos sockets passou: três testes, zero falhas, 81,57 s; compilação 8 min 42 s, 92 warnings, saída 0, prioridade 19, um job/uma thread. A rejeição por autenticação do peer incorreto foi mantida. Isso confirma esta execução, não elimina a disputa por portas com processos externos nem garante os prazos sob qualquer carga.

Recebido e lido integralmente `tres-testes-mesma-familia.rs` (141 linhas). Seus três casos foram adaptados em `production_route_same_family_v22_tests.rs`, incluído pelo módulo de testes existente. Os nomes agora descrevem asserções reais: claim/observação Pending com o dono correto, materialização de Refund sem acessar a outra posição e reconstrução do roteador preservando os donos. As sequências completas de chamadas são conferidas. Não alegam finalidade, execução do aborto ou crash recovery persistente. O patch anexo de 529 linhas continua sendo a cópia exata do arquivo anterior à inclusão desse módulo.

Formatação e checagem do diff dos três testes passaram. Após o término confirmado dos testes de rede, iniciou-se somente `cargo test --offline --locked -j1 -p dom-interopd --no-default-features --features production --lib --bin dom-interopd -- same_family_v22_tests production_usage_tests --test-threads=1`, prioridade 19. A execução dos três novos casos e do usage ainda está pendente; o resultado de rede anterior não cobre o novo módulo.

O complemento `apenas-testes-mesma-familia.patch` foi lido integralmente. Seu único arquivo já existe byte a byte nesta árvore: `production_route_router_tests.rs`, blob Git `4fc0f0a7431bcdf0a19d239137db56e47d788ae4`. Não foi reaplicado. Ele cobre roteamento com filhos instrumentados e retomada do coordenador; não contém os três testes adicionais de finalidade/aborto anunciados no LEIA-ME e não é prova de execução nas chains.

Atualização dos portes: `route_matrix_v22_tests` passou, 5 testes/zero falhas (compilação 7 min 52 s, 92 warnings). O mesmo binário recém-compilado executou os seis testes dos encoders BTC/EVM: seis aprovações/zero falhas. Execuções sequenciais, prioridade 19; esses resultados não demonstram os ciclos econômicos das 16 rotas.

A execução isolada dos três testes `production_relay_network_runtime::tests`, uma thread, terminou com duas aprovações e uma falha em 118,39 s. No caso do peer incorreto, o respondedor retornou `AcceptDeadlineElapsed` em vez de chegar à autenticação. A fixture iniciava o prazo de aceitação antes de concluir a reabertura criptografada da identidade e banco da contraparte. A preparação das duas identidades/bancos foi movida para antes do início de cada par de conexões; nenhum limite de produção ou asserção de autenticação foi relaxado. A repetição com fonte atual está em andamento, ainda sem aprovação. A serialização do patch permanece restrita ao módulo.

Pendentes nesta revisão: execução do teste do usage no binário e validação específica do novo produtor de testemunha; não confundir a checagem de compilação com execução dessas fronteiras.

A checagem dos portes selecionados passou: `cargo check --offline --locked -j1 -p dom-interopd --no-default-features --features production --all-targets`, saída 0, 2 min 23 s, prioridade 19, 92 warnings em lib test. Inclui compilação dos encoders/usage, testes serializados de loopback, matriz e produtor `compensation_funding_witness_v22`; não é execução dos testes novos nem de todas as integrações. Após seu encerramento, iniciou-se somente `route_matrix_v22_tests`, um job/uma thread, prioridade 19. O usage V4 foi ajustado para mostrar `--create` como opcional e não alegar execução completa das 16 rotas.

Revisão de `$HOME/v22-do-outro-agente/LEIA-ME.md` concluída integralmente, sem interromper o Cargo ativo. O primeiro patch foi portado sem commits: `ConfigurationDetail`, mensagens V4 e encoders canônicos EVM/BTC junto aos decoders, com testes e runbook. O root universal exigiu aplicação contextual por conter alterações locais. Os relatos de testes/estado da outra árvore não foram importados como evidência desta revisão. O segundo patch adicionou a serialização dos três testes de portas de loopback; coordena esse módulo, não processos externos.

Do terceiro patch foram incorporados os cinco testes da matriz de topologia e uma descrição precisa do limite: aceitar uma topologia não prova funding/claim/recovery em todas as 16 rotas. O dispatcher que reaproveita uma única share de refund para três rounds XMR não foi importado: esta árvore possui cinco contribuições distintas e sessões auxiliares nativas. Os três testes de ciclo de vida citados no LEIA-ME não aparecem nos cinco patches; foi pedido o arquivo complementar sem bloquear o restante. O caminho de admissão D do quarto patch não substituiu o nosso; foram preservados a derivação centralizada, roster/cerimônia D separados e o pump de recovery já integrado.

Do quinto patch foi portado `compensation_funding_witness_v22`: a autoridade usa seu getter de observação fresca já validada, exige hash de 32 bytes e igualdade com o txid XMR admitido, e emite apenas o marcador de escopo. A condição de consenso/certificado permanece obrigatória. O binder M.8 alternativo não substituiu o condutor pós-M.8 existente. Os demais símbolos principais de funding/claim já encontrados nesta árvore foram preservados.

A reprodução solicitada `cargo test --offline --locked -j1 -p dom-interopd --no-default-features --features production --test relay_worker prepared_operational -- --test-threads=1` passou: quatro testes, zero falhas, 304,99 s, compilação 2 min 13 s, 49 warnings na lib, prioridade 19, saída 0. Inclui os dois casos `signing` e `final_refund` relatados como falhos na outra revisão; `Quarantined` não foi reproduzido na árvore atual. Isso não é aprovação de toda a suíte nem prova de correção causada pelos patches. Após o término confirmado, iniciou-se checagem de todos os alvos do daemon com os portes atuais; os novos testes de bundle, usage, matriz e serialização ainda aguardam execução específica.

A checagem anterior do grafo unsigned terminou normalmente com saída 0, 4 min 20 s e 92 warnings em lib test. Foi mantida ativa durante a chegada dos patches; seu resultado não deve ser usado para aprovar os portes posteriores.

A regressão `funding_intent_schema_cannot_override_admitted_facts_or_supply_a_spend` passou: 1 teste, zero falhas, 0,00 s; compilação 19 min 53 s, 92 warnings em lib test, offline, prioridade 19, um job/uma thread, saída final 0. Durante a compilação das dependências foi acrescentada a ligação unsigned descrita abaixo; uma checagem independente dos alvos atuais ainda é necessária. A aprovação do teste continua restrita ao schema, não ao fluxo econômico.

Construção unsigned ligada ao Stage12: ao atingir a barreira XMR depois de C/D, o owner passa as duas formações re-auditadas, os outputs verificados, contribuições públicas Noise, política de compensação, intenção de funding e checkpoint DOM admitido para `XmrRecoveryGraphTemplatesV12::build_with_funding_condition_v22`. Só guarda o resultado após balanços/provas/política nativos e igualdade do hash do refund com o hash admitido. A leitura `xmr_graph_output_v22` reconstitui evidência pública própria sem consumir shares/nonces e confere cápsula/compromisso. O teste C/D foi ampliado para comparar a evidência reaberta.

A guarda `XmrRecoveryGraphRequired` continua ativa mesmo após construir templates: ainda faltam negociação/assinaturas, custódia e readiness bilateral. Não há declaração de grafo operacional, funding ou recuperação pelo daemon. O teste de schema iniciado antes dessa ligação segue na compilação de dependências e não foi reiniciado; a checagem dos patches/formatação passou. A nova construção ainda não tem aprovação de compilação nem execução de integração.

A ligação da intenção de funding ao daemon passou em `cargo check --offline --locked -j1 -p dom-interopd --no-default-features --features production --all-targets`: saída 0, 4 min 19 s, prioridade 19, 93 warnings em lib test. O resultado cobre o parser/binding ao input admitido, instalação no owner Stage12 pelo root e compilação do teste de schema; não executa admissão XMR nem construção/assinatura do grafo. Depois do encerramento confirmado, foi iniciada somente a regressão de schema, com um job/uma thread e prioridade 19.

A regressão `construction_quorum_validation_never_authorizes_an_unbound_spend` passou: 1 teste, zero falhas, 0,01 s após compilação de 2 min 38 s, offline, prioridade 19, um job/uma thread. Em seguida, o mesmo binário recém-compilado executou todos os seis casos de `dom-consensus/tests/xmr_funding_v22.rs`: seis aprovações, zero falhas, 0,05 s. Isso cobre validação de quorum/chaves, recusa do spend não vinculado, certificados, validade temporal e combinação de snapshots. Não valida o caminho completo do daemon.

Foi acrescentado também um teste de schema da intenção de funding: o JSON não pode fornecer hashes/valor admitidos nem um spend digest, e os quatro parâmetros explícitos são obrigatórios quando o campo é usado. Formatação e checagem do patch passaram; o teste de schema ainda não foi executado. Checagem da nova ligação do daemon em andamento, prioridade 19 e um job, depois do término confirmado do teste de consenso.

A reconstrução dos outputs C/D passou em `cargo check --offline --locked -j1 -p dom-interopd --no-default-features --features production --all-targets`, saída 0, 12 min 04 s, prioridade 19, 94 warnings em lib test. Isso compila a ampliação do teste C/D, mas não a executa.

Depois dessa aprovação, foi acrescentado `funding_intent_v22` opcional ao bundle XMR canônico já fixado pelo manifesto: `output_index`, `minimum_confirmations`, `attestors` (chaves SEC1 como arrays de bytes) e `threshold`. Rota/sessão, chain DOM, genesis XMR, setup, txid e valor vêm dos inputs admitidos, não do JSON. O root instala esse draft no owner Stage12 antes da ativação Noise, revalidando o escopo e recusando substituição. O output index é uma proposta pública configurada, não prova de inclusão ou de saída XMR; a futura condição assinada e seu certificado ainda precisam atestar o funding exato. Ausência do campo preserva a recusa de grafo/funding, sem configuração implícita de attestors.

A regra nativa de chaves/quorum foi extraída para `validate_xmr_attestors_v22`, reutilizada pela validação completa sem relaxar seus requisitos. O draft mantém `spend_digest` zero até o construtor nativo vinculá-lo à transação exata; a validação completa/certificado continua recusando esse estado. A regressão `construction_quorum_validation_never_authorizes_an_unbound_spend` cobre essa separação e mutações de quorum/chaves. Formatação e checagem do patch passaram; execução dessa regressão em andamento, um job/uma thread, prioridade 19. A compilação da nova ligação do daemon e a integração com inputs admitidos ainda estão pendentes. Não foram liberados funding, assinatura ou transmissão nem concluído o grafo.

A checagem da projeção pública de setup concluiu com saída 0: `cargo check --offline --locked -j1 -p dom-interopd --no-default-features --features production --all-targets`, 24 min 03 s, prioridade 19, 94 warnings em lib test. O mesmo processo foi acompanhado até saída terminal; esse resultado cobre a projeção admitida e as quatro correções de aliases, mas não executa integração com inputs XMR.

Após essa checagem, o driver C/D foi ligado também à reconstrução de `VerifiedSharedOutputV1`: usa a prova terminal autenticada, o compromisso da declaração e a cápsula exata do journal, revalida pelo verificador nativo e só publica os dois caches depois de ambas as verificações. O teste C/D foi ampliado para exigir o output verificado e conferir compromisso/cápsula. Esta alteração ainda precisa de compilação e execução; não constrói nem assina o grafo completo e não libera funding.

Projeção pública de setup acrescentada: `ProductionXmrGraphSetupV22` nasce de `AuthenticatedXmrSessionBindingsV1` e confere rota, sessão, termos, perna DOM, posição do participante no roster, deployment Monero, valor e ponto T. Preserva setup validado, genesis registrado, ponto U e hash de refund admitido; não abre carteira, RPC ou sidecar e não emite autoridade de funding. O owner Stage12 recebe essa projeção apenas para pernas XMR e confere seu binding com o contexto nativo Noise antes de aceitar contribuições públicas. Não foram inventados attestors nem output index; ainda falta ligar esses dados validados à construção condicional do grafo.

A primeira checagem dessa projeção apontou quatro acessos `.0` indevidos em aliases de arrays de 32 bytes; foram corrigidos. Formatação e checagem do patch passaram. A checagem seguinte permanece ativa, prioridade 19 e um job, aguardando leitura de disco; uma consulta observou oito `rustc` de outra execução. Não houve reinício por timeout nem encerramento de processos externos. A compilação final e o teste de integração com inputs XMR admitidos permanecem pendentes; as aprovações anteriores não cobrem essa projeção.

A regressão `resumed_outbound_never_completes_xmr_from_message_phase_alone` passou: 1 teste, zero falhas, 0,00 s, compilação 7 min 49 s, 93 warnings em lib test. O mesmo processo foi acompanhado até saída 0, offline, prioridade 19, um job/uma thread. A matriz cobre os 256 tipos de mensagem combinados com prova concluída e política XMR; preserva replay das mensagens BP e recusa conclusão XMR por fase da mensagem. Não é um teste de injeção de crash no journal. O binário atual também compila a agregação pública recente, mas a execução da ampliação bilateral dessa agregação continua pendente.

A checagem atual do daemon passou: `cargo check --offline --locked -j1 -p dom-interopd --no-default-features --features production --all-targets`, saída 0, 3 min 36 s, prioridade 19; 93 warnings em lib test. Inclui formação nativa C/D retida pelo driver, decisão compartilhada de retomada, material público agregado pelo owner e compilação das ampliações dos testes. Não executa essas ampliações. Após seu término confirmado, iniciou-se somente a regressão curta `resumed_outbound_never_completes_xmr_from_message_phase_alone`, com um job/uma thread e prioridade 19, acompanhada sem timeout de reinício; resultado pendente.

A regressão `retained_shared_formation_reopens_and_refuses_value_terms_capsule_substitution` passou: 1 teste, zero falhas, 35,38 s; compilação 8 min 17 s, dois warnings em lib test. Foi executada offline, prioridade 19, um job/uma thread, sem Bulletproofs. Acompanhou-se o mesmo processo até o término; leituras de `/proc` mostraram espera por disco e progresso de bytes, com o próprio Cargo detendo o lock do cache. O resultado cobre a versão com ordenação por índice nativo e o Contracts real em perfil EvidenceOnly, não a execução do driver C/D completo.

O owner do daemon agora monta `ProductionXmrGraphPublicMaterialV22` dos dois pacotes autenticados: cinco excesses/offsets agregados pelas operações nativas, inputs/troco/taxa do DOM funder, quatro pagamentos em ordem de política e duas provas públicas de valor. A construção revalida ambos os pacotes no contexto nativo e a retenção permanece em memória, sem ack de grafo durável ou autoridade de funding. A regressão bilateral foi ampliada para comparar as duas visões e recusar auto-substituição de participante; execução dessa ampliação pendente. O decoder foi compartilhado entre verificação e montagem, sem relaxar a validação. Formatação e checagem dos patches passaram; `cargo check` sequencial do daemon está em andamento, sem reinício por timeout.

As duas tentativas de checar a ligação atual no daemon terminaram por timeout 124 aos 90 s: a primeira reportou espera pelo lock do cache Cargo; a repetição offline terminou sem saída de compilação. A consulta aos locks foi somente leitura, sem remover arquivo ou encerrar processos externos. Não há aprovação da ligação atual nem execução da nova regressão da formação. A checagem de integridade do patch (`git diff --check`) terminou com saída 0. A aprovação de 36,03 s permanece restrita ao módulo Contracts/alvos de teste antes da ordenação final das contribuições.

Nova leitura `ContractsSessionStoreV1::retained_shared_output_formation_v22`: audita o transporte e o roster/identidades, exige seis mensagens iniciais autenticadas, revalida commits/reveals e reconstrói `FrozenSharedOutputV1` com os dois PoPs nativos. Confere termos, cápsula, valor e declaração C/D exata; antes dos reveals retorna ausência, sem escrever journal nem gerar shares/nonces. A regressão nova usa o Contracts real em perfil EvidenceOnly, reabre a formação e recusa substituição de valor/termos/cápsula, conferindo head inalterado; execução ainda pendente.

O driver real C/D agora retém essa formação após confirmar a prova de range durável, com o valor fixado pela política; pernas ordinárias não usam essa nova retenção. O teste de bootstrap C/D foi ampliado para conferir valor, sessão e termos da formação. Isso prepara a entrada nativa do construtor do grafo, sem concluir o bootstrap C nem liberar funding. A primeira checagem encontrou e corrigiu uma conversão indevida de chave pública já validada. `cargo check --locked -j1 -p dom-scriptless-store --all-targets` passou em 36,03 s, prioridade 19, dois warnings em lib test; depois foi adicionada ordenação das contribuições pelo índice nativo. A checagem atual do daemon cobre essa última alteração e a ligação do driver; ainda não há resultado dela.

A tentativa de executar `resumed_outbound_never_completes_xmr_from_message_phase_alone` terminou por timeout 124 aos 90 segundos, sem saída de compilação ou teste. Usou prioridade 19, um job e uma thread; não gerou evidência de aprovação da extração. O teste nativo anterior permanece aprovado em 626,99 s, mas seu binário antecede essa extração. Não foi iniciada repetição imediata enquanto a execução externa permanece ativa.

O teste ampliado `v22_both_wallets_reopen_payout_proofs_and_five_native_graph_excesses` passou: 1 teste, zero falhas, 626,99 s de execução, após compilação de 1 min 54 s. Inclui as duas carteiras nativas reabertas, pacotes completos e o helper TCP/Noise: duas conexões válidas em Relays reabertos com candidatos idênticos nas duas direções, seguidas da recusa explícita da primeira PoP adulterada pelo peer. Não demonstra construção/assinatura das cinco transações nem claim/recovery econômico pelo daemon. Foi iniciado isoladamente, prioridade 10, um job/uma thread; uma execução externa começou posteriormente, sem ter sido iniciada ou encerrada por esta tarefa.

Depois da compilação desse binário, a decisão comum às branches de retomada `SigningRequest`/`Committed` foi extraída para `resumed_outbound_may_complete_v22`. A regressão nova percorre todos os tipos u8 de mensagem e combinações de prova concluída/política XMR, preservando replay de BP e recusando conclusão XMR por mensagem posterior. Formatação passou; essa extração e seu teste ainda precisam de compilação/execução própria. É uma regressão da decisão compartilhada, não uma injeção de crash no journal real.

A versão ampliada do teste das carteiras compilou em 1 min 54 s, com 92 warnings, após a coerção explícita do erro do helper. A execução nativa está em andamento, ainda sem aprovação. Esse resultado de compilação inclui também as duas guardas adicionais de retomada do bootstrap; não exercita por si só as branches `SigningRequest`/`Committed` posteriores à prova C.

A repetição da checagem encontrou E0277 na conversão de `Box<dyn Error + Send + Sync>` do helper threaded para `Box<dyn Error>` do teste original. Foi aplicada coerção explícita, preservando a causa. Após consulta confirmar ausência de Cargo/rustc/testes, iniciou-se isoladamente a execução ampliada de `v22_both_wallets_reopen_payout_proofs_and_five_native_graph_excesses`, com prioridade 10, um job e uma thread. Ainda em compilação, sem resultado de execução; as aprovações anteriores desse teste não incluem o helper Noise novo.

O teste nativo das duas carteiras foi estendido novamente (execução ainda pendente): após reabrir os journals, passa as duas ofertas reais para TCP/Noise com identidades Contracts próprias, duas conexões válidas sobre Relays reabertos e uma terceira com a primeira PoP adulterada depois da validação local do peer malicioso. Exige candidatos byte a byte idênticos nas duas direções e recusa explícita no caso adulterado. Esse teste não substitui a construção/assinatura dos kernels nem prova resultados econômicos pelo daemon.

Revisão das saídas de retomada encontrou duas conclusões antecipadas no bootstrap: `SigningRequest` e `Committed` com mensagem posterior aos tipos 1–10 e prova C concluída. Ambas agora exigem ausência de política XMR antes de marcar `complete`, assim como o caminho sem outbox; caso XMR retorna `XmrRecoveryGraphRequired`. Formatação e `git diff --check` passaram. A checagem limitada terminou por timeout 124 após progresso da biblioteca, sem comprovar compilação completa; repetição com cache em andamento. Não foi executado outro teste pesado junto à compilação externa.

A regressão existente `cancelled_scope_shares_one_noise_connection_and_restarts_without_cross_delivery` passou novamente com o binário que inclui as alterações de recusa/Hello: 1 teste, zero falhas, 22,06 s. Foi executada depois das duas novas regressões, sem recompilação e com prioridade 10/uma thread. Confere a entrega normal C/D, retomada sem entrega cruzada e recusa do peer legado; não habilita ofertas GraphOffer válidas.

Regressões Noise adicionais: `graph_v22_unnegotiated_frames_preserve_pending_relay_after_reopen` passou (1 teste, zero falhas, 21,88 s; compilação 2 min 32 s, 92 warnings). O caso usa TCP/Noise e identidades Contracts reais, recusa anúncio XGO1 não suportado e frame GraphOffer fora da etapa negociada; após reabrir o Relay, confere bytes C/D pendentes e cursores zerados. A negociação Hello agora compartilha um codec canônico com a regressão `hello_v22_requires_exact_capabilities_scope_and_limits`, também aprovada (0,00 s), cobrindo as três modalidades, todas as mutações de byte, truncamentos, bytes extras e escopo D estrangeiro. Execuções sequenciais, prioridade 10, um job/uma thread.

Corrigidos os caminhos de recusa: falhas no Hello enviam recusa explícita antes de retornar, e as operações falíveis do envio/recebimento da oferta estão dentro de uma closure para que a validação do respondedor não pule esse envio. Formatação e `git diff --check` passaram. O novo teste de rede cobre negociação/etapa inválidas, não o ramo de validação de uma oferta negociada completa; a transmissão bilateral válida dos pacotes nativos e sua integração ao grafo ainda precisam de evidência própria. O bloqueio `XmrRecoveryGraphRequired` permanece; não há demonstração de swap completo por esses testes.

As ligações da oferta XMR ao Noise e ao loop real passaram em `cargo check --locked -j1 -p dom-interopd --no-default-features --features production --all-targets`: saída 0, 58,03 s, prioridade 19. Permanecem 92 warnings no alvo lib test. Uma tentativa foi recusada preventivamente pelo mecanismo de segurança por ausência de confirmação de término do Cargo anterior; uma consulta atual comprovou ausência de Cargo/rustc/testes/linker, e a execução isolada foi autorizada em seguida. Não houve contorno da proteção nem processo externo encerrado. Os testes específicos de negociação/transmissão/retomada Noise da oferta ainda precisam ser implementados e executados.

A repetição de `v22_both_wallets_reopen_payout_proofs_and_five_native_graph_excesses` com o pacote público completo passou: 1 teste, zero falhas, 402,90 s de execução, compilação 2 min 11 s. Cobriu oferta de funding, compromisso reconstruído de dados públicos, pacote completo, retomada dos mesmos bytes e mutações de rota/chave/offset/prova/comprimento. Esse binário foi compilado antes das alterações Noise descritas abaixo.

Transporte do pacote em implementação: frame próprio `GraphOfferV22`, negociação obrigatória `XGO1` no Hello quando habilitado, escopo C/D preservado e validação do pacote contra participantes/direções e termos autenticados. O pacote precede as páginas Relay; frames desse tipo fora dessa etapa são recusados. Os bytes locais retidos são retransmitidos a cada conexão. Não existe ack de aceitação econômica ou durabilidade do grafo nesse frame. O relatório redige o payload no Debug.

O loop real passa a habilitar esse recurso a partir do driver C e do journal local, usando os termos/política retidos. O owner revalida o candidato recebido para a perna exata e o mantém em memória; após crash, a retransmissão recupera o candidato. Isso ainda não constrói/assina os cinco kernels nem altera `XmrRecoveryGraphRequired`. A primeira checagem do componente Noise isolado passou; a checagem das ligações no loop está em andamento. Testes TCP/Noise dessa extensão ainda pendentes.

Pacote bilateral público acrescentado (validação de execução pendente): `XmrGraphOfferV22` reúne a oferta de funding, os dois pagamentos locais, cinco chaves/offsets e cinco PoPs. O decoder limita o pacote a 32.768 bytes e cada payload ao limite de seu tipo, verifica contexto esperado externo, propósitos dos pagamentos, offsets nativos e as cinco provas contra o compromisso reconstruído. Não autentica sozinho o remetente e não concede assinatura/funding; ainda faltam transporte Noise e validação econômica do grafo completo.

`retain_local_graph_offer_v22` monta o pacote somente de registros nativos já retidos, confere binding/capability/roster e igualdade do compromisso com as shares da carteira. O root retém os bytes antes de transferir as shares ao próximo estágio. O journal admite 19 chaves conhecidas e limite por registro de 32.768 bytes, mantendo limite agregado de 131.072 bytes. O teste das duas carteiras foi ampliado com roundtrip/reabertura do pacote e mutações de rota, chaves, offsets, provas e comprimentos.

Após confirmar ausência de outra execução Cargo/teste, foi iniciada isoladamente a repetição de `v22_both_wallets_reopen_payout_proofs_and_five_native_graph_excesses`, prioridade 10, um job e uma thread. Ainda está em compilação; os resultados anteriores não validam esse novo pacote.

A versão ampliada de `xmr_collateral_reservation_restarts_with_exact_inputs_and_change` passou: 1 teste, zero falhas, 43,19 s de execução, compilação de 1 min 11 s, prioridade 10, um job e uma thread. O caso usa carteira cifrada e reserva reais; reabre a mesma oferta pública de funding sob nova lease, recusa oferta sem troco ou com taxa divergente como `IdempotencyConflict` e confere bytes da carteira inalterados após essas recusas. Preserva os casos anteriores de snapshot antigo/banco substituto. A execução foi iniciada após confirmar ausência de outros processos Cargo/teste.

A checagem da integração do compromisso público reconstruível passou em `cargo check --locked -j1 -p dom-interopd --no-default-features --features production --all-targets`: saída 0, 52,66 s, prioridade 19, limite de 90 s. Inclui compilação do teste ampliado, não sua execução; permanecem 92 warnings no alvo lib test. A troca automática via Noise e a formação/assinatura do grafo continuam pendentes.

O compromisso das cinco shares foi adaptado para reconstrução pública por `XmrGraphContributionDigestV22`: chain, rota, sessão parent, termos, participante, cinco chaves/offsets e funding (inputs ordenados, taxa, compromisso de troco). Não inclui mais identificador interno de reserva nem valores individuais de inputs/troco. As cinco PoPs passam a comprometer esse digest público. O teste das duas carteiras foi ampliado para reconstruí-lo a partir da oferta pública de funding, sem consultar metadados privados; execução dessa versão ainda pendente.

Compatibilidade: o domínio/cálculo do compromisso mudou nesta versão em desenvolvimento. Registros anteriores de `xmr-graph-keys-v22`/provas não são migrados ou sobrescritos automaticamente: divergência é recusada. Não foi implementada migração de cerimônias pré-existentes nem autorizado apagar seus estados. Não houve alteração de segredo, share privada ou regra de funding para contornar a divergência.

A regressão `public_digest_binds_each_contribution_without_wallet_private_metadata` passou: 1 teste, zero falhas, menos de 0,01 s, compilação 23,45 s, prioridade 19 e uma thread. Confere canonicalização da ordem de inputs e separação por escopo, taxa, lista de inputs e presença de troco/funding. Checagem da integração atual no daemon em andamento.

A regressão `all_policy_payout_offers_roundtrip_and_refuse_scope_or_encoding_mutations` passou: 1 teste, zero falhas, 1,25 s, com compilação de 5,62 s. Cobre os quatro propósitos, codificação canônica, escopo, direção dos pagamentos de sucesso, termos, limites externos e comprimento interno da prova. Não é um teste de transporte bilateral.

Na retomada da oferta de funding, a carteira agora compara os inputs, taxa e compromisso de troco retidos antes de gerar uma prova nova. Divergência retorna `IdempotencyConflict`. O teste nativo de reserva/carteira foi ampliado para recusar ausência de troco e taxa alterada, preservando bytes da carteira, e reabrir a mesma oferta sob nova lease. `cargo check --locked -j1 -p dom-actuator --all-targets` passou em 28,21 s; a execução dessa ampliação permanece pendente.

Revisão do transporte: o scheduler V17 ainda usa arquivos `.local`/`.peer` que exigem cópia externa, enquanto o transporte Noise já multiplexa as sessões C/D. O fluxo XMR completo precisa integrar as contribuições públicas ao transporte autenticado e manter a validação econômica antes de congelar candidatos e autorizar assinaturas; as ofertas locais retidas ainda não satisfazem essa etapa.

A oferta pública de funding e sua integração na carteira/root passaram em `cargo check --locked -j1 -p dom-interopd --no-default-features --features production --all-targets`: saída 0, 20,28 s na tentativa final, prioridade 19. As duas tentativas anteriores terminaram por timeout 124; a última recebeu limite de 90 s e concluiu antes dele. O resultado inclui a compilação do teste ampliado de reabertura, mas não sua execução. A aprovação anterior de 525,04 s continua restrita à versão anterior desse teste, sem a oferta de funding.

Oferta pública de funding acrescentada: `XmrFundingOfferV22` limita a codificação a 16.384 bytes, fixa chain/sessão/termos/participante, exige inputs canônicos sem duplicação e permite inputs/troco/taxa somente ao DOM funder. Não publica valores individuais nem aberturas dos inputs. A prova do troco é nativa; propriedade/presença dos inputs e balanço completo continuam obrigações do owner, grafo e gate. A carteira reconstrói a reserva e reutiliza a prova retida; o root retém `xmr-funding-offer-v22`, com 18 chaves conhecidas no journal. Ainda não há transporte bilateral dessa oferta.

A regressão `public_funding_offer_refuses_foreign_scope_nonpayer_inputs_and_malformed_lengths` passou: 1 teste, zero falhas, 0,01 s, após compilação de 36,16 s, prioridade 19, um job/uma thread e limite de 45 s. Inclui escopo estrangeiro, inputs do não pagador, duplicação/ordem, taxas inválidas e comprimentos malformados. O teste pesado das duas carteiras foi ampliado para comparar inputs, taxa, troco e bytes retidos da oferta; a versão ampliada ainda não foi executada. A checagem de integração está pendente após uma tentativa terminar por timeout 124 nas dependências, sem erros reportados; repetição limitada iniciada.

O teste `v22_both_wallets_reopen_payout_proofs_and_five_native_graph_excesses` passou: 1 teste, zero falhas, 525,04 s de execução, após compilação de 2 min 07 s. Foram usados owners C/D nativos, as duas carteiras cifradas e o journal real. O caso conferiu as cinco equações públicas de cada participante, reserva do DOM funder, os quatro pagamentos locais distribuídos entre as carteiras, provas de posse, recusa de substituição C/D e retomada das mesmas provas/compromissos sob nova lease. Também verificou consumo único das shares parent e recusa de novas provas após esse consumo. Não comprova assinatura dos cinco kernels, troca autenticada com o peer, funding em rede, claim ou recuperação não cooperativa pelo daemon.

Após confirmar o término da execução externa e a ausência de outros processos Cargo/teste, foi iniciado isoladamente `cargo test --locked -j1 -p dom-interopd --no-default-features --features production --lib v22_both_wallets_reopen_payout_proofs_and_five_native_graph_excesses -- --test-threads=1`, com prioridade 10. A execução ainda não tem resultado. O caso cobre os dois participantes com owners C/D nativos, carteiras cifradas, reserva real, equações das cinco shares e retomada das provas; não transmite fundos nem demonstra claim/recovery completo pelo daemon.

A regressão `five_proofs_refuse_stage_digest_and_roster_substitution` passou: 1 teste, zero falhas, 0,03 s de execução; compilação 17,18 s. Comando limitado a 45 s, prioridade 19, um job e `--test-threads=1`. O caso valida as cinco provas nativas e recusa troca de etapas mesmo com chaves iguais, substituição do compromisso, roster estrangeiro, truncamento e bytes adicionais. Não executa Bulletproofs nem substitui o teste pesado de reabertura das duas carteiras, ainda pendente.

A integração atual no daemon passou em `cargo check --locked -j1 -p dom-interopd --no-default-features --features production --all-targets`, saída 0, 10,85 s na repetição com cache. Foi usada prioridade 19 e limite de 45 s, sem execução de testes. A tentativa anterior chegou a imprimir `Finished` em 37,04 s, mas retornou timeout 124; somente a repetição com saída 0 é considerada aprovada. O resultado cobre a compilação do runtime, das provas de cinco shares, dos limites do journal e do teste das duas carteiras. Permanecem 92 warnings no alvo lib test. A execução desses novos testes e a demonstração econômica pelo daemon continuam pendentes.

As checagens recentes passaram: `cargo check --locked -j1 -p xmr-refund-policy --all-targets` em 3,71 s e `cargo check --locked -j1 -p dom-actuator --all-targets` em 23,31 s. Ambas usaram prioridade 19 e limite de 45 segundos, sequencialmente, sem execução de testes. A primeira tentativa limitada do módulo de política terminou por timeout (124) durante a preparação das dependências; a repetição aproveitou o cache e concluiu. Esses resultados cobrem a compilação das novas ofertas, das cinco provas e das contribuições locais da carteira. Não cobrem a compilação das alterações do daemon nem a execução dos testes. Permanecem três avisos de API depreciada em `dom-scriptless-crypto`.

Provas das cinco shares (ainda sem compilação/execução): `XmrGraphKeyProofScopeV22` reconstrói cinco statements nativos separados por etapa, vinculados ao compromisso público completo, chain, sessão, termos, direção e roster autenticado. O verificador exige exatamente cinco provas, sem contagem fornecida pelo peer. O teste usa deliberadamente chaves iguais para exigir que a troca entre etapas seja recusada, além de mutações de compromisso, roster e comprimento.

A carteira produz essas provas sem exportar shares e revalida bytes retidos sem regeneração. O root retém `xmr-graph-proofs-v22` antes de entregar as shares aos próximos estágios; o journal admite agora 17 chaves conhecidas e exige comprimento exato para esse novo registro. O teste das duas carteiras confere provas idênticas após reabertura, recusa bytes alterados/truncados e impede geração nova após consumo das shares. Provas de posse não autenticam o peer nem provam balanço, segurança do funding ou conclusão do swap. Continuam pendentes a troca autenticada das contribuições e a composição/validação dos cinco kernels.

A leitura de material público em um owner já aberto agora aplica os mesmos limites da retenção e da auditoria de reabertura. Foi acrescentado um teste unitário para o comprimento exato de 32 bytes do compromisso das shares e os limites dos quatro pagamentos. O teste de decodificação das ofertas também passou a mutar o comprimento interno da prova nativa, além do comprimento externo do pacote. Formatação e `git diff --check` passaram; esses testes novos ainda não foram executados.

Uma tentativa de `cargo check` foi interrompida por esta tarefa (código 130, sem resultado de compilação) ao confirmar que uma nova execução externa pesada havia começado após a anterior terminar. Não foi encerrado nenhum processo externo. A compilação das alterações mais recentes permanece pendente; não confundir essa tentativa com as checagens aprovadas abaixo.

A repetição isolada de `v22_xmr_collateral_proof_restarts_without_authorizing_funding_before_recovery_graph` passou: 1 teste, zero falhas, 1.774,61 s. Esse resultado valida a prova bilateral C, sua reabertura e a recusa de funding antes do grafo de recuperação; não valida as alterações posteriores de ofertas de pagamento e cinco shares nem o swap completo.

Foram acrescentadas cinco contribuições locais opacas da carteira (funding, claim, cancel, refund e compensação), compostas com as capabilities nativas C/D e offsets separados por propósito. O root retém o compromisso público e mantém as shares sob custódia; não há ainda oferta autenticada ao peer, composição completa dos kernels ou autorização de funding. O teste novo `v22_both_wallets_reopen_payout_proofs_and_five_native_graph_excesses` verifica as equações públicas de ambos os participantes e a reabertura das carteiras/provas; sua compilação e execução permanecem pendentes.

A revisão do journal identificou um teto antigo de 11 registros, anterior às novas chaves XMR. O teto foi atualizado para as 16 chaves explicitamente permitidas, mantendo os limites de bytes, e o compromisso `xmr-graph-keys-v22` passou a exigir exatamente 32 bytes tanto na retenção quanto na auditoria de reabertura. O teste de carteira inclui recusa de compromissos com 31 e 33 bytes. Essa correção ainda aguarda validação compilada. Um teste pesado externo foi confirmado ativo; nenhuma segunda carga pesada foi iniciada por esta tarefa.

Material público dos pagamentos (alterações posteriores à última compilação, ainda não validadas em execução): `XmrPolicyPayoutOfferV22` codifica até 4.096 bytes com propósito, chain, sessão, termos, destinatário, valor, output nativo e, para os dois pagamentos de sucesso, PoP de valor/posse. O decoder usa limites antes de ler payloads, revalida a política e as provas e exige bytes canônicos. Não autentica sozinho o remetente nem concede funding. Os valores dos dois pagamentos de recuperação ainda dependem também do balanço nativo do grafo completo.

A carteira passa a produzir esse material por `prepare_xmr_payout_proof_v22` somente depois de autenticar o pin nativo, a abertura cifrada e a capability C com roster completo. Reutiliza os bytes previamente retidos, sem exportar blinding. O root retém as duas ofertas locais no mesmo journal do bootstrap; a reabertura admite somente as quatro chaves públicas conhecidas e seus limites. O enum dos quatro propósitos foi movido para a camada de política, com reexport compatível pelo atuador. Foram acrescentados casos para os quatro propósitos e mutações de escopo/codificação; ainda aguardam compilação e execução após a prova bilateral C já ativa.

A resolução offline completa do lockfile, rustfmt dos arquivos alterados e `git diff --check` passaram. Permanecem pendentes a prova operacional do produtor com carteira real, a entrega autenticada ao peer, a composição dos cinco kernels e o gate do grafo.

A checagem `cargo check --locked -j1 -p dom-interopd --no-default-features --features production --all-targets` passou em 1 min 05 s com as alterações atuais de orçamento, pagamentos e roster. Continuam 92 warnings no alvo de testes; essa checagem não comprova o fluxo econômico. Foi iniciada a repetição isolada de `v22_xmr_collateral_proof_restarts_without_authorizing_funding_before_recovery_graph` após corrigir a expectativa da fixture de taxa; ainda sem resultado.

A regressão `payout_verifier_refuses_foreign_roster_even_when_recipient_and_value_match` passou em 0,03 s (compilação 1 min 03 s). O teste prova que a PoP adversarial é válida no roster substituto, conserva os bytes canônicos do statement e ainda assim é recusada pelo verificador econômico; a prova no roster original continua aceita. A checagem de produção completa foi iniciada em seguida, sem outro teste pesado concorrente desta tarefa.

Execução dos novos testes de carteira: `cargo test --locked -j1 -p dom-actuator --lib wallet::funding_v16::xmr_tests -- --test-threads=1` passou: **3 testes**, zero falhas, 51,76 s de execução (compilação 1 min 35 s). O caso nativo verificou as aberturas de troco/refund do DOM funder, escopos separados, reserva de colateral mais taxa, conservação do valor, reabertura dos mesmos inputs e troco sob nova lease, recusa de snapshot anterior aos pins e de banco substituto e recuperação com os owners originais. Isso não prova ainda o lado XMR funder, a formação dos cinco kernels ou o swap completo.

Foi iniciada em seguida, isoladamente, a regressão `payout_verifier_refuses_foreign_roster_even_when_recipient_and_value_match` do verificador econômico. Ainda sem resultado.

Checagem isolada do atuador: `cargo check --locked -j1 -p dom-actuator --all-targets` passou em 6,95 s depois de corrigir um acesso a campos privados. A derivação dos escopos de pagamento agora pertence ao próprio `DomSessionBindingV1`, permanece interna ao crate e valida parent, política e destinatário; os campos privados não foram expostos. Essa checagem inclui a compilação dos testes do atuador, não a execução.

Após confirmar que os processos Cargo externos tinham terminado, foi iniciada apenas `cargo test --locked -j1 -p dom-actuator --lib wallet::funding_v16::xmr_tests -- --test-threads=1`. Resultado ainda pendente. A compilação de produção completa e os testes de prova/roster ainda precisam ser repetidos com as alterações recentes.

Resultado da prova bilateral C: `v22_xmr_collateral_proof_restarts_without_authorizing_funding_before_recovery_graph` terminou com **falha** após 1.804,80 s. As asserções anteriores confirmaram ambos os owners em `OutputFinalized`, revisão 17, e a recusa de funding sem grafo. A primeira prova reaberta foi verificada no valor do colateral. A falha veio depois: o teste tentou construir um orçamento V17 com a taxa 10 da fixture, e esse construtor recusou `fee ceiling cannot cover recovery`. Não houve sucesso do teste completo nem comparação final dos dois digests.

A expectativa foi corrigida para exigir essa recusa V17 e testar também que a prova XMR não aceita o principal sem margem/taxas; a mutação de valor +1 continua presente. Os testes novos de orçamento tinham a mesma expectativa incorreta e foram ajustados: o caso ordinário separado usa teto suficiente para o orçamento nativo. Não foram alteradas as regras de taxa nem de verificação da prova. Reexecução pendente.

A resolução completa de dependências `cargo metadata --locked --offline --format-version 1` passou com o lockfile atual. As checagens de formatação e diff também passaram; ainda não há compilação das alterações de carteira/pagamentos/roster posteriores ao início daquele teste.

Pagamentos XMR na carteira (compilação e testes pendentes): `authenticate_xmr_payout_face_v22` autentica o compromisso, valor, destinatário e termos da política contra uma abertura já existente na carteira criptografada. Principal, troco de sucesso, refund e compensação recebem escopos separados no journal nativo do atuador, derivados do parent e do propósito; não são sessões de assinatura DSC1 nem substituem C/D. Reutiliza a sequência nativa preparação → pin criptografado → ativação. Não cria aberturas ausentes. O runtime verifica os dois pagamentos do participante local antes de reservar colateral.

O teste de carteira/reserva foi ampliado para conferir os dois escopos locais, compromissos exatos e reabertura sob nova lease. Inclui restauração da carteira anterior aos pins, recusa de banco substituto mesmo com parent copiado e recuperação ao voltar aos owners originais. Os resultados desses testes continuam pendentes. Ainda é necessário provisionar/negociar as aberturas antes de congelar a política, formar as cinco contribuições e conectar o grafo ao F6/F7; o caminho F6 genérico não foi declarado equivalente ao grafo XMR.

Revisão das provas dos pagamentos: `require_payout` agora verifica o roster completo retido no contexto nativo da PoP, além de destinatário, índice, chain, sessão, termos, valor e compromisso. O novo método `SharePoPStatementV1::require_authenticated_roster_v22` compara o digest do conjunto ordenado com os participantes autenticados; não altera os bytes canônicos nem concede autoridade de assinatura. O teste adversarial constrói uma prova criptograficamente válida sob outro roster, preservando destinatário e todos os bytes públicos do statement, e exige recusa no verificador econômico. A formatação e `git diff --check` passaram; compilação e execução desse caso ainda estão pendentes.

Durante a prova bilateral C foi observado outro `cargo test --lib` iniciado por uma tarefa externa do Claude. Esse processo não foi iniciado nem encerrado por esta tarefa. Aqui permanece apenas a execução bilateral já iniciada; nenhum segundo teste pesado foi iniciado.

Reserva econômica XMR (alterações ainda não compiladas): a carteira oferece `prepare_xmr_funding_inputs_v22`, revalida a política contra os termos congelados e reserva `collateral_noms()` mais a taxa de funding limitada por `dom_max`. A seleção, a identidade da reserva, a abertura do troco e a retomada continuam no mesmo mecanismo nativo. A API ordinária recusa XMR sem política antes de reservar inputs. O root chama essa API com a política do owner D e deixa de produzir a oferta ordinária V17 de três assinaturas para XMR. Isso ainda não entrega os cinco kernels nem os quatro pagamentos comprometidos da recuperação.

Foram acrescentados testes de orçamento (política ausente/trocada, termos/taxa/sessão alterados e separação de V17) e um teste com carteira criptografada, reserva real e retomada sob nova lease, exigindo os mesmos inputs, valor, taxa, troco e bytes de carteira. Estão pendentes de compilação/execução: a prova bilateral C da etapa anterior continua na sessão de teste já iniciada, sem concorrência de testes pesados. `cargo metadata --locked --no-deps --format-version 1`, formatação dos arquivos alterados e `git diff --check` passaram; não substituem compilação ou execução desses testes.

Atualização do colateral C: Stage12 agora seleciona `for_xmr_collateral_v22` para XMR e usa `collateral_noms()` da mesma política autenticada pelo provisionamento D. O construtor revalida a política contra os termos completos e autentica as shares/cápsula de C. Não aplica o orçamento nem os templates ordinários V17. A conclusão isolada da Bulletproof continua recusando funding com `XmrRecoveryGraphRequired`; ainda falta conectar a construção e assinatura do grafo condicionado, não apenas sua validação.

A regressão `native_xmr_d_ceremony_restarts_and_refuses_missing_journal_or_substituted_policy` passou em 379,41 s com os journals Contracts D criados pelo comando de bootstrap real, incluindo ausência de diretório e cápsula substituída. Depois desse resultado, o teste recebeu novos casos para C (shares D/perna errada, termos alterados e recusa de templates ordinários); esses acréscimos ainda precisam de execução.

O `cargo check --locked -j1 -p dom-interopd --no-default-features --features production --all-targets` passou em 35,13 s após corrigir o caminho de `LockMechanism`. Foi acrescentado `v22_xmr_collateral_proof_restarts_without_authorizing_funding_before_recovery_graph`: conduz a prova C bilateral com reabertura em cada tick, compara as provas dos dois participantes, rejeita o valor genérico V17 e exige recusa de funding sem grafo. Sua execução foi iniciada isoladamente; resultado ainda pendente. A rejeição adicional do valor V17 foi acrescentada após a checagem e será compilada pela própria execução do teste.

`cargo check --locked -j 1 -p dom-interopd --no-default-features --features production --all-targets` terminou com sucesso após a correção da retomada dos rounds XMR. A retomada exige agora o mesmo roster, tipo de contrato, sessão, chain, propósito, template, índice de kernel e ponto adaptor. Apenas ausência real permite criar o round; erros do journal não são tratados como ausência. `cargo fmt --all -- --check` e `git diff --check` também passaram.

Continuam presentes avisos de APIs obsoletas, imports e código sem uso. Em particular, o driver do grafo e os rounds XMR ainda aparecem sem chamadores de produção: compilar não comprova a integração. A comparação adicional do roster foi verificada por compilação e revisão; falta um teste comportamental específico de retomada com roster substituído.

Não há evidência nesta validação de execução de nós, transações reais, Kani, bootstrap C/D completo ou sucesso/recuperação nas 16 composições. Esses requisitos permanecem abertos.

Foi acrescentado `DomSessionBindingV1::for_xmr_ordinary_recovery_v22`, utilizado pelo driver de rounds para derivar as sessões de cancelamento e compensação a partir do binding principal e do hash canônico do template. A derivação preserva todos os demais campos de autoridade, recusa chain/sessão/termos divergentes e não emite autorização de assinatura. O signer continua exigindo sua share com o binding auxiliar exato; o refund adaptor U mantém o binding principal.

`cargo test --locked -j 1 -p dom-actuator xmr_auxiliary_binding -- --test-threads=1` executou e aprovou dois testes: separação dos rounds/templates e preservação integral da autoridade; rejeição de substituições e derivação recursiva. Esta API ainda não inicializa D, cria journals auxiliares ou conecta o bootstrap completo ao daemon.

### Implementação seguinte: abertura de D

A derivação de D é compartilhada entre o construtor do grafo e o actuator, preservando o domínio e os bytes V12. `ProductionXmrCancelledBootstrapScopeV22` confere a política contra a chain, sessão, termos e participantes do binding principal; fornece o binding do journal D e aberturas separadas para criação e retomada nativas.

O comando de bootstrap agora chama a cerimônia bilateral de D antes de avançar na cerimônia principal. O plano aceita `xmr_compensation_policy_files`, um array de dois caminhos opcionais na ordem upstream/downstream; por exemplo, `["/caminho/politica-xmr.bin", null]`. Os arquivos contêm a codificação canônica de `XmrCompensationPolicyV11`, validada contra os termos congelados. Quando o array está presente, toda perna XMR exige seu arquivo. A ausência do campo preserva o formato legado e não habilita este bootstrap D nem remove a recusa posterior do grafo XMR incompleto.

Os packets públicos `cancelled-offer-SLOT.bin` e `cancelled-reveal-SLOT.bin` usam os slots existentes (0–3), com assinaturas e retenção nativas. O estágio `cancelled-shares` informa os arquivos da contraparte ainda aguardados. Cada participante mantém `cancelled-SLOT.sqlite` e um vault derivado da sessão D; a montagem de Stage 10 reabre as shares em `_cancelled_shares` sem permitir recriação de material ausente. Ainda falta consumir esse material na prova bilateral de valor de D, nos journals Contracts auxiliares e na composição dos cinco kernels.

O bootstrap de shares exige o binding físico correto do journal antes de acessar o vault. O teste `production_consumer_binding_rejects_foreign_and_development_journals` passou isoladamente, incluindo a reabertura e a ausência de mutação após recusa.

Após a ligação ao coordenador, `nice -n 15 cargo check --locked -j 1 -p dom-interopd --no-default-features --features production --all-targets` passou, assim como formatação e whitespace.

O teste `native_xmr_d_ceremony_restarts_and_refuses_missing_journal_or_substituted_policy` passou isoladamente (338,76 s de execução, um job e uma thread). Executou a cerimônia bilateral nativa em duas pernas XMR e conferiu shares D distintas de C, identidade da share/cápsula após reabertura, exclusividade da custódia, recusa de journal removido sem recriação e recusa de política substituída. Isso não cobre todos os cortes de crash nem prova o fluxo DOM↔XMR completo. A regressão unitária separada da identidade D ainda não foi executada.

A alteração seguinte preserva os dois bindings públicos autenticados no material nativo concluído e os compara também no construtor de prova C existente. O novo construtor de prova D usa a sessão derivada e o valor `cancelled_noms()` da política validada; recusa material C ou de outra perna. Sua compilação e o teste focal ampliado passaram (335,80 s). A recusa explícita adicional de cápsula/direção compilou; a asserção adversarial acrescentada ao teste de custódia ainda não foi executada.

O teste `v22_two_native_d_owners_complete_bp_with_restart_after_every_tick` passou em 1.969,56 s, com um job e uma thread. Usou sessão e shares D nativas, Contracts e Relay reais, reinício após cada tick e reabertura final dos journals. Ambos chegaram a `OutputFinalized`, revisão 17, com o mesmo digest de prova; o verificador nativo recusou valor divergente e continuou aceitando o valor correto. Essa execução utilizou a criação inicial de Contracts na fixture, anterior às ligações de provisionamento/montagem abaixo; não valida essas ligações nem o swap completo.

Durante essa execução foi acrescentado `production_contracts_cancelled_bootstrap_v22.rs`, que prepara a sessão D a partir do leg pai autenticado, da política validada, das shares nativas e da identidade local. Reutiliza a convergência e reautenticação de origem/roster/identidades do Stage 10. O modo de retomada exige uma origem já existente e não recria sessão ausente.

O comando real de bootstrap agora chama essa preparação antes de publicar o artefato final: cria `cancelled-contracts-SLOT` usando a API nativa de criação retomável, com binding próprio e marcadores imutáveis de preparação/conclusão no journal da cerimônia. Após conclusão, somente reabertura é permitida; um artefato já publicado não autoriza regenerar estado ausente.

A montagem de `MountedBootstrapV13` reabre esses mesmos journals e exige ambos os marcadores, a sessão D e seus termos. O Stage 10 reautentica origem/roster/identidade com o owner já aberto e retém a autoridade early junto ao journal, sem uma segunda abertura. A próxima versão do teste transfere esse journal montado ao worker, verifica recusa de pai substituído/sessão ausente sem criar registros e mantém o reinício por tick. O teste de custódia também foi ampliado para remover o diretório Contracts D e exigir recusa sem recriação.

O Stage 12 agora consome o journal D em um worker próprio, sem autoridade F6. IDs de sender/inbox/frames são derivados separadamente dos pins do pai e da sessão D. A prontidão exige D concluído e o relógio durável inclui esse worker. O loop conduz D, faz submit/poll no Relay central e só avança o bootstrap C quando a prova D está concluída.

C e D usam a mesma conexão Noise, com páginas e cursores separados por sessão. Uma extensão autenticada de Hello compromete o ID D antes de qualquer página; divergência/ausência recusa a conexão. Ambos os escopos são trocados em toda conexão, independentemente da fase local, evitando exigir uma troca sincronizada de sessão após reinício. O deadline continua único para toda a conexão.

`cargo check --locked -j 1 -p dom-interopd --no-default-features --features production --all-targets` passou após essas ligações (1m30s), com avisos ainda existentes. O teste `cancelled_scope_shares_one_noise_connection_and_restarts_without_cross_delivery` está em execução; cobre entrega bilateral C/D, reabertura sem reenvio e recusa de peer sem negociação D preservando os bytes pendentes. A regressão de custódia ampliada e a prova bilateral usando o journal provisionado pelo comando ainda aguardam execução. Continuam pendentes o bootstrap econômico C específico de XMR, a composição dos cinco kernels, os rounds de recuperação e a demonstração completa pelo daemon.

Foram identificados timestamps futuros nos fontes importados, que invalidavam repetidamente o cache Cargo. Apenas os mtimes de 1.300 fontes/manifests, 74 entradas adicionais do diretório monitorado pelo build secp e, depois, duas migrações SQL incluídas por `include_str!` em Store foram normalizados. Comparações SHA-256 antes/depois comprovaram conteúdo idêntico. A eliminação completa de recompilações indevidas ainda precisa ser observada.

O primeiro teste do transporte C/D falhou ao inserir o envelope adicional do cenário de downgrade: a fixture usava sequência 1 com predecessor zero, recusado corretamente como `NonContiguousDelivery`. O predecessor foi corrigido para o digest do envelope C anterior, sem mudar a regra do Relay. A repetição passou em 21,90 s: entrega C/D pela mesma conexão, reabertura sem duplicação e recusa do peer sem negociação D antes de confirmar a página C, mantendo seus bytes pendentes. A regressão de custódia com os journals Contracts D provisionados pelo comando foi iniciada em seguida, isoladamente; ainda não há resultado dela.

## Condição que o consenso DOM verifica

Novo kernel `KERNEL_FEAT_XMR_COMPENSATION_V22 = 0x04`, implementado em `crates/dom-consensus/src/xmr_funding_v22.rs`. O valor usa um bit separado da marca coinbase, inclusive para a reinjeção após reorg.

A política comprometida na assinatura dos participantes fixa a chain DOM, sessão, termos, rede/genesis XMR, setup, txid, índice de output, quantidade, confirmações mínimas, pagamento DOM exato, conjunto ordenado de atestadores e limiar. São admitidas de 3 a 7 chaves distintas, com limiar estritamente superior a dois terços. Chaves com a mesma coordenada x, inclusive pontos negados, não contam como membros independentes.

O certificado contém bloco de inclusão XMR, tip XMR, digest da observação, intervalo de validade em alturas DOM e assinaturas Schnorr dos atestadores. O consenso exige o quórum, verifica as assinaturas e os vínculos, confirmações declaradas e intervalo; a amplitude máxima do intervalo é 12 blocos DOM. A validação de blocos usa a altura do bloco que contém a transação. O minerador exclui certificados vencidos nessa altura, e a admissão do mempool remove pacotes que já não podem entrar no próximo bloco antes de verificar conflitos de inputs.

**Modelo de confiança: atestação por quórum negociado.** O consenso DOM não executa RPC, não usa o relógio local e não verifica diretamente PoW Monero ou uma prova criptográfica trustless de output oculto. Confia na veracidade do quórum de atestadores. O produtor nativo de atestado parte de `VerifiedXmrFundingV11`, emitido pelo observador concreto com quórum RPC e view-key/sidecar. Cada atestador precisa executar sua própria observação e possuir sua própria chave provisionada. A implementação não prova que operadores de chaves distintas são entidades independentes.

A compensação assinada sem certificado é apenas um artefato off-chain. Mempool e blocos rejeitam sua admissão. O certificado pode ser renovado sem mudar input, output, prova, taxa, deadline, excess ou offset do pagamento pré-assinado. Remover a condição ou trocar a política invalida a assinatura dos participantes. A compensação tem exatamente um input, um output e um kernel; não admite agregação que altere esse pagamento.

As codificações dos kernels legados permanecem iguais. Nós antigos rejeitam o novo kernel. **É uma alteração de consenso que exige coordenação de atualização da rede. Não foi definida nem implantada uma ativação mainnet.** Pagamentos legados já assinados não ganham essa proteção retroativamente; a abertura de novos caminhos de produção exige o grafo condicionado.

## Integrações presentes no código

| Frente | Implementação desta revisão | Limite restante |
| --- | --- | --- |
| Compensação | Pré-assinatura condicionada, certificado exigido pelo consenso, dupla verificação local, pacote persistido antes do envio, renovação e reconhecimento de transmissão externa | Provisionamento e operação dos atestadores; validação compilada e de rede |
| Recuperação XMR | Reabertura do gate e da custódia nativos, `open_sweep_v12` chamado, loop com os mesmos owners, checkpoint do funding, registro de compensação pelo supervisor | Criação automática inicial do grafo C/D ainda não conectada |
| Revelação/avanço XMR | `VerifiedXmrFundingV11` exigido no caminho de funding antes do avanço da outra perna | Funding não fornece escalar de claim; extração de segredo de gasto CLSAG continua inadmissível |
| M.8 | Consumo do token Contracts, condução do round DOM, exposição persistida e recuperação pelo receptor | Depende das shares e vaults do bootstrap nativo V17; não validado em execução nem em todos os perfis |
| SOL↔XMR | Abertura e execução do sweep com recuperação nativa; seleção de bootstrap por perna | Bootstrap C/D e fluxo completo da composição não concluídos |
| 16 composições | Caminhos existentes preservados e conexões acima acrescentadas | Não há comprovação de complete/abort/restart para as 16 combinações |

O pump XMR divide observação e execução em ticks, renova a lease do supervisor e reutiliza o mesmo sidecar/store do filho. Provas envelhecidas são recusadas e reobservadas. O limite de 60 segundos no observador assíncrono não transforma chamadas bloqueantes ao sidecar em operações preemptíveis; os timeouts concretos e as leases ainda precisam de validação integrada.

## Configuração adicional de reabertura XMR

O bundle Monero aceita `recovery_v22` com `directory`, `sealing_key_file` e `certificate_file` opcional. São caminhos relativos ao diretório de estado, isolados das outras pernas e recursos. `directory` é um componente de diretório de custódia já provisionado. A chave de selagem tem exatamente 32 bytes, acesso restrito ao dono, arquivo regular sem hardlinks adicionais; não pode ser a chave do store XMR nem a autenticação do sidecar.

`certificate_file` contém a serialização canônica pública de `XmrFundingConditionV22` com certificado completo. Pode ser substituído atomicamente quando renovado. O arquivo não autoriza por si só: a custódia verifica quórum, política exata, snapshot XMR observado e altura DOM. Ausência, expiração ou snapshot antigo impedem compensar enquanto se aguarda atualização. Cancelamento e refund mantêm seus próprios caminhos.

Esta configuração **não importa um JSON como gate nativo, não cria C/D e não elimina a recusa do bootstrap incompleto**. A execução só abre quando o mesmo Contracts Store já contém o gate e a custódia autênticos do novo grafo.

## Utilitário offline

Código em `crates/dom-consensus/src/bin/xmr-compensation-v22.rs`. Não há binário pronto. Depois de compilar no ambiente de desenvolvimento:

```sh
cargo build --locked -p dom-consensus --bin xmr-compensation-v22
cargo check --locked -p dom-interopd --features production
```

O utilitário oferece:

```text
xmr-compensation-v22 assemble PRE_TX ALTURA SAIDA ATESTADO...
xmr-compensation-v22 verify TX CHAIN_HEX ALTURA
xmr-compensation-v22 certificate TX CHAIN_HEX ALTURA SAIDA
```

`PRE_TX` é o pagamento nativo pré-assinado sem certificado. Cada `ATESTADO` é uma `XmrFundingConditionV22` canônica com a mesma política e assinaturas sobre o mesmo snapshot/intervalo. `assemble` verifica e agrega o quórum; `verify` valida para a chain/altura informadas; `certificate` exporta a condição pública de uma transação válida para alimentar o runtime. Nenhum comando observa rede, gera uma atestação, transmite uma transação ou sobrescreve um arquivo existente. O produtor de assinatura existe como API de `VerifiedXmrFundingV11`; não há um serviço autônomo de atestadores entregue neste pacote.

## Trabalho ainda necessário

1. Conectar a inicialização bilateral dos outputs independentes C e D, suas provas, cinco contribuições de kernel e pagamentos comprometidos nos termos. O bootstrap V17 atual ainda retorna `XmrRecoveryGraphRequired` em `production_bootstrap_refund_v18.rs` para uma sessão XMR nova.
2. Conduzir os três rounds de recuperação com a share autenticada específica de cada equação, preservando a posse do vault e o histórico de nonces em reinício. O despachante do ZIP recebido usava o mesmo signer para os três rounds; foi preservado apenas como referência inativa em `docs/v22/reference-bootstrap-dispatcher.rs.txt`.
3. Encadear a finalização desse bootstrap à emissão do gate, custódia e execução da rota, além do provisionamento dos atestadores e da publicação dos certificados.
4. Compilar esta revisão e corrigir eventuais incompatibilidades de tipos/features/lints. Executar validações adversariais da nova regra de consenso, renovação, reorg, envio manual e recuperação de crash; validar as 16 composições nas três trajetórias solicitadas.

Não foram removidas as recusas que ainda protegem um caminho sem essa autoridade. Em particular, o domínio XMR não fornece o escalar de um gasto CLSAG: funding verificado autoriza avanço de funding, não fabrica um segredo para claim.
