# Missão persistente desta cópia

Instrução explícita do operador, reiterada em 26/09/2026:

> Criar um mecanismo novo, não melhorar o atual.

- Desenvolver um novo mecanismo de swap atômico DOM↔XMR, seguro e rápido,
  diretamente entre esses dois ativos. Correção explícita do operador em
  26/09/2026: o fluxo DOM↔XMR não deve envolver BTC. A composição mencionada
  anteriormente não autoriza inserir BTC como etapa ou dependência deste fluxo.
- Instrução adicional explícita do operador: toda transação deve passar pelo
  daemon, e DOM deve ser a parte central de todo fluxo. Esclarecimento posterior:
  uma operação entre XMR e BTC deve obrigatoriamente seguir XMR↔DOM↔BTC,
  em ambos os sentidos, sem uma rota direta XMR↔BTC que contorne DOM.
  O requisito esclarecido é a composição das pernas por DOM; não confundir
  essa centralidade com apenas encaminhar chamadas por um processo daemon.
  Hoje XMR usa monerod externo próprio; DOM usa DomNode local dentro do
  executável de teste. Correção explícita posterior do operador: esta missão
  não inclui integração ao `dom-interopd`. Não modificar as outras pernas.
- Esclarecimento do operador: o protocolo completo terá pernas DOM↔Bitcoin,
  DOM↔Solana, DOM↔EVM e DOM↔Monero. A perna DOM↔Bitcoin está praticamente
  finalizada. Esta missão cuida exclusivamente da nova perna DOM↔Monero;
  não remover as outras pernas do projeto nem modificar seu desenvolvimento.
- Reutilizar componentes existentes é permitido. Otimizar o executor, as
  rotinas de armazenamento ou os workflows do protocolo anterior não cumpre
  a missão e não deve substituir o desenvolvimento do mecanismo novo.
- Pesquisar outros projetos de swaps XMR e aplicar as lições ao novo mecanismo.
- O operador aceita aproximadamente dois minutos e informou que as duas horas
  observadas eram durante os testes no GitHub. Medir a execução do mecanismo
  separadamente de compilação, preparação e confirmações; não apresentar o
  tempo de uma simulação como tempo de uma troca real.
- Esclarecimento mais recente: "pode exeder um pouco 2 min sem problemas".
  Tratar dois minutos como meta com alguma margem; não inventar um novo teto
  exato aceito. Essa tolerância de duração não altera por si só as hipóteses
  de segurança ou o prazo original de uma operação já financiada.
- Preparação antecipada de fundos e uma camada adicional de confiança ainda
  não foram aceitas pelo operador; são hipóteses de pesquisa, não requisitos
  aprovados ou justificativas para esconder espera.
- Trabalhar nesta cópia independente, `/home/leonardov/DOM-XMR-Segundos`.
  Outro agente trabalha em `/home/leonardov/Branchcodex-two-workflows`.
  Não alterar essa pasta original nem a cópia `Auditoria somente leitura`.
- O candidato experimental e seu estado estão em `labs/dom-xmr-direct/`.
  Pesquisa, modelos e assinaturas isoladas são etapas intermediárias: não
  declarar a missão concluída antes de demonstrar a perna funcional, sua
  recuperação e a ligação direta entre DOM e XMR, com as limitações e medições reais.
- A auditoria `clsag-lab/EARLY-RECOVERY-AUDIT.md` reproduziu perda de atomicidade
  no perfil curto com recuperação antecipada DOM. A variante atual troca essa
  cápsula por devolução DOM pré-assinada e travada pelo consenso em uma altura,
  **sem divulgar a share DOM** (`clsag-lab/DOM-HEIGHT-REFUND.md`). A recuperação
  XMR e as margens conjuntas continuam pendentes; não declarar esse avanço uma
  solução completa nem reintroduzir a cápsula DOM no mesmo caminho protegido.
- Continuidade após compactação: preservar o cálculo conservador de altura
  em `clsag-lab/src/time_bounds.rs` e a auditoria `TIMING-BOUND-AUDIT.md`.
  A tarefa retomada foi testar primeira abertura XMR inválida, busca de outra
  válida e custo integral dessa busca. O ensaio financiado de seis puzzles
  passou, seguido do perfil de 198 puzzles com duas tentativas. A auditoria
  está em `clsag-lab/RECOVERY-SEARCH-AUDIT.md`; ainda não fornece
  limites temporais adversariais para o protocolo completo.
- O orçamento calculado da busca ordenada exige admitir todos os 99 candidatos
  para o cenário n=198/Q=2^64/erro 2^-128. `AssumedXmrRecoveryWindow` já liga
  esse custo integral à altura DOM sob premissas explícitas. Não reduzir esse
  orçamento ao número de solves de um benchmark. O modo público `solve-session`
  já verifica uma oferta imutável uma vez e atende a busca sequencial; a conta
  `from_session_costs` conserva todos os candidatos. Próximo trabalho de custo:
  medir a busca inteira e avaliar paralelismo limitado.
- A prova de faixa real aceitou um plaintext `q+1` no novo teste Go. O cliente
  não deve tratar prova de faixa como garantia de escalar canônico: a sessão
  rejeita esse candidato, conta seu custo e continua, sem reduzir módulo q.
- O ensaio financiado da sessão única passou com 198 puzzles e duas ofertas:
  recuperação 18,760 s; total 187,035 s, acima de três minutos. Relatórios
  `XMR-RECOVERY-SESSION-198-*` em `clsag-lab/`, inclusive timeout anterior.
  Não confundir esse resultado de duas aberturas com o custo dos 99 candidatos.
- A ordem de divulgação foi separada no cliente local: `open-staged` espera
  SHA-256 reconhecido do setup; `prepare-session` verifica T antes de receber
  puzzles e mantém a sessão durante a recuperação. Prova/aberturas/Feldman são
  conferidos antes de funding. Doze testes Go, onze de prazos Rust e três do
  cliente passaram. `from_prepared_costs` conserva 99 candidatos e divulgação
  original. Aumentar T sozinho ainda não prova margem útil após a preparação;
  falta estabelecer mínimo adversarial, máximo honesto, persistência e justiça.
- O ensaio financiado após essa separação passou: duas ofertas, índices `[1,2]`,
  rejeição de `[1]`, devolução e gasto posterior, 5,288 s de recuperação e
  138,127 s totais. Resultados `XMR-RECOVERY-STAGED-198-*` em `clsag-lab/`.
  Isso não comprova o prazo ou a segurança bilateral: as verificações após
  divulgar puzzles ainda levam mais que o solve observado do perfil curto.
- O benchmark `recovery-audit/lhtlp_full_search_test.go` processou 99 puzzles
  reais, 98 não canônicos e último válido: 64,716 s de busca, 100,578 s total.
  Resultado `FULL-SEARCH-WORKLOAD-RESULT.json`. Partição fixa, sem Fiat-Shamir,
  Feldman/Rust, IPC ou funding: medição de trabalho, não cápsula real aceita
  nem limite de pior caso. Próximo: avaliar vínculo criptográfico direto entre
  ciphertext e ponto público para evitar o custo multiplicado por 99 sem
  abandonar recuperabilidade. Ainda não há backend substituto aprovado.
  A retomada dessa investigação está em
  `labs/dom-xmr-direct/recovery-audit/DIRECT-PLAINTEXT-RESEARCH.md`: começar
  pela álgebra/extração com respostas limitadas e testes de wraparound; não
  confundir a proposta de Sigma com prova de segurança nem reduzir q+1 no
  backend atual. Os processos dos ensaios desta etapa já terminaram com exit 0.
- A direção direta agora tem modelo e experimento real: oito testes Python
  passaram (incluindo falsificações sem limites), 1.155 statements/7.488 pares
  aceitos conferidos; quatro testes Go passaram com 19 mutações adversariais.
  `recovery-audit/direct_dlog.go` usa 256 rodadas de um bit e respostas inteiras
  limitadas, ponto Ed25519 canônico/subgrupo primo, contexto/chave esperados
  do chamador e snapshot próprio. Uma abertura recuperou o segredo: 17,433 s
  geração, 17,236 s verificação, 0,740 s abertura, 36,248 s total positivo.
  Resultado `DIRECT-DLOG-RESULT.json`; `go vet` passou. Sem funding/IPC, sem
  troca do backend anterior, sem prova de segurança completa ou margem temporal.
  Próximo: auditar extração/privacidade, conferir vínculo ao roster/ponto Rust
  e separar processos. `filippo.io/edwards25519 v1.1.0` foi adicionado somente
  ao módulo Go de pesquisa ignorado; reprodução e checksum estão na pesquisa.
- A integração direta entre processos passou: `direct_dlog_cli.go` registra
  modos somente no build explícito; `examples/direct_recovery_bridge.rs` usa
  produtor/verificador separados e devolve a share ao roster Rust. O vínculo
  `XmrDirectRecoveryLink` exige contexto/chave do papel antes de abrir e confere
  roster/papel/binding ao recuperar; offset somente depois. Primeiro ensaio
  42,014 s e último 37,838 s, ambos sem funding e sem timeout externo de 120 s.
  Resultados `clsag-lab/DIRECT-DLOG-IPC-*`. Verificação 17,517 s versus abertura
  1,119 s no último: o perfil curto continua sem margem de segurança temporal.
  Vinte testes Go distintos e 25 Rust passaram; Clippy e go vet passaram.
  `DIRECT-DLOG-AUDIT.md` registra o argumento condicional e obrigações. Próximo:
  ligar custos de uma abertura ao novo vínculo (não reduzir a antiga cápsula
  de 99), estabelecer margem após preparação e testar devolução financiada e
  corridas. Todos os processos próprios desses ensaios terminaram com exit 0.

- O vínculo direto já tem conta temporal própria `from_direct_costs`, sem
  reduzir os 99 candidatos da cápsula anterior. O ensaio financiado
  `xmr-direct-recovery` passou em 52,027 s totais, com 0,673 s de recuperação,
  devolução XMR incluída e gasto dos dois outputs. Relatórios
  `clsag-lab/XMR-DIRECT-RECOVERY-*`. Dezenove testes Rust e Clippy passaram.
  Perfil curto: preparação depois da oferta 33,689 s versus abertura 0,671 s;
  `timing_admission_used=false`, `safe_bilateral_window_proven=false`.
  Próximo: perfil de atraso útil e integração com claims/altura DOM. O resultado
  isolado com moedas de teste não conclui a missão nem prova atomicidade.

- O perfil direto de 10.000.000 quadraturas passou na devolução financiada
  antiga por coinbase em 130,227 s. Setup 31,658 s; abertura 39,536 s versus
  40,376 s após receber a oferta: ainda sem margem. Resultados
  `clsag-lab/XMR-DIRECT-RECOVERY-10M-*`. Perfis limitados a 200.000/10.000.000,
  escolha conferida pelos dois processos, tipo de setup separado do legado.
  Foram aprovados 21 testes Go e a rejeição adicional de T aumentado com h
  antigo (32,447 s); 19 Rust, Clippy e go vet passaram antes da etapa seguinte.
  O trabalho seguinte separa geração do saldo individual e depósito nativo
  na reserva compartilhada; conserva ambos no total e só deposita após a
  verificação pública. Essa separação já passou: `XMR-DIRECT-TRANSFER-10M-*`,
  131,917 s totais, saldo 14,157 s, depósito/maturação 1,009 s. O monerod aceitou
  depósito nativo de 5 XMR de teste, devolução e gasto dos dois outputs.
  Intervalo após a oferta 17,423 s versus abertura 48,179 s. É margem observada
  local, não mínimo adversarial; sem admissão temporal ou DOM no mesmo ensaio.
  Próximo: compor com claims concorrentes e altura DOM, sem transformar tempos
  observados em limites garantidos. Autenticação/persistência continuam abertas.
  Após a separação passaram três testes do cliente, Clippy de todos os targets
  e regressão financiada `height-dom-first` em 34,863 s, incluindo claims e
  gastos posteriores, sem cápsula direta. Resultados
  `HEIGHT-DOM-FIRST-FUNDING-REGRESSION-*`. Todos os processos próprios dessas
  etapas terminaram com exit 0; não há ensaio pendente a reiniciar.

- A integração nativa está sendo executada nos modos `direct-pair-xmr-first`,
  `direct-pair-dom-first` e `direct-pair-abandon`. `DIRECT-PAIR-REGTEST.md`
  descreve as hipóteses condicionais, que não são uma política segura provada.
  A primeira tentativa XMR-first falhou antes do depósito XMR (88,295 s): a
  preparação DOM consumiu o orçamento de 28 s. Evidências
  `DIRECT-PAIR-XMR-FIRST-INITIAL-*`. A correção separa o saldo DOM individual,
  prova e corpo de funding ainda não assinado antes da cápsula; depois dela,
  atualiza a âncora canônica, calcula a altura e assina funding/devolução antes
  de publicar o depósito. Não ampliou a janela. Sucesso devolve o troco XMR ao
  dono original; abandono devolve todos os outputs a esse dono.
  `required_dom_refund_height_for_dom_first` também conta inclusão e observação
  DOM antes da resolução XMR; 20 testes Rust passaram (13 prazos, quatro vínculo,
  três cliente). O ensaio XMR-first corrigido terminou com exit 101 no timeout
  interno de 240 s, sem relatório final nem evidência da etapa exata. PID
  852637 e filhos 852638/852737 confirmados ausentes; evidência preservada em
  `DIRECT-PAIR-XMR-FIRST-SECOND-FAILURE.json`. Não há sucesso integrado provado
  por essa tentativa. O próximo ensaio registra fases antes da espera pela
  altura para distinguir claims, gastos posteriores e teste de conflito.
  Os checks usam recepção completa local,
  não primeira divulgação autenticada; permanecem sem prova de segurança.

- A tentativa instrumentada XMR-first incluiu claims em 79,335 s e gastos
  posteriores em 81,064 s, mas expirou em 240 s minerando para altura 214.
  Evidência `DIRECT-PAIR-XMR-FIRST-INSTRUMENTED-FAILURE.*`. Depois do saldo
  individual, os modos direct-pair agora usam o minerador regtest nativo sem
  carteira de recompensas, evitando KDF/persistência dessa carteira em cada
  bloco; consenso, timestamps, altura e validações permanecem iguais.
  A execução seguinte PASSOU: claims 82,206 s, total 168,836 s, devolução
  tardia rejeitada na altura 214, todos os outputs gastos, cápsula cancelada
  sem abrir. Evidência `DIRECT-PAIR-XMR-FIRST-REGTEST-RESULT.json`, fases,
  watchdog e provenance. Novos asserts também conferem observação da claim
  antes da recuperação adversarial condicional e da devolução XMR até seu
  limite honesto mais resolução. Dezessete testes Rust de vínculo/prazos
  passaram. A sequência session 56401 terminou exit 0: DOM-first (PID 855506)
  passou em 165,979 s, claims 79,088 s; descarte do witness antes de extrair da
  transação DOM canônica, gastos posteriores e devolução tardia rejeitada.
  Evidência `DIRECT-PAIR-DOM-FIRST-*`. Abandono serial (PID 855909) passou em
  204,880 s, acima da meta; preservado em `DIRECT-PAIR-ABANDON-SERIAL-*`.
- A cadeia DOM agora avança durante a abertura XMR no abandono, com um minerador
  nativo sob handle próprio e IPC da abertura em spawn_blocking. Publicar e
  observar a devolução XMR ANTES de aguardar o minerador DOM; não inverter essa
  ordem. A mesma verificação de bloqueio roda em cada altura. O abandono
  concorrente PASSOU em 173,551 s (PID 856707): recuperação 35,499 s, DOM na
  altura 139 ao concluir; XMR devolvido aos 121,739 s; altura DOM 215, devolução
  216, gasto 217. Evidência `DIRECT-PAIR-ABANDON-*`. Os três cenários têm
  resultados completos sob 180 s, não garantia de segurança ou tempo global.
  Após a mudança passaram 20 testes Rust (incluindo os três do cliente antigo)
  e Clippy all-targets. A regressão height-dom-first também PASSOU em 29,106 s
  (PID 857041), com claims, gastos e rejeição da devolução conflitante; evidência
  `HEIGHT-DOM-FIRST-MINER-*`. Session 42445 terminou exit 0. Os grupos de
  processos próprios dessas execuções foram conferidos ausentes. Não há teste nativo de
  disputa após entrega dos adaptors ainda. Próxima etapa: essa disputa, seguida
  da preparação entre participantes, autenticação/persistência/reabertura e
  integração ao dom-interopd; não promover premissas temporais a limites provados.

- Conflitos depois dos adaptors implementados em três modos novos. O controle
  `direct-pair-late-claim-audit` reproduziu perda em 118,846 s: depois de receber
  sua devolução XMR, o peer recebeu deliberadamente uma claim XMR perdedora,
  extraiu seu segredo e tomou DOM na altura 7 (gasto na 8). A recusa temporal
  foi deliberadamente ignorada; não se presume que RPC privado rejeitado seja
  retransmitido pelo monerod. Evidência `DIRECT-PAIR-LATE-CLAIM-AUDIT-*`.
  `AssumedXmrRecoveryWindow::check_initial_claim_release` agora conta a ordem
  inteira e é chamado antes de completar/publicar a primeira claim, além do
  check posterior. Não usar a recusa de iniciação para abandonar a obrigação
  da outra perna depois de pagamento. Não reiniciar o relógio de divulgação.
  Teste de fronteiras, ordem, instante antigo, zero e overflow acrescentado;
  21 testes Rust e Clippy all-targets passaram.
- Respeitando a recusa, `direct-pair-refund-wins` PASSOU em 171,147 s: devolução
  XMR e seus gastos, DOM devolvido na altura 215/gasto 216, só então exposição
  dos replays XMR/DOM, ambos rejeitados. `direct-pair-claim-wins` PASSOU em
  168,811 s, claims 82,534 s; abertura/conferência 34,001 s gerou devolução XMR
  válida, rejeitada por key image gasto; devolução DOM rejeitada na altura 214.
  Evidências nos prefixos correspondentes; notas `DIRECT-PAIR-CONFLICTS.md`.
  Session 38848 terminou exit 0 (PIDs 859866,860128,860572). Esses são conflitos
  ordenados, não teste de mempool adversarial/reorg/finalização. A regressão
  DOM-first com o novo check PASSOU em 168,676 s (claims 81,558 s), preservada
  em `DIRECT-PAIR-DOM-FIRST-RELEASE-CHECK-*`. Session 50864/PID 861059 terminou
  exit 0. Os quatro grupos de processos foram confirmados ausentes; hashes
  dos quatro conjuntos conferem com binários e fontes. Não há ensaio pendente.
  Próxima necessidade concreta: persistir a distinção entre claim
  preparada PRIVADAMENTE e POSSIVELMENTE EXPOSTA antes de qualquer envio, sem
  reabrir prazos nem reutilizar nonces após restart. A reconciliação deve
  observar o vencedor canônico; recusa tardia não apaga segredo já exposto.
  Autenticação, limites temporais fundamentados, preparação independente e
  integração ao dom-interopd continuam pendentes; a missão não está concluída.

- O checkpoint solicitado foi salvo localmente no commit `ffc418e`, sem push.
  Depois dele foi criada a barreira `clsag-lab/src/release_journal.rs`: arquivo
  exclusivo 0600, lock entre processos, política original/ordem/cápsula e
  digest da transação exata, checksum e leitura limitada. Grava e sincroniza
  `ExposurePossible` ANTES da função de envio; repete o check temporal depois
  do disco. Erro de escrita inutiliza o handle. Falha RPC ou cancelamento não
  restaura `Private`; reabertura exige reconciliação. Prazo expirado persiste
  `InitialReleaseClosed`, sem autorizar refund nem esquecer contraparte devida.
  Criação e reabertura sincronizam arquivo e diretório; não recriar registro
  ausente/corrompido como fallback. Exige diretório já durável e confiável;
  não detecta remoção de evento completo por rollback de backup/storage hostil.
- Passaram 32 testes Rust (11 journal, 18 vínculo/prazos, três cliente),
  inclusive quatro processos filhos encerrados sem destructors, lock entre
  processos, cancelamento durante RPC, cada byte corrompido/corte parcial,
  erro de escrita, prazo consumido no disco e relógio recuado. O helper
  crash_child fica ignorado na listagem principal porque é lançado pelo pai.
  Clippy all-targets com -D warnings e formatação também passaram. Evidência
  `INITIAL-RELEASE-JOURNAL-TESTS.json`; notas `INITIAL-RELEASE-JOURNAL.md`.
- A barreira foi ligada à primeira claim dos modos cooperativos direct-pair,
  mantendo a claim devida fora do gate de iniciação. Regressões nativas:
  DOM-first 166,947 s / claims 80,649 s, PID 864259;
  XMR-first revisão atual 166,429 s / claims 78,718 s, PID 865019.
  Ambas reabrem o journal antes/depois do envio, gastam os outputs e rejeitam
  a devolução DOM conflitante. Evidências `DIRECT-PAIR-DOM-FIRST-JOURNAL-*`
  e `DIRECT-PAIR-XMR-FIRST-JOURNAL-FINAL-*`, com hashes conferidos. O ensaio
  XMR-first preliminar PID 863315 (173,535 s / claims 86,789 s) está preservado
  em `DIRECT-PAIR-XMR-FIRST-JOURNAL-*`; usou versão anterior à sincronização
  adicional na reabertura e teve compilação concorrente. Sessions 37087 e
  30795 terminaram exit 0; nenhuma execução precisa ser reiniciada.
- Essa etapa NÃO implementa restart completo: segredos, nonces, material de
  assinatura e solver ainda são efêmeros; journal começa na claim, não antes
  de funding/disclosure. Próximo trabalho concreto: separar envelope imutável
  de claim/extração de `PreparedClaim` (hoje carrega InputOpening privado),
  persistir contexto e adaptors validados sem reabrir rodada de assinatura,
  e testar retomada após primeira perna paga usando extração canônica sem o
  witness original. Depois ligar reconciliação a estado durável anterior aos
  depósitos e à divulgação original. Não tratar `NeedsReconciliation` como
  recuperação concluída, não reiniciar prazos nem reutilizar nonces. Revisão
  criptográfica, limites temporais fundamentados, autenticação, preparação
  independente e integração ao dom-interopd continuam pendentes.

- A separação para retomada foi implementada: `PreparedClaim` agora contém
  `ClaimBody` e abertura privada separados. `into_claim_envelope` consome a
  preparação e descarta InputOpening, retornando `XmrClaimEnvelope` com corpo,
  contexto e adaptor validados. Os verificadores antigos delegam ao mesmo
  ClaimBody. XMR e DomClaimOffer têm to/from_resume_bytes, versões, limite
  64 KiB, digest fixado externamente e roundtrip canônico. Parser revalida
  pontos, escalar, shape, mensagem, prova de faixa/balanço e pré-assinatura.
  XMR usa formato nativo contendo PRE-signature (ainda não gasto válido).
  Não há signing keys/nonces/witness/InputOpening nos envelopes, mas há
  real ring index e vínculo transacional: preservar privacidade dos arquivos.
- `examples/support/claim_resume_bridge.rs` grava registros 0600 em diretório
  0700 e sincroniza antes da primeira claim. Novos modos
  `direct-pair-xmr-first-resume` e `direct-pair-dom-first-resume` pagam a
  primeira perna, descartam objetos originais/witness e lançam worker que
  lê registros e morre exit 73. Um segundo processo restaura os registros,
  extrai da transação nativa observada e grava a contraparte sem nova rodada
  de assinatura. O pai a verifica e publica. A inclusão canônica e os digests
  aprovados ainda são responsabilidade do pai; os workers não consultam
  cadeias por conta própria. Não chamar isso de restart integral do daemon.
- Passaram 43 testes Rust (incluindo quatro novos de envelopes, nove native
  no total) e Clippy all-targets -D warnings. Evidência CLAIM-RESUME-TESTS.json.
  Cenários nativos com moedas próprias offline:
  XMR-first-resume PID 868657 passou em 170,142 s, claims 83,299 s,
  dois workers 0,321 s, devolução DOM conflitante rejeitada em 214;
  DOM-first-resume PID 869602 passou em 171,024 s, claims 83,683 s,
  workers 0,289 s, devolução rejeitada em 215. Em ambos, os três outputs foram
  gastos. Evidências DIRECT-PAIR-XMR-FIRST-RESUME-* e
  DIRECT-PAIR-DOM-FIRST-RESUME-*; hashes conferem com fontes/binário.
  Session 62416 terminou exit 0. Notas completas em CLAIM-RESUME.md.
- Próxima lacuna concreta de retomada: o pai ainda conserva os digests e
  valida inclusão canônica, e a obrigação da contraparte não tem journal
  próprio para envio ambíguo/restart. Persistir manifesto original e estado
  da obrigação antes de expor a primeira claim; vincular ao journal inicial,
  registrar os bytes exatos da contraparte antes do envio, e reconciliar
  inclusões/reorg sem criar outra assinatura ou reiniciar o prazo. Só então
  testar queda após envio sem resposta e reinício do coordenador. Persistência
  anterior a funding/disclosure, solver, autenticação, preparação independente,
  limites temporais, revisão criptográfica e integração ao dom-interopd seguem
  abertas. O mecanismo continua experimental; a missão não está concluída.

- O journal da contraparte já existe em `src/counterpart_delivery.rs`. Guarda
  bytes exatos, digest do manifesto original, primeira claim/bloco/altura e
  cadeia alvo; create_new/0600, lock, fsync arquivo/diretório na criação e
  reabertura. Marca exposição antes do envio, não recria assinatura nem prazo.
  Observações são fornecidas por adaptador confiável: Unknown exige reconciliar;
  InPool/Included só acompanham; AbsentAndUnspent permite mesmos bytes;
  conflito exige resolução. Não tratar not-found isolado como input não gasto.
  Não há cache de inclusão definitivo: nova consulta falha volta a Unknown;
  exposição nunca é apagada. Registro parcial/corrompido não é reparado e
  falha de escrita inutiliza o handle. Armazenamento hostil/rollback completo
  continua fora do modelo; observações do enum não são provas de cadeia.
- `claim_resume_bridge` agora persiste manifest.record antes da primeira
  liberação, com operação, dois digests de envelope, cápsula, janela original,
  ordem e custos. Workers conferem seu digest. O pai ainda conserva os digests
  aprovados: manifesto não é ainda uma restauração autônoma de todo coordenador.
  `counterpart_delivery_bridge` lança emissor separado que abre journal,
  fsync exposição e entrega bytes por loopback limitado/token. O pai admite
  bytes exatos no nó nativo e só então fecha a conexão SEM resposta. Emissor
  recebe EOF e morre exit 74; journal reaberto consulta pool/bloco nativos.
  É perda da resposta da ponte ao emissor, NÃO falha/retransmissão presumida
  do monerod. O pai e os nós continuam vivos. Não despachar retry no pool.
  O helper DOM mantém replay diagnóstico apenas depois de confirmado.
- Passaram 49 testes Rust e Clippy all-targets -D warnings, build separado;
  evidência COUNTERPART-DELIVERY-CHECKS.json. Os seis testes novos incluem
  estado ambíguo, observação/reorg simulado (não reorg nativo), corrupção,
  lock, bindings e erro de escrita. Novos modos nativos:
  direct-pair-xmr-first-ack-loss PID 872753: 171,713 s total,
  claims 83,788 s, trecho sem ack 0,166 s, devolução DOM rejeitada em 215;
  direct-pair-dom-first-ack-loss PID 873049: 168,896 s total,
  claims 82,681 s, trecho sem ack 0,301 s, devolução DOM rejeitada em 214.
  Ambos retomam primeiro o worker de claims (exit 73/0), depois exercitam
  emissor exit 74, consultam pool/bloco e gastam todos os outputs. Evidências
  DIRECT-PAIR-XMR-FIRST-ACK-LOSS-* e DIRECT-PAIR-DOM-FIRST-ACK-LOSS-*.
  Session 80883 terminou exit 0; hashes de fontes/binários conferidos.
  Notas detalhadas em COUNTERPART-DELIVERY.md.
- Próxima necessidade: retirar do pai a reconstrução dos bindings e a
  interpretação da cadeia na retomada. Persistir um checkpoint de controle
  original, recuperar manifestos/journals a partir de operação conhecida e
  consultar nós em processo novo após envio ambíguo. Hoje o pai entrega
  DeliveryBinding/observações e permanece vivo; não promover isso a restart
  completo. O journal da contraparte nasce depois da primeira inclusão;
  queda antes desse ponto ainda exige reconstrução da obrigação. Permanecem
  lacunas anteriores ao funding/disclosure, solver, autenticação, reorg real,
  preparação independente, limites temporais e integração ao dom-interopd.
  A missão continua ativa e o mecanismo não está provado seguro em produção.

- Commit local solicitado pelo operador concluído: `30e5d9c398e41447c3e533cb480e4574933803be`,
  Soren Planck como único autor/committer, sem push. Salvou journals iniciais,
  envelopes e envio sem resposta. A etapa abaixo é posterior a esse commit.
- `operation_checkpoint.rs` fixa antes da primeira liberação operação,
  manifesto e identidades/endpoints dos nós próprios; parser canônico limitado,
  checksum, arquivo 0600/fsync, armazenamento local confiável (não defesa
  contra escritor hostil/rollback). ClaimManifest reconstitui os instantes
  originais sem novo prazo. Credencial DOM é privada e não entra em evidências.
  `settlement_resume.rs` recebe SOMENTE root + operação via CLI. Lê envelopes,
  verifica claims e witness comum, consulta identidade e transações dos RPCs
  nativos, verifica corpo/bloco e tips novamente, reconstrói DeliveryBinding
  e abre journal. Não recebe interpretação de cadeia/digests do pai via IPC.
  Não assina/envia nem infere AbsentAndUnspent de not-found. Decide apenas
  MonitorPool/MonitorInclusion/Reconcile. Pai e nós ainda vivem: não confundir
  com restart completo. Continuidade detalhada em SETTLEMENT-RESUME.md.
- O primeiro ensaio revelou `/tx/{hash}` DOM sem entrada auxiliar depois
  de inclusão real. Worker conservou Reconcile; falha preservada em
  DIRECT-PAIR-XMR-FIRST-SETTLEMENT-RESUME-INDEX-MISS-* (PID 876851, exit 101,
  82,518 s). Correção consulta kernel, localiza bloco e exige corpo exato no
  scan nativo autenticado; não mexe no índice/consenso DOM. Também mantém
  checagem de primeira inclusão e nova consulta de tips. Isso detecta mudança
  visível, não prova snapshot atômico, finalização ou defesa contra reorg ABA.
- 52 testes Rust, Clippy all-targets -D warnings e build separados aprovados;
  SETTLEMENT-RESUME-CHECKS.json. O XMR-first corrigido (PID 877590) passou:
  189,613 s total, claims 101,893 s; três workers independentes observaram
  pool (0,222 s), inclusão (0,116 s) e RPC DOM realmente desligado (0,079 s).
  Usou fallback kernel+scan na inclusão; outputs gastos e refund rejeitado
  em 214. Total ACIMA de 180 s; não ocultar esse resultado selecionando o
  tempo das claims. Evidências DIRECT-PAIR-XMR-FIRST-SETTLEMENT-RESUME-*.
- A próxima lacuna estrutural não é mais somente interpretar cadeias fora
  do pai. O observador ainda depende de `observed.tx`/`counterpart.tx` que
  foram gravados após a primeira inclusão, e o journal da obrigação nasce
  nesse ponto. `journaled_initial_send` persiste digest/política/exposição,
  mas não os bytes completos da primeira claim. Próximo: persistir antes
  do primeiro envio o material exato para descobrir essa claim, reconstruir
  a obrigação a partir dos envelopes e RPC após queda ANTES desses arquivos,
  e fazer o novo coordenador controlar envio/reconciliação (sem recriar
  assinatura nem prazo). Ainda faltam persistência anterior a depósitos e
  divulgação, solver, preparação independente/autenticação, reorg nativo,
  limites temporais fundamentados, prova de segurança e dom-interopd.
  Uma inclusão/reorg incerta jamais cancela por si só a contraparte devida.
- DOM-first corrigido (PID 880709) também passou: total 169,919 s,
  claims 83,693 s, observadores 0,166 / 0,111 / 0,074 s. Pool/inclusão usaram
  kernel+scan DOM; endpoint desligado voltou a Reconcile. Todos os outputs
  gastos, refund DOM rejeitado em 214. Evidência
  DIRECT-PAIR-DOM-FIRST-SETTLEMENT-RESUME-*. Session 27995 terminou exit 0.
  Resultados guardam a variação real de tempo (XMR-first acima de 180 s),
  não provam SLA ou segurança. Fontes/binário dos dois corrigidos conferidos.

- Etapa seguinte concluída funcionalmente: `journaled_initial_send` agora
  grava `initial-claim.tx` 0600/create_new/fsync ANTES de criar/expor o journal.
  ClaimManifest é v2 e inclui candidates original; não converter artefatos v1
  antigos nem inventar candidatos. `original_release_policy` restaura campos
  originais e digest desses bytes; worker exige initial-claim.wal coerente e
  ExposurePossible, nunca evento novo/prazo renovado. `restore_original` é
  somente restauração de premissas, não prova de prazo.
- `settlement_resume` recebe root/operação/ação. Em reconstruct, verifica
  primeira claim e inclusão nativa, completa somente o adaptor aprovado e
  cria CounterpartDelivery com bytes/binding. Se existe, abre estritamente,
  verifica body/witness e NÃO completa outra assinatura. Exposto existente
  retorna Reconcile, nunca CounterpartPrepared. Não usa observed.tx nem
  counterpart.tx posteriores à inclusão. Erro após possível criação reporta
  signature_created desconhecido, não falso. Transporte ainda é da ponte do pai.
- Modos ack-loss agora testam: primeira claim no pool recusa criar obrigação;
  worker após inclusão morre exit 75 ANTES do journal; próximo cria; terceiro
  reusa byte a byte; emissor separado recebe EOF e morre exit 74; processos
  independentes observam pool/bloco/RPC DOM desligado. Há nova reconstrução
  após exposição que conserva Reconcile e journal intacto. Manifesto/envelopes
  são anteriores ao primeiro envio e arquivos pós-inclusão permanecem ausentes.
  Pai e nós vivem: não chamar de restart completo do daemon.
- Passaram 54 testes Rust e Clippy all-targets -D warnings/build separados;
  OBLIGATION-RECONSTRUCTION-CHECKS.json. XMR-first PID 887515 passou em
  167,841 s, claims 80,239 s, queda/reconstrução/reuso 0,550 s, refund rejeitado
  em 215. DOM-first PID 887951 passou em 205,188 s, claims 116,390 s, retomada
  0,983 s, refund rejeitado em 214. Todos os outputs gastos. Evidências
  DIRECT-PAIR-{XMR,DOM}-FIRST-OBLIGATION-RECONSTRUCTION-* e notas
  OBLIGATION-RECONSTRUCTION.md. Session 91768 terminou exit 0, fontes/binário
  conferidos, workers/grupos próprios ausentes. Nenhum ensaio ficou ativo.
- DOM-first ficou ACIMA de três minutos; preparação individual 44,455 s
  versus 16,721 s na inversa. Não reexecutar apenas para escolher resultado
  rápido. OBLIGATION-RECONSTRUCTION-TIMING.json registra folgas observadas
  de 13 s / 5 s até earliest adversarial ASSUMIDO. Evento de exposição até
  inclusão XMR marcou 0 / 5 segundos inteiros; evento precede fsync/gate final,
  logo não é medida exata da latência de envio nem prova de orçamento.
  Custos de IO, restart e probes devem entrar na janela original; premissas
  de 1 s por etapa seguem sem fundamento e não virar garantia.
- Próxima lacuna: coordenador novo já cria obrigação mas ainda não controla
  transporte/envio; pai prepara observações de ausência/input livre e encaminha
  bytes por sua ponte. Transferir envio e reconciliação com estado durável ao
  novo coordenador, testando queda antes de registrar receipt e mantendo bytes
  e exposição. Nunca inferir ausência/unspent de not-found ou fechar obrigação
  devida pelo gate inicial. Orçamento completo de retomada, preparação/solver
  duráveis, participantes independentes/autenticação, reorg nativo, limites
  temporais e revisão criptográfica/dom-interopd ainda pendentes.

- O envio nativo independente agora passou nos modos
  direct-pair-{xmr,dom}-first-native-send. Worker restaura checkpoint e obrigação,
  exige ausência exata/input livre via RPC, fsync exposição e reconsulta antes
  de publicar bytes imutáveis diretamente no nó. Exit 77 antes do RPC; outro
  worker verifica RetryExactBytes; exit 76 depois de receber admissão nativa
  mas antes de comunicar/persistir resultado. Não chamar 76 de resposta perdida
  pelo monerod. Pai continua host/minerador e emissor inicial; replay diagnóstico
  DOM ocorre depois de confirmado. Não é restart completo nem dom-interopd.
- 57 testes Rust, Clippy all-targets -D warnings e build separados passaram;
  NATIVE-SENDER-CHECKS.json. XMR-first PID 901649: total 183,011 s,
  claims 93,891 s, reconstrução 0,689 s, entrega com quedas 0,604 s.
  DOM-first PID 903609: total 200,772 s, claims 111,636 s,
  reconstrução 1,184 s, entrega 1,706 s. Ambos acima de 180 s; preservar essas
  medições. Pool/bloco/RPC indisponível suprimiram pedidos explícitos de envio;
  todos os outputs gastos e refund conflitante rejeitado em 215. Artefatos
  DIRECT-PAIR-{XMR,DOM}-FIRST-NATIVE-SEND-*; notas NATIVE-SENDER.md.
  Session 22311 terminou exit 0, hashes fontes/binários conferidos e PIDs
  registrados ausentes. Não há ensaio dessa etapa pendente a reiniciar.
- Próximo: reorg nativo/concorrência e orçamento integral das retomadas.
  Observações sequenciais e rechecks de tips em nós próprios não são snapshot
  atômico, defesa ABA ou autenticação de nó público. Não declarar segurança
  completa nem meta temporal cumprida. Preparação/solver duráveis antes de
  funding/disclosure, participantes independentes, fundamentos temporais e
  criptográficos e integração ao dom-interopd continuam pendentes. A lacuna de
  envio da contraparte pelo pai foi fechada somente no novo caminho descrito.

- Continuidade seguinte: `direct-pair-dom-first-xmr-detach` retira o bloco
  XMR via pop_blocks, exige MonitorPool, faz flush só do hash aprovado, minera
  substituição vazia e reenvia os bytes imutáveis por novo worker depois de
  ausência/key image livre. Reinclusão em outra altura/bloco, journal idêntico,
  dentro da janela ORIGINAL assumida. Não é reorg por fork-choice entre peers.
  Primeira execução PID 909696 falhou em 108,376 s com status DOM genérico;
  diagnóstico PID 913498 falhou em 114,082 s: HTTP 429 em /chain/identity após
  retirada/evicção, emissor Reconcile sem tentar publicar. Logs/fases/watchdogs
  e provenance preservados em DIRECT-PAIR-DOM-FIRST-XMR-DETACH-INITIAL-FAILURE*
  e -DIAGNOSTIC-*. Erros agora registram código/rota sem token nem corpo.
- Middleware DOM atual tem burst 100 e reposição 1/s, apesar do comentário
  100 req/sec. Não foi alterado. Ensaio separado com override explícito
  DOM_RPC_RATELIMIT_READ=256 somente no processo do laboratório passou:
  PID 915028, total 173,427 s, claims/reinclusão 86,800 s, retirada/evicção/
  reenvio/reinclusão 0,815 s, altura XMR 152→153, folga condicional assumida
  nove segundos. Outputs gastos e refund rejeitado em 214. Artefatos
  DIRECT-PAIR-DOM-FIRST-XMR-DETACH-CAPACITY256-*; XMR-NATIVE-DETACH.md.
  Session 5694 terminou exit 0, hashes fontes/binário conferidos, PIDs/grupo
  encerrados. Onze testes relacionados/Clippy/build passaram; ver
  XMR-DETACH-CHECKS.json. Não generalizar sucesso para configuração padrão
  nem esconder falhas/tempos anteriores. Não houve ensaio de peers concorrentes.
- Próximas lacunas concretas: (1) throttling/reconciliação precisa de política
  e orçamento original, sem envio cego nem extensão de prazo; (2) worker cria
  DeliveryBinding usando bloco/altura ATUAIS da primeira claim e open exige
  igualdade com âncora ORIGINAL. Uma reinclusão da primeira claim em outro
  bloco fica presa em Reconcile. Separar âncora histórica de evidência canônica
  atual da mesma transação, preservando manifesto, bytes, exposição e journal;
  testar perda e reinclusão NATIVAS antes de afirmar recuperação dessa situação.
  Não simplesmente ignorar inclusão ausente, nem sobrescrever/descartar journal.

- A rejeição da primeira claim reincluída foi corrigida: DeliveryPayment fixa
  manifesto, digest da transação inicial e cadeia alvo. open_for_payment lê
  e bloqueia o mesmo arquivo, valida formato/checksum/exposição e preserva a
  âncora histórica; open(binding completo) continua estrito. Worker só usa a
  nova API APÓS verificar bytes/envelope e inclusão nativa canônica atuais,
  depois revalida corpo/witness guardados e tips. Não transformar identidade
  estável/checksum em prova de cadeia, nem permitir envio com primeira claim
  apenas no pool/ausente. Esses casos conservam a obrigação em Reconcile.
- Passaram 59 testes Rust, Clippy all-targets -D warnings e build separado;
  FIRST-REINCLUSION-CHECKS.json. Modo direct-pair-xmr-first-reinclude PID 931558
  passou em 176,728 s total, claims 90,383 s, trecho de exposição/retirada/
  evicção/reinclusão/restauração 1,180 s. Burst DOM explicitamente 100 (padrão).
  Depois de exit 77 antes do RPC, primeira claim foi retirada: send/reconstruct
  no pool e na ausência recusaram envio e preservaram journal. Supervisor
  republicou bytes XMR originais; altura 152→153, novo worker aceitou inclusão
  atual conservando âncora 152 e bytes/prazos/exposição originais. Contraparte
  enviada por worker, outputs gastos, refund rejeitado em 214. Folga até
  limite adversarial ASSUMIDO dez segundos; não é prova temporal.
  Artefatos DIRECT-PAIR-XMR-FIRST-REINCLUDE-*, FIRST-REINCLUSION-VERIFICATION.json
  e FIRST-PAYMENT-REINCLUSION.md. Session 42712 terminou exit 0, fontes/binário
  conferidos, PIDs/grupo encerrados; nenhum ensaio desta etapa pendente.
- Próximo: política/orçamento de retomada sob HTTP 429 e transporte durável da
  PRIMEIRA perna (a republicação inicial após retirada ainda é do supervisor).
  Não reintroduzir gate inicial sobre obrigação exposta, renovar prazo ou
  recriar assinatura. A mudança de âncora está fechada no cenário nativo
  isolado; forks concorrentes/ABA, setup/solver duráveis, participantes
  independentes, fundamentação criptográfica/temporal e dom-interopd continuam
  abertos. O sucesso com burst 100 nesta ordem não apaga a falha 429 DOM-first.

- Etapa RPC: worker reutiliza prev_hash do cabeçalho localizado pelo kernel
  como hint de âncora; scan nativo valida âncora/bloco/corpo/identidade/tip sob
  um único chain lock. Removeu leitura posterior redundante /block/{height},
  conservou todos os checks de corpo exato, snapshot e tips finais/pós-fsync.
  Não mudou consenso, limitador ou código do nó; não é snapshot distribuído
  entre as duas cadeias nem defesa ABA/nó hostil.
- GET com HTTP 429 e header válido pode aguardar até 2.000 ms SOLICITADOS
  por worker, compartilhados entre rotas, no máximo duas repetições. Respeita
  Retry-After inteiro ou x-ratelimit-after nativo arredondado para baixo +1s;
  malformed/duplicado/excessivo recusa repetição. POST nunca é repetido por
  esse transporte. Timeout de recuperação 10s e instantes originais continuam;
  contadores de espera decorrida incluem cancelamento durante sleep. Limite
  por worker NÃO é orçamento global durável de reinícios nem SLA.
- 38 testes relacionados (seis novos), Clippy all-targets -D warnings e build
  passaram; RPC-READ-RECOVERY-CHECKS.json. Regressões com burst padrão 100:
  DOM-first-xmr-detach PID 942133 passou em 189,201 s, claims 103,184 s,
  recuperação 0,946 s, refund rejeitado em 213. XMR-first-reinclude PID 943166
  passou em 179,736 s, claims 95,228 s, recuperação 1,340 s, refund em 212.
  Outputs gastos, journals/prazos preservados. Tentativas DOM públicas/auth:
  82/31 e 62/16, zero throttling nessas execuções; testes HTTP locais exercitam
  429/backoff/POST/cancelamento. Não dizer que o backoff foi exercitado por
  rate-limit nativo nesses dois ensaios. Primeiro >180s; segundo com margem
  inferior a um segundo, nenhum garante a meta. Fontes/binários conferidos,
  PIDs/grupos encerrados; session 60441 exit 0, nenhum ensaio pendente.
  Artefatos DIRECT-PAIR-{DOM-FIRST-XMR-DETACH,XMR-FIRST-REINCLUDE}-RPC-READ-RECOVERY-*,
  RPC-READ-RECOVERY-VERIFICATION.json e RPC-READ-RECOVERY.md.
- Próximo: emissor/restaurador durável da PRIMEIRA transação, hoje republicada
  pelo supervisor no teste. Distinguir possível exposição (que pode ocorrer
  antes de qualquer RPC) de evidência de divulgação/inclusão anterior; não usar
  marcador de exposição como autorização ilimitada para primeira liberação
  tardia. Gate inicial não se reaplica à contraparte comprovadamente devida.
  Preservar bytes/journals/instantes e consultas independentes. Orçamento global
  de retomadas, setup/solver duráveis, participantes independentes, fundamentos
  temporais/criptográficos e dom-interopd continuam abertos.

- Republicação inicial implementada: inspect-first/replay-first restauram
  journal original ExposurePossible, bytes/envelopes e obrigação histórica.
  Exposição sozinha não autoriza replay. Observam ambas as cadeias, exigem
  ausência/input livre e janela original para contraparte ainda não paga;
  contraparte canônica paga permite quitar dívida depois da janela. Histórico
  depende de writer/storage local confiável, não prova contra storage hostil.
  Conserva lock inicial e obrigação durante envio; não cria assinatura/prazo.
  check_exposed_replay_deadline rejeita relógio abaixo do evento de exposição,
  mas não persiste high-water de relógio nem fechamento da janela de replay.
- Passaram 67 testes Rust, Clippy/build; INITIAL-NATIVE-REPLAY-CHECKS.json.
  Primeiro ensaio PID 975550 exit 101 em 99,989 s: reservas financiadas,
  janela expirou antes das claims. NENHUM worker exercitado. Preservado em
  DIRECT-PAIR-XMR-FIRST-NATIVE-REPLAY-INITIAL-FAILURE-*. Grupo encerrado.
  Não repetir mesma versão apenas por sorte nem ampliar prazo.
- direct_dlog.go agora verifica duas equações independentes por vez; conserva
  256 rodadas, transcript, bounds/subgrupo e abertura/setup sequenciais.
  Erro determinístico por menor índice, todos os workers terminam antes do
  retorno, no máximo uma equação extra em prova inválida. Não altera o backend
  cut-and-choose. 21 testes Go, real proof com -race, vet/build passaram.
  Mesma prova: 7,422 s concorrente, 14,646 s sequencial. Evidências em
  recovery-audit/DIRECT-PARALLEL-{CHECKS,RACE,BUILD}.json e notas VERIFICATION.md.
- Ensaio nativo com novo helper e mesmo Rust passou: PID 1018508, total
  172,394 s / claims 78,972 s; retirada/reinclusão 2,002 s, replay/restauração
  0,452 s. Worker republica XMR diretamente, recebe ACK e morre exit 79;
  novo processo apenas monitora pool, depois inclusão 152→153. Primeira
  emissão ainda do pai. Registros idênticos, contraparte por worker, outputs
  gastos e refund conflitante rejeitado em 221. Burst DOM 100/GOMAXPROCS=2,
  leituras workers públicas/auth 86/28, zero 429. Não abre cápsula neste caso.
  Artefatos DIRECT-PAIR-XMR-FIRST-NATIVE-REPLAY-PARALLEL-*, notas
  INITIAL-NATIVE-REPLAY.md e INITIAL-NATIVE-REPLAY-VERIFICATION.json. Session
  14306 exit 0, hashes/PIDs/grupo conferidos, nenhum ensaio pendente.
- Continuidade: replay inicial DOM e repagamento após janela com contraparte
  canônica só têm cobertura unitária; setup/solver duráveis ANTES de funding/
  divulgação, restart completo, orçamento global, participantes independentes,
  fork-choice/ABA, provas temporais/criptográficas e dom-interopd permanecem
  abertos. Um resultado em 172 s não prova repetibilidade nem encerra missão.

- Checkpoint local da cápsula em src/capsule_checkpoint.rs: formato v2,
  setup/oferta opacos, contexto/ponto/binding aprovado/recebimento original/
  dificuldade/medições, checksum e parser limitado. Arquivo 0600/create_new/
  fsync arquivo+diretório, nenhum reparo automático. Caller estabelece parent
  durável; novo cenário cria root 0700 e sincroniza também sua entrada no pai.
  Não é aceitação criptográfica; helper novo revalida setup/prova completos.
  Não protege metadados contra escritor local hostil/rollback. Payload inclui
  números Go arbitrariamente grandes: NÃO parsear toda oferta com serde_json
  Value só para obter setup. Formato v1 da tentativa falha não é migrado.
- Modo direct-pair-abandon-solver-restart persiste cápsula ANTES dos depósitos,
  mata Go verificador esperando pedido de abertura e restaura outro só do
  registro + binding aprovado. Sem produtor/prova novos, recebe a mesma share,
  preserva recebimento e janela. Pai Rust, nós, roster/share local continuam
  vivos; não é restart completo, retomada de solve parcial ou dom-interopd.
  Tempo restaurado usa segundo original floor (até 1s extra no relatório),
  não cria primeira divulgação autenticada ou defesa de rollback de relógio.
- Primeira tentativa PID 1057817 exit 101 em 76,667 s após os dois depósitos
  e kill do Go antigo: Value recusou inteiro fora de faixa. Nenhuma abertura
  ou nova verificação. Evidência *ABANDON-SOLVER-RESTART-INITIAL-FAILURE-*.
  Correção v2 passou 35 testes Rust, Clippy all-targets -D warnings e build;
  CAPSULE-COLD-RESTART-CHECKS.json. Grupo anterior encerrado.
- Corrigido PID 1062947 terminou exit 0: total 194,762 s; revalidação setup
  40,279 s, prova 8,989 s, restauração 49,304 s, abertura 35,939 s; recuperação
  INTEGRAL 85,247 s. Falha nas metas de 180 s totais e 65 s de custo assumido.
  XMR devolvido em 1790477485 antes do limite original 1790477488 porque
  começou cedo; NÃO valida o início máximo admitido. DOM refund travado219,
  incluído220/gasto221; outputs XMR gastos. Registro original inalterado.
  PIDs Go 1063596 (SIGKILL) /1063912 (novo). Hashes/PIDs/grupo conferidos;
  session70530 exit0, nenhum processo desta etapa pendente. Evidências
  DIRECT-PAIR-ABANDON-SOLVER-RESTART-* e CAPSULE-COLD-RESTART-VERIFICATION.json;
  notas CAPSULE-COLD-RESTART.md. Preservar também primeira falha e variação
  de preparação individual38,766s (anterior19,399s), sem repetir por sorte.
- Próximo: reduzir recomputação sequencial de setup na restauração mantendo
  vínculo à oferta APROVADA antes do funding. Avaliar evidência/cache de estado
  aceito sob a confiança local existente; não aceitar flag de peer dizendo
  "já verificado", confundir cache com prova remota, renovar divulgação ou
  ampliar orçamento para tornar teste verde. A recuperação nova é funcional,
  mas o orçamento temporal ainda não a cobre. Persistência de roster/share
  local/solve parcial, preparação independente, limite global de quedas,
  autenticação/provas criptográficas/temporais e dom-interopd continuam abertos.

- Retomada com comprovante LOCAL implementada em direct_dlog_cli.go e bridge
  Rust. Autoridade aleatória separada 0600/create_new/fsync, caminho absoluto
  configurado só no verificador. HMAC-SHA256 emitido só depois de verificar
  setup sequencial e todas as 256 equações; vincula hashes exatos de setup/
  oferta, contexto/ponto/work/recebimento original. JSON de peer não fornece
  chave. Restauração autentica comprovante e repete prova; dispensa apenas
  recomputação H já aceita. Não é prova remota nem defesa contra writer que
  controla a autoridade local. Registro v2 sozinho não autoriza cache.
- Passaram 35 testes Rust, 24 Go, Clippy all-targets -D warnings, vet/build.
  Os 13 testes do exemplo repetidos após espera tardia não são novos testes.
  LOCAL-SETUP-RECEIPT-{RUST,LATEST-START}-CHECKS.json e recovery-audit/
  LOCAL-SETUP-RECEIPT-GO-CHECKS.json. Sem novo teste -race nesta etapa.
- Native direct-pair-abandon-local-receipt PID1084776/session58410 exit0:
  total219,839s, recuperação44,756s, restauração9,796s, abertura34,936s.
  Esperou recebimento1790478990 +35 para iniciar em1790479025; XMR refund
  observado1790479070 antes do limite1790479090. Custo<=65 passou; total<=180
  FALHOU. Setup inicial70,089s/cápsula103,502s; não repetir por sorte.
  DOM lock217/refund218/gasto219, outputs XMR gastos. Cápsula/comprovante/
  autoridade/prazos inalterados. PIDs1084776/1085002/1109383 e grupo ausentes,
  fontes/binários conferidos. Não há ensaio pendente. Evidências
  DIRECT-PAIR-ABANDON-LOCAL-RECEIPT-* e LOCAL-SETUP-RECEIPT-VERIFICATION.json;
  notas LOCAL-SETUP-RECEIPT.md. Supervisor Rust/nós/roster/share local vivos,
  sem solve parcial, restart integral ou integração ao dom-interopd.
- Próximo: persistência da share local/roster e retomada por processo novo,
  conservando autoridade/cápsula/janela já financiadas. Não confundir restart
  apenas do Go com restart do coordenador. Orçamento global de quedas,
  preparação independente, fundamentos criptográficos/temporais e daemon
  seguem pendentes; resultado de laboratório não conclui a missão.

- LocalXmrRecoveryCheckpoint em src/xmr_recovery/checkpoint.rs persiste share
  LOCAL original, reserva/chaves/papel/binding cápsula/recebimento/work; formato
  fixo/checksum/0600/create_new/fsync, buffers de segredo Zeroizing. Exige
  identidade pública aprovada externa ao arquivo; não protege storage hostil
  ou rollback. Sem aggregate key, offset, nonce ou autorização de publicação.
  Restore confere cápsula/roster/papel, não prova nem janela temporal.
- 25 testes Rust/Clippy/build passaram. Quatro novos exercitam corrupção,
  substituição e restauração por filho novo para ambos papéis com só arquivos
  e bindings públicos; fixture de codec sem prova/funding. Primeira rodada
  Clippy recusou drop_non_drop no teste, corrigido por fim de escopo/move;
  LOCAL-XMR-STATE-{INITIAL-CHECKS,CHECKS}.json conserva histórico. Session81611
  terminou exit0; session97589 falhou no lint antes do build e foi encerrada.
- Native PID1250252/session46505 exit0: total178,415s/parede178,466s,
  recuperação58,509s (dentro65), restauração9,129s/abertura49,311s. Preparação
  cápsula65,443s/setup37,640s; variação não prova melhoria de velocidade.
  Recebimento1790480170/início1790480205 (+35), XMR observado1790480264 antes
  do limite1790480270 (6s). DOM lock219/refund220/gasto221, outputs gastos.
  Original local/roster/link descartados e reconstruídos do registro no MESMO
  Rust; Go antigo1250312/new1251361. Não é full coordinator restart.
  Hashes/PIDs/grupo conferidos, nenhum processo pendente. Evidências
  DIRECT-PAIR-ABANDON-LOCAL-XMR-STATE-* e LOCAL-XMR-STATE-VERIFICATION.json;
  notas LOCAL-XMR-STATE.md. Native <=180 passou nesta execução com pouca
  folga; manter resultados anteriores mais lentos. Não há SLA/prova temporal.
- Próximo concreto: recuperação E devolução financiadas em processo Rust novo
  carregando plano nativo/autorizações/janela originais, além do estado local.
  Hoje refund PreparedClaim, outputs/offset/endereço/fee ainda vêm da memória
  do coordenador em regtest_claim.rs. Não resolver essa lacuna deixando uma
  devolução XMR completa previamente disponível antes do atraso. Persistência
  de sessões cooperativas, quedas globais, preparação independente, provas
  criptográficas/temporais e dom-interopd continuam abertas.

- PreparedClaim agora exporta/restaura intenção SEM assinatura em
  src/native/recovery_checkpoint.rs. Conserva corpo/contexto/aberturas privadas,
  sem spend shares/nonces; marcador CLSAG fixo inválido para satisfazer wire.
  Revalida digest COM DOMÍNIO claim_resume::digest, pontos/commitments/offsets/
  corpo/Bulletproof/balanço/canonicalidade; recusa assinatura completa embutida.
  Não usar SHA256 simples como expected deste codec (job externo usa SHA256).
- direct-pair-abandon-local-receipt agora persiste refund-recovery.job depois
  dos depósitos e antes de esperar recuperação. Contém identidade local/cápsula/
  link/recebimento/limite original/offset/intenção sem assinatura. Pai descarta
  ambas shares, mata Go; Rust novo --xmr-refund-recovery-worker carrega tudo,
  confere links, restaura Go/prova, abre cápsula, aplica offset, confere key
  image e assina com nonces novos. Retorna TX e métricas, nunca spend shares.
  Pai confere, publica no monerod e observa; ainda host dos nós/minerador DOM.
  Sem full coordinator restart ou publicação/observação independente do worker.
- Primeira tentativa PID1331232/Rust1331589 exit101 em136,145s após depósitos
  e kill do Go: job usava hash simples no decoder de intenção. Falhou antes
  de Go novo/abertura/assinatura. Corrigido domínio, teste novo passa por job
  com intenção nativa real. Falha *REFUND-WORKER-INITIAL-FAILURE-* preservada,
  fontes/binários anteriores conferidos e grupo encerrado. Não renovou prazo
  nem retomou essa operação expirada. Novo ensaio usa outra reserva própria.
- Após correção 31 testes Rust (12 native,4 local state,15 example), Clippy
  all-targets -D warnings/build passaram; REFUND-RECOVERY-WORKER-CHECKS.json.
  Versão anterior 30 testes em INITIAL-CHECKS. Sem mudança/novo teste Go.
- Corrigido PID1346571/session23347 exit0: total168,992s/parede169,012s,
  recuperação integral39,318s/worker39,229s, restauração7,517s/abertura31,467s.
  Recebimento1790481710/início1745 (+35), XMR observado1784 antes de1810
  (todos no prefixo179048). DOM lock221/refund222/gasto223, outputs gastos.
  Cinco arquivos de entrada iguais; Rust1346866/Goantigo1346649/novo1346867.
  Hashes/PIDs/grupo conferidos. *ABANDON-REFUND-WORKER-* e
  REFUND-RECOVERY-WORKER-VERIFICATION.json; notas REFUND-RECOVERY-WORKER.md.
- Regressão height-dom-first PID1348011/session69362 exit0: total32,265s,
  claims/gastos nativos e refund conflitante recusado. Artefatos
  HEIGHT-DOM-FIRST-REFUND-WORKER-REGRESSION-*, hashes/processo/grupo conferidos.
  Nenhum ensaio pendente. Metas observadas passaram no cenário corrigido;
  manter falha inicial e resultados anteriores mais lentos, sem SLA.
- Próximo: ligar worker aos journals originais de entrega/exposição e à
  observação/publicação nativa independente com retomada do envio. Job atual
  é restrito a abandono ANTES da entrega de adaptors, não tem barreira durável
  dessa entrega e sozinho não autoriza generalizar para claims possivelmente
  expostas. Queda antes de gravar intenção após funding, quedas durante
  assinatura/envio, limite global de retomadas, preparação independente,
  provas temporais/criptográficas e dom-interopd continuam abertos.

- PreparationGate (src/preparation_gate.rs) criado em preparation.wal antes
  dos depósitos dos modos direct-pair. Binding=link cápsula64+recebimento
  original; Private escolhe uma vez ExchangePossible{operação final} ANTES
  de dom.offer/presign OU RecoveryOnly{job exato}. Lock/fsync/0600/create_new,
  root0700/durável para todos direct-pair. Sem transição de volta ou entre
  estados. Registro ausente/parcial/corrompido não é recriado. Checksum/lock
  pressupõem storage/writers confiáveis; rollback de evento completo excluído.
- Worker de refund reserva o job antes de ler shares/iniciar Go e mantém lock
  durante recuperar/assinar; pai confere decisão e recusa troca depois. Modos
  antigos de abandono só no pai também fixam uma finalidade ligada à cápsula.
  Journaled_initial_send e settlement_resume exigem ExchangePossible com a
  operação do manifest antes de envio/retomada. Não reaplica gate temporal
  inicial à contraparte devida. O gate não é autorização de refund exposto,
  observação de cadeia, prova temporal ou orçamento global de tentativas.
- 32 testes Rust (5 preparação,11 initial journal,16 example), Clippy/build
  passaram; PREPARATION-GATE-CHECKS.json. Testes pais executam filhos que
  encerram sem destructors, locks entre processos, troca de binding/job e
  corrupção/truncamento; teste do worker exposto recusa antes de shares/Go.
  Session18412 exit0. Nenhuma alteração/teste novo Go.
- Recuperação nativa PID1418559/session86935 exit0: total174,093s,
  recuperação43,715s, recebimento1790482735/início1790482770 (+35), refundXMR
  observado1790482813 antes de1790482835. DOM lock219/refund220/gasto221.
  RecoveryOnly contém hash do job original, tentativa de troca posterior
  recusada. Rust1441087/Goantigo1418622/novo1441093, hashes/PIDs/grupo conferidos.
  Prefixo DIRECT-PAIR-ABANDON-PREPARATION-GATE-*.
- Coop native-replay PID1462686/session68082 exit0: total178,899s/claims84,314s,
  worker1463064 republica XMR e morre79 após ACK; pool/reinclusão152→153,
  contraparte por worker, outputs gastos/refund DOM conflitante recusado221.
  ExchangePossible contém operação original do manifest; RecoveryOnly recusado
  após a decisão. RPC DOM86public/28auth/1POST/0retry429, sem backoff nativo
  exercitado. Prefixo DIRECT-PAIR-XMR-FIRST-REPLAY-PREPARATION-GATE-*.
  Hashes/pai/workers/grupo conferidos; nenhum ensaio pendente. Notas
  PREPARATION-GATE.md e PREPARATION-GATE-VERIFICATION.json. Resultados <=180
  nesta rodada não apagam variação anterior nem provam segurança/SLA.
- Próximo: worker de refund observa/publica nos nós por checkpoint original
  de endpoints/genesis/inputs e reconcilia bytes exatos após queda. Agora já
  exige fase privada reservada ao job; não usar ausência do journal inicial
  como prova de não exposição, nem reutilizar esse caminho em ExchangePossible.
  Recuperação após exposição, quedas antes de persistir intent após funding,
  orçamento global, preparação independente, provas criptográficas/temporais
  e dom-interopd continuam pendentes.

- Commit241b4fc salvou PreparationGate com identidade Soren e árvore limpa.
- Etapa seguinte refund_delivery.rs: Job v2 inclui digest de checkpoint
  refund-network.record (porta loopback/genesis/altura+hash após funding).
  Workers separados do signer carregam job assinado e RecoveryOnly exato,
  mantêm lock e validam fakechain/offline/genesis/anchor/anel nativo unlocked,
  bytes/assinatura, pool/inclusão ou ausência+keyimage livre. Ponta estável
  antes/depois, deadline original; sem solver/chaves recebidas no publisher.
  refund-send.intent create_new/0600/fsync antes do POST, job+digest da tx;
  reconsulta antes do envio. Nunca retry POST automático nem assinatura nova.
  Job/signature faltante/parcial falha fechado. Storage/clock/nó confiáveis,
  ABA e rollback hostil excluídos. Timeout8s por processo não é budget global.
- run do signer usa publishers novos: saída80 antes RPC, saída81 após ACK,
  depois processo novo observa pool sem enviar; pai apenas minera e outro
  worker verifica inclusão nativa. Refund XMR não é publicado pelo pai nesse
  modo. Seis arquivos protegidos, signed bytes e send intent iguais.
- 18 testes example (incluindo dois novos native-response/network-pinning),
  Clippy all-targets -D warnings e build passaram session37907. Primeira
  compilação apontou tipo RPC transporte vs MoneroDaemon; corrigida antes do
  ensaio. REFUND-DELIVERY-CHECKS.json guarda hashes/resultados. Sem testes ou
  alterações Go novos. Somente três fontes example mudaram, codecs core intactos.
- Native direct-pair-abandon-local-receipt PID1528381/session98733 exit0:
  total196,115s, recovery42,163s, signer41,097s. Recebimento1790484240,
  início1790484275 (+35), XMR observado1790484317 antes de4340 (mesmo prefixo).
  DOM lock220/refund221, outputs gastos. Rust signer1529477, publishers1529592
  (exit80),1529593(exit81),1529594(pool sem POST),1529595(incluído152 sem POST).
  Go antigo1528852/novo1529479. Hashes/PIDs/grupo conferidos e encerrados.
  Prefixo DIRECT-PAIR-ABANDON-REFUND-DELIVERY-*, notas REFUND-DELIVERY.md,
  REFUND-DELIVERY-VERIFICATION.json. Nenhum ensaio pendente.
- Total excedeu180s em16,115s: não declarar meta cumprida. Saldos40,452s,
  cápsula verificada98,322s, refundXMR166,187s, depois altura/refundDOM.
  Recuperação funcional dentro65s assumidos, sem prova universal/SLA.
- Próximo: orçamento global durável de tentativas e recuperação após
  interrupção durante assinatura/arquivo parcial sem renovar prazo; queda
  antes de persistir job após funding continua descoberta. Separar recuperação
  pós-exposição; não usar private-abandonment como atalho. Preparação entre
  participantes independentes, prova de atomicidade/tempos e dom-interopd
  continuam obrigatórios. Perfis temporais experimentais não fundamentados.

- Commit8e78296 salvou publicação independente do refund, Soren-only/árvorelimpa.
- Etapa SIGNING-RESUME: refund_signing_state.rs guarda UMA share original
  recuperada em refund-opening.record privado0600, job32+scalar32+metrics
  limitadas/checksum, Zeroizing, chave pública conferida; persiste só após
  validar link/roster/cápsula sob RecoveryOnly. É segredo LOCAL, não exportado
  em relatório nem prova pública/cache peer. Storage/clock confiáveis; não
  protege rollback. Pai apenas compara digest, mesmo domínio privado original.
- Arquivos pending são fsync/hard-link create-only para final/fsync-dir/unlink.
  Opening completo pendente pode ser promovido; parcial de abertura falha
  sem fallback ao solver. Assinatura completa pendente é conferida contra a
  intenção original/promovida sem assinatura nova. Pending de assinatura
  parcial PRIVADO pode ser removido/refeito com nonces novos, somente se não
  existe final nem send.intent. Final inválido nunca reparado; final ausente
  com intent é recusado antes de shares/solver. Gate fica locked/originaldeadline.
- Native run injeta saída82 após opening durável, saída83 após metade da tx,
  saída84 após staging completa; signers seguintes recebem solver inexistente.
  Conserva também saídas80/81 e pool/inclusão por publisher. Mede custo integral
  de todos os processos, sem reabrir cápsula ou renovar prazo. Não cobre queda
  no MEIO do solve ou abertura parcial antes de checkpoint, nem budget global.
- 22 testes example, Clippy all-targets -D warnings e build passaram
  session43955; SIGNING-RESUME-CHECKS.json/hashes. Quatro testes novos cobrem
  identidade/ponto/canonicalidade/truncamento/corrupção/promoção sem overwrite,
  opening parcial recusado e final possivelmente publicado ausente recusado.
  Não mudou Go/core nem requereu testes Go novos.
- Primeira native PID1580165/session17841 exit101 em16,021s: decoy selection
  round limit no preparo do saldo individual, ANTES de cápsula/sharedfunding.
  Preservada *SIGNING-RESUME-INITIAL-FAILURE-*, hashes/grupo ausente conferidos.
  Novo ensaio com outra reserva, MESMAS fontes/binários, sem prazo renovado.
- Segundo PID1580411/session86359 exit0: total186,557s, recovery45,737s,
  conjunto signer43,773s, abertura única31,866s, última retomada0,780s.
  Recebimento1790485218/início1790485253/refund observado1790485299/latest5318
  (mesmo prefixo179048); DOM lock220/refund221, outputs gastos. Workers1582656
  (exit82),1582755(exit83),1582757(exit84),1582758(promove bytes), publishers
  1582759(exit80),1582760(exit81),1582761(pool semPOST),1582762(inclusão semPOST).
  Go antigo1581243/novo1582658. Hashes/PIDs/grupo conferidos/encerrados.
  Prefixo DIRECT-PAIR-ABANDON-SIGNING-RESUME-*; SIGNING-RESUME-VERIFICATION.json
  e SIGNING-RESUME.md. Nenhum ensaio pendente. Total ainda6,557s acima180s;
  não declarar meta atingida, nem apagar primeira falha/rodada anterior196s.
- Próximo: recuperação durante cálculo sequencial/checkpoint incompleto e
  orçamento global de retomadas; fixture de seleção de decoys mostrou falha
  antes de funding que precisa ser considerada na confiabilidade. Não ficar
  só nos testes: preparação com participantes independentes, revisão do modelo
  adversarial/prova de atomicidade e integração ao dom-interopd seguem requisitos
  obrigatórios. Sem usar abandono privado para recovery pós-exposição.

- Commit3cd997a salvou completed-opening/signing-staging recovery, Soren-only.
- AUDITORIA CRÍTICA posterior: ao estudar checkpoint durante solve, upstream
  SolvePuzzle revelou Exp(w,2,N)+contador big.Int alocados a cada passo.
  Implementado direct_fast_open_audit.go (Go Mul/Mod com temporários) e modo
  local direct-restore-fast-audit após MESMA prova/verificação. Callback opcional
  não vem do peer. Original open continua SolvePuzzle; decodePlaintext comum
  preserva validações. Binário separado target/recovery-research/direct-fast-audit;
  helper nativo antigo não foi sobrescrito. Não implementou ainda mid-solve resume.
- 26 testes Go (24 anteriores+2 diferenciais/política), vet/build passaram
  session90718; FAST-OPEN-AUDIT-CHECKS.json. Mesma cápsula encerrada da native
  PID1580411 (outputs já gastos): fastGo29,284s, referência32,167s, fastGo32,852s;
  escalar igual, toda prova verificada a cada processo. PIDs1590037,1590168,
  1590518/session16293 exit0. FAST-OPEN-AUDIT-RESULT.json registra hashes/pressão.
- Auditor independente direct_montgomery_audit.c usa OpenSSL Montgomery com
  exatamente10M squarings, só N/U/T públicos. Python finaliza V público e
  libsodium confere scalar*G == ponto original. Sem fatores, share fornecida,
  produtor novo, funding ou deadline novo. C -O3 -Wall -Wextra -Werror -lcrypto;
  1/2/17/200000 passos iguais a pow modular Python; seis entradas inválidas
  recusadas. Sem gmp headers/pkg-config; usou OpenSSL3.0.13 já instalado.
- Native arithmetic C/session95191 exit0, PIDs1592789/1592815: laço7,375/7,390s,
  COM processo/extração/checkEd25519 7,475/7,492s. Mesma cápsula/job original,
  sem segredos escritos em artefatos. MONTGOMERY-OPEN-AUDIT-RESULT.json.
- O MÍNIMO ADVERSARIAL30s DO PERFIL ATUAL ESTÁ REFUTADO, não só pendente.
  Não reduzir a constante para8 nem aumentarT por regra de três alegando
  segurança:8 é teto observado de conclusão, não mínimo. Hardware adversarial,
  primeira divulgação e margem honesta integral precisam fundamentação.
  Testes anteriores continuam funcionais/condicionais, não atomicidade.
  README/STATUS e recovery-audit/FAST-OPEN-AUDIT.md dão prioridade a esta falha.
- Teste tests/recovery_time_bounds.rs mostra que perfil30 aceita release d+10
  e offers-ready d+28, apesar de recuperação observada caber antesd+8; ambos
  seriam recusados sob essa possibilidade. É contraexemplo de premissa/guard,
  NÃO ainda corrida de roubo financiada.11 testes Rust passaram session67911.
  Somente comentário no example marca perfil histórico refutado; mantido para
  reproduzir ensaios owned/regtest, sem permissão de funding real.
- Próximo: reproduzir corrida nativa com adversário abrindo cedo, refund XMR
  vencendo primeiro claim e possível extração do witness/claim DOM. Honesto
  conserva guard/journals; adversário não respeita locks locais. Considerar
  tempos de assinatura/RPC/inclusão, não afirmar perda nativa sem medir.
  Revisar/calibrar ou substituir recuperação temporizada com fundamentos;
  preservar missão de mecanismo NOVO DOM↔XMR, sem voltar ao grafo antigo como
  otimização ou introduzir BTC/novo custodiante. Preparação independente,
  prova de atomicidade e dom-interopd continuam obrigatórios. Há ações concretas;
  missão ativa, não marcar blocked/complete por esta descoberta.

As instruções globais de `/home/leonardov/AGENTS.md` continuam aplicáveis,
inclusive controle de escopo, verificações finais e identidade de publicação.

- Auditoria FAST-RACE de 27/09/2026: modo explícito
  `direct-pair-fast-race-audit` no example usa verificador Go separado com
  abertura C OpenSSL Montgomery. Producer não recebe configuração do avaliador;
  setup e prova completos são verificados antes do funding. O participante
  honesto mantém `PreparationGate`, consulta nativa de key image livre,
  `AssumedXmrRecoveryWindow` e `InitialClaimJournal` durável antes da exposição.
  Adversário usa somente sua share local e a share pública recuperada.
- Ensaio owned offline PID2704556/Go+C PID2704623: saída0, total83,273 s,
  abertura7,369 s, resolução XMR após exposição0,080 s. d=1790526437;
  adaptors prontos d+10, clock/unspent aceitos d+17, divulgação/refund XMR
  observado d+18, antes do mínimo suposto d+30. Refund XMR incluído e dois
  outputs gastos; claim honesto rejeitado como gasto; assinatura perdedora
  permitiu claim DOM altura7 e gasto altura8. O dono DOM original não recuperou
  DOM nem recebeu XMR. `clsag-lab/FAST-RACE-AUDIT.md` e cinco JSONs
  `FAST-RACE-AUDIT-1790526373283002881-*` guardam tempos/hash/PIDs/grupo vazio.
- A ordem de entrega da transação completa ao peer antes de sua inclusão no
  `monerod` é modelada pela callback de envio; não houve medição de relay P2P
  ou interceptação de RPC privado. Aceitação/rejeição/inclusão e gastos são
  nativos. Não declarar probabilidade de ataque na mainnet. O binário medido
  marcou incorretamente `negative_control:true` num checkpoint; rótulo fonte
  corrigido após medição sem alterar fluxo. Hashes do artefato correspondem
  ao binário e fontes da rodada, não ao código após essa correção de rótulo.
- O perfil30 s está refutado também por perda de atomicidade financiada sob
  aquele escalonamento; não usá-lo em operações reais, não trocar30 por8 e
  declarar segurança. Próximo trabalho obrigatório: substituir/fundamentar
  mecanismo de recuperação e janelas, preservar a perna exclusiva DOM↔XMR,
  integrar daemons e participantes independentes e provar segurança/prazo.
- `labs/dom-xmr-direct/ARBITRATION-REPLACEMENT.md` documenta a próxima direção
  após consultar Farcaster, Athanor e COMIT: talvez retirar inteiramente a
  devolução XMR antecipável e usar uma arbitragem DOM com Ready/Claim/Refund
  excludentes. O consenso DOM ATUAL só tem kernel plain, coinbase e
  height-locked; esse árbitro exige nova regra de consenso ou primitiva
  equivalente, não flags locais. Ainda é pesquisa, não implementação.
  `arbitration_model.py` + três testes demonstram outra corrida: segredo
  divulgado por claim DOM perdedor pode permitir DOM+XMR ao mesmo ator.
  Evitar a corrida depende de limite de inclusão DOM demonstrado; um bloco
  além da hipótese a reproduz. Não alegar segurança nem meta de 2–3 minutos.
- DXF1 é o mecanismo novo preparado após essa pesquisa. O núcleo não fica mais
  privado no laboratório: `crates/dom-xmr-fast-handoff` contém estado, journal
  v4 e a autoridade/ports, sem dependência do `dom-interopd` ou de outra perna.
  O laboratório reexporta o mesmo código. A autoridade grava exposição DOM
  antes do RPC, exige reabertura após o compromisso XMR, grava txid e SHA-256
  dos bytes XMR assinados antes do RPC e exige restauração byte a byte; reorg
  mantém Refund proibido e força republicação do mesmo Claim pela autoridade.
  O início absoluto dos 180 s fica no binding durável; a autoridade lê o
  relógio, conserva observações não decrescentes no journal e falha fechado em
  restart vencido ou recuo do relógio, sem aceitar um contador reiniciado.
  O DXF1 agora também possui o port de submissão XMR: somente a autoridade
  chama o `monerod` com os bytes persistidos; o coordenador não pode registrar
  uma admissão fornecendo apenas um txid. Os construtores e escritores do
  journal são privados ao crate; fora dele, o journal é somente leitura.
  Resposta divergente falha fechado. O port XMR recebe um deadline absoluto
  menor que a janela restante; sem dois segundos inteiros disponíveis, nenhum
  RPC é iniciado. Um segundo completo fica reservado para validar e sincronizar
  a admissão, e resposta tardia não conclui o journal.
  Teste local financiado com reorg, já com a reserva de fsync, passou em
  18,678 s ativos / 200,861 s total.
  Três contêineres isolados passaram em 21,400 s ativos / 174,060 s protocolo /
  210,464 s runner, com namespaces, estados e wrapping
  keys separados. Limite
  condicional atual: Claim em até 57 blocos e seis confirmações antes da altura
  de Refund. Falta testar três hosts físicos e coordenar ativação pública; não
  declarar produção ou finalidade PoW em segundos.
