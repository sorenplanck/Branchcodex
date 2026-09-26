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
  executável de teste. A integração do mecanismo novo ao dom-interopd
  (daemon de interoperabilidade) ainda não está concluída, e a composição
  XMR↔DOM↔BTC não foi validada ponta a ponta. Não modificar as outras pernas.
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

As instruções globais de `/home/leonardov/AGENTS.md` continuam aplicáveis,
inclusive controle de escopo, verificações finais e identidade de publicação.
