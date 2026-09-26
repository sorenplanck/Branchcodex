# Pesquisa de projetos XMR para o mecanismo novo

Consulta: 26 de setembro de 2026. Fontes primárias; uma afirmação de um projeto
não equivale a uma auditoria independente ou a uma medição feita neste trabalho.
O novo laboratório `clsag-lab/` adapta o transcript CLSAG de monero-oxide;
a revisão e a licença estão registradas em `clsag-lab/NOTICE.md`.

## Comparação

| Projeto | Construção observada | Aplicação ao novo DOM/XMR | Limite relevante |
| --- | --- | --- | --- |
| COMIT / Eigenwallet | Segredos vinculados por provas entre curvas e assinaturas adaptadoras; Eigenwallet sucede o repositório COMIT | Reaproveitar primitivas revisadas e tratar desconexão como estado recuperável | Continuação de um protocolo existente não prova uma liquidação em dois minutos |
| BasicSwap | OtVES; lock da chain com scripts primeiro; lock XMR em chave combinada depois; liberação condicionada à confirmação | Separar oferta de assinatura verificável de sua liberação; manter contexto por troca | Continua esperando confirmação e precisa de funções que DOM deve realmente suportar |
| Farcaster | Papéis distintos para a chain que arbitra e a chain sem scripts; setup explícito e recuperação/punição | Mapear capacidades nativas antes de projetar a máquina de estados; separar capacidade real de política local | Recuperação econômica por punição não equivale à devolução do XMR original |
| AthanorLabs | Contrato EVM com estados, prazos e divulgação de segredo em claim/refund | A exclusão entre caminhos concorrentes deve ser efetiva | As regras do contrato não podem ser simuladas por flags locais no DOM |
| Serai | Pools e carteira multisig por limiar, protegidos economicamente por validadores | Bibliotecas e organização de assinaturas distribuídas são referências | Modelo de confiança diferente de swap bilateral sem custodiante |
| PayMo | Canais financiados previamente e recuperação com primitivas temporizadas | Base de pesquisa para substituir o grafo de punição por recuperação do próprio ativo | Precisa de adaptação criptográfica concreta, hipóteses de tempo e preparação prévia |

## COMIT e Eigenwallet

O [repositório Eigenwallet](https://github.com/eigenwallet/core) declara a origem
no COMIT e contém componentes separados de protocolo, banco, transporte,
orquestração e carteira. O
[changelog](https://github.com/eigenwallet/core/blob/master/CHANGELOG.md)
descreve Hermes como um meio de transmitir a assinatura encriptada pela rede
Monero, reduzindo a dependência de P2P depois do setup. A lição é fornecer um
caminho de recuperação de mensagens críticas; isso não elimina espera de bloco.

A análise histórica do COMIT sobre
[pré-assinatura XMR](https://comit.network/blog/2021/07/02/transaction-presigning/)
explica a dependência do hash assinado em relação aos índices dos outputs.
Ela é de 2021: não se usa seu texto como prova isolada de uma limitação atual.
O verificador e construtor nativos selecionados precisam demonstrar hoje como
obtêm e autenticam os índices e se conseguem preparar a recuperação antes
do financiamento. O simples conhecimento da chave pública não resolve isso.

## BasicSwap

O [protocolo de adaptor signatures](https://github.com/basicswap/basicswap/blob/master/doc/protocols/adaptor_sig.md)
descreve uma assinatura verificável encriptada, sua conclusão com um segredo
e a extração desse segredo pela comparação com a assinatura final. O documento
exige confirmação antes da liberação do lock da chain com scripts. Os papéis
de ofertante/comprador são distintos dos papéis criptográficos. Para DXP1,
isso exige vincular cada assinatura a papel, ativo, reserva, destinatário e
plano; encontrar uma ordem de mensagens mais curta não autoriza liberar o
segredo antecipadamente. A especificação consultada é marcada WIP.

## Farcaster

As [premissas de protocolo](https://github.com/farcaster-project/RFCs/blob/main/00-introduction.md)
separam a chain que impõe as restrições da chain sem esses recursos. O texto
também explica a punição por ausência da parte que deveria executar o refund.
É especialmente relevante para não importar ao DOM capacidades que só existem
em scripts Bitcoin.

O [setup criptográfico](https://github.com/farcaster-project/RFCs/blob/main/07-cryptographic-setup.md)
separa verificação de adaptor, conclusão e extração, com prova cross-group
quando necessário. A [especificação de transações](https://github.com/farcaster-project/RFCs/blob/main/08-transactions.md)
apresenta alternativas Bitcoin e suas verificações. Ao aplicar essas lições à
perna DOM↔XMR, é preciso validar o formato nativo DOM; compartilhar a curva
secp256k1 não torna transações ou recursos de script intercambiáveis.

## AthanorLabs

A [descrição do protocolo](https://github.com/AthanorLabs/atomic-swap/blob/master/docs/protocol.md)
explica a corrida em que um segredo aparece antes de a transação confirmar.
O [contrato](https://github.com/AthanorLabs/atomic-swap/blob/master/ethereum/contracts/SwapCreator.sol)
impõe estados e prazos na EVM. Esta é uma referência para o requisito de
exclusão, não uma receita transplantável a uma chain scriptless.

O [guia mainnet](https://github.com/AthanorLabs/atomic-swap/blob/master/docs/mainnet.md)
informa aproximadamente 20–25 minutos, atribuídos ao tempo de bloco. É uma
estimativa do projeto, não um benchmark DOM. O repositório consultado estava
arquivado; serve como referência de construção, não como dependência nova
automaticamente escolhida.

## Serai e PayMo

O [README de Serai](https://github.com/serai-dex/serai) descreve fundos em
multisig por limiar e proteção econômica. Adotar esse modelo mudaria a confiança
do usuário. Não foi escolhido como atalho para afirmar atomicidade bilateral.

[PayMo](https://eprint.iacr.org/2020/1441) oferece a direção mais diferente do
grafo atual: canais e recuperação temporizada. Seu §2.4 discute a integração
com índices de outputs e uma alternativa baseada em divulgação temporizada de
share. Isso motiva o candidato de reservas individuais, mas não implementa as
cápsulas do DXP1. As medições do artigo não são medições de swaps DOM/XMR e
não garantem finalidade nativa em segundos.

## Decisões e obrigações resultantes

1. Desenvolver o protocolo novo em módulo separado; não reescrever os testes
   do protocolo atual para produzir uma aparência de rapidez.
2. Reutilizar primitivas verificadas quando compatíveis, preservando contexto,
   propósito, domínio, curvas, nonces e validação de transações.
3. Projetar sucesso e devolução antes de implementar funding. Resgate do ativo
   original e compensação em outro ativo são resultados diferentes.
4. Vincular diretamente as claims DOM e XMR ao mesmo plano e segredo, com
   prazos que protejam ambos os participantes. BTC não integra o mecanismo;
   a exploração anterior de três ativos permanece somente como registro histórico.
5. Usar o modelo atual apenas para refutar cronogramas inseguros. Ele já produz
   um contraexemplo quando a margem DOM fica curta; não autentica ofertas,
   cápsulas, transações ou consentimento de preparação antecipada.
6. Verificar a primitiva temporizada concreta antes de adotar o candidato.
   Precisam ser resolvidos geração dos parâmetros sem trapdoor indevido,
   prova de share correta, domínio escalar, custo do adversário, disponibilidade,
   reinício e o tempo já gasto desde a entrega da cápsula.
7. Medir toda a operação. Nenhuma fonte consultada comprovou a meta de dois
   minutos para uma troca nativa completa DOM↔XMR partindo de novas reservas.

## Auditoria de VTC para recuperação

O artigo "Verifiable Timed Signatures Made Practical" descreve compromissos
temporizados para chaves de assinatura em que a verificação abre um subconjunto
aleatório e a prova de soundness depende de puzzles bem formados que correspondem
às shares públicas. A implementação Go
[`primefactor-io/vtc`](https://github.com/primefactor-io/vtc), revisão
`b18a1c7153abcff407d6d8469de1f6278fabaa1e`, foi auditada localmente antes de
qualquer integração.

O teste [`recovery-audit/vtc_fixed_basis_test.go`](recovery-audit/vtc_fixed_basis_test.go)
forja o primeiro puzzle para cifrar uma share escalar diferente da share pública
mantida no compromisso. Quando o Fiat-Shamir não abre esse índice, a verificação
aceita a cápsula. Em seguida, `SolveTimedCommitment` resolve sempre os primeiros
`t` puzzles e reconstrói um escalar que não satisfaz `recovered * G == pk`.
Execução observada:

```text
accepted forged commitment with opened indexes [2 3 5 6 7 8 11 12 14 17]; recovered scalar no longer matches the committed public point
--- PASS: TestAcceptedCommitmentCanRecoverWrongScalar (38.96s)
```

Decisão: essa implementação não entra como backend de recuperação DXP1. Ela
continua útil como referência de benchmark e de formato geral, mas a construção
adotada precisa provar e verificar a relação entre puzzle, share escalar e
share pública para o conjunto que será resolvido. A recuperação também deve
rejeitar qualquer abertura cujo escalar final não corresponda ao ponto público
do plano.

## Pesquisa adicional: corridas e composição

[PipeSwap, S&P 2025](https://eprint.iacr.org/2024/881) descreve o ataque
double-claiming contra Universal Atomic Swaps: iniciar o refund não revoga
o claim já autorizado. O adversário pode ganhar essa disputa e recuperar
também sua própria entrada. O artigo propõe fluxos em dois saltos; seus
benchmarks usam Schnorr/ECDSA, não demonstram compatibilidade CLSAG/DOM.

O modelo DXP1 já permite que o claim vença o refund após o prazo. A nova
variante negativa `resume_claim_after_recovery=False` verifica também a falha
de parar de reagir ao segredo ao iniciar a recuperação. A política candidata
continua reagindo e exige margens de inclusão/observação. Isso cobre essa
variante abstrata do ataque; não demonstra resistência geral ao PipeSwap,
nem valida cápsulas temporizadas ou disponibilidade contínua.

[ParaSwap, USENIX Security 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/xiao-danlei)
estuda preparação e execução em paralelo, com segredo colaborativo e novo
lock quando falta tempo. Seus experimentos citam Bitcoin, Ethereum,
Avalanche e Binance Smart Chain. A aplicação ao DOM/XMR exigiria validar
as novas dependências de transações, maturidade e recuperação; não foi
adotado como protocolo já compatível.

A proposta de [relative locks do Monero Research Lab](https://github.com/monero-project/research-lab/issues/161)
discute recursos futuros com FCMP++. É uma proposta, não autorização para
assumir que o Monero atual já fornece esses locks ou que seu `unlock_time`
implementa recuperação condicional. O protótipo atual usa o verificador CLSAG
fixado na revisão do projeto, sem alterar consenso.

## Componente novo em implementação

`clsag-lab/` experimenta um claim XMR adaptado a `t`: os compromissos do nonce
incluem `tG` e `tHp(P)`, vinculados por uma prova de igualdade na mesma curva.
A assinatura completada é conferida pelo verificador CLSAG externo e o segredo
é extraído da resposta correspondente à oferta. O laboratório também testa
sua composição criptográfica diretamente com as primitivas DOM existentes.

Isso difere do mecanismo anterior, que obtém a revelação na claim DOM e usa
a share revelada para um sweep XMR. O candidato novo investiga a própria
assinatura XMR como origem verificável da revelação, para propagar a execução
pelos elos. O laboratório agora usa `ClsagMultisig` com shares separadas e o
construtor nativo para uma transação restrita de um input e dois outputs.
As verificações não estabelecem preparação justa ou recuperação temporizada.
Setup autenticado e persistência continuam pendentes; nenhum fundo real é usado.

O [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html) reforça que nonces de
assinatura por limiar não podem ser reaproveitados. O adaptador consome o estado
de cada rodada, incluindo falhas; isso ainda não protege snapshots, rollback ou
crashes sem armazenamento durável. A adaptação CLSAG não é uma ciphersuite
padronizada por esse RFC. As operações concretas são conferidas no código
primário fixado de `monero-clsag` e `modular-frost` 0.11.0.

## Referência local de desempenho, sem modificar o mecanismo anterior

A medição posterior dos 99 candidatos identificou o custo que cresce com o
atraso individual. A investigação seguinte está em
[DIRECT-PLAINTEXT-RESEARCH.md](recovery-audit/DIRECT-PLAINTEXT-RESEARCH.md):
prova do vínculo entre ciphertext e ponto público, com referências primárias,
relações explícitas e testes adversariais necessários. Ainda não é backend
integrado ou aprovado para financiar; o mecanismo atual conserva seu orçamento.

A execução [35932737683, job 107422833451](https://github.com/sorenplanck/Branchcodex/actions/runs/35932737683/job/107422833451)
usou `5922e34016d1bb481dfe6d8834e689b741dd2ce7`, anterior ao clone atual.
Registrou 78.268 s de preparação e 937.360 s de execução incompleta antes de
falhar, sem claims finais. O primeiro funding `committed` foi observado em
444.808 s. Esses logs sustentam investigar o caminho normal, mas não dizem
quanto do intervalo não instrumentado pertence a cada componente, nem
representam uma troca bem-sucedida. Não foram disparados novos workflows.
