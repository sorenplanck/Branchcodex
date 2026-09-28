# DXP1 — novo mecanismo direto DOM↔XMR

**Atualização de segurança: o perfil temporal atual foi refutado.** A cápsula
de 10 milhões de quadraturas foi aberta em menos de oito segundos com
OpenSSL, contra os 30 segundos mínimos adversariais assumidos pelo fixture.
O perfil não pode autorizar operações reais. Os testes de assinaturas e
retomadas anteriores permanecem válidos como testes funcionais; não comprovam
atomicidade. A [corrida nativa](clsag-lab/FAST-RACE-AUDIT.md) também reproduziu
perda de atomicidade sob divulgação completa ao peer antes da inclusão XMR,
mesmo com relógio, input livre e journal honestos aceitando o claim.
Evidência da abertura: [auditoria de abertura](recovery-audit/FAST-OPEN-AUDIT.md).

Proposta experimental, ainda não implementada como swap. O objetivo é criar
um mecanismo novo, seguro e rápido, independente do executor atual, com a
troca diretamente entre DOM e XMR. Correção do operador em 26/09/2026:
BTC não participa desse fluxo. O operador aceita cerca de dois
minutos e esclareceu que as duas horas observadas eram dos testes no GitHub.
Um modelo rápido não comprova essa meta.

O protocolo completo prevê pernas DOM↔Bitcoin, DOM↔Solana, DOM↔EVM e
DOM↔Monero. Esta missão desenvolve somente a nova perna DOM↔Monero. A perna
DOM↔Bitcoin, informada pelo operador como praticamente finalizada, está fora
das alterações desta missão.

## Isolamento

Trabalho em `/home/leonardov/DOM-XMR-Segundos`, na branch
`research/dom-xmr-seconds`. Clone independente de
`/home/leonardov/Branchcodex-two-workflows`, fixado em
`964e030b190c4b1cce3f7f40597de88c4389a383`, sem alternates/hardlinks e sem
remote apontando para a pasta do outro agente. Arquivos não rastreados e
ignorados não integram um clone Git. A única alteração fora do laboratório
é a seleção de verificador em `dom-scriptless-bulletproof`: finalização MPC
com `extra_commit` vazio usa o verificador plain; o caminho com dados extras
continua exigindo esses dados. Essa dependência é necessária para provar a
nova reserva nativa comum. Consenso, nó e executor anterior não foram alterados.

## O que torna esta proposta diferente

A variante atual usa **reservas de uso único, devolução DOM pré-assinada por
altura e recuperação temporizada XMR**, com assinaturas adaptadoras vinculadas
ao mesmo segredo. A devolução pretendida é do próprio ativo depositado. Isso substitui
a dependência do grafo DOM de cancel/refund/compensação como mecanismo da nova
perna; não é uma otimização desse grafo ou de seu armazenamento. O candidato
anterior também cifrava a share DOM; a abertura antecipada motivou sua substituição
pela [devolução DOM nativa](clsag-lab/DOM-HEIGHT-REFUND.md), sem divulgar essa share.

Essa proposta depende de primitivas ainda não implementadas aqui. A principal
é uma cápsula verificável que disponibilize a share correta de recuperação
somente depois do prazo criptográfico. Um relógio local ou `sleep` não
implementa essa propriedade. O mecanismo pode precisar ser rejeitado se sua
criptografia, implantação ou modelo de disponibilidade não forem viáveis.

Preparar reservas antes da troca é uma **hipótese em estudo**, não uma escolha
já aceita pelo operador. Não se esconde essa espera para afirmar dois minutos.
Também não se confunde receber capacidades de claim com liquidação on-chain.

## Sequência bilateral candidata

A deposita DOM e recebe XMR; B deposita XMR e recebe DOM.

1. Autenticar um plano imutável contendo redes/genesis, participantes,
   quantias, taxas, destinos, reservas, prazos e parâmetros criptográficos.
2. Gerar shares exclusivas para cada reserva e verificar a recuperação antes
   de financiar. Nenhum participante pode conhecer sozinho a chave agregada.
3. A recebe a devolução DOM pré-assinada, travada na altura aprovada, sem
   receber a share DOM de B. B recebe a cápsula da share necessária à recuperação
   XMR. A possibilidade mais cedo de devolver DOM deve vir depois da janela
   XMR, com margens demonstradas. Essa relação entre altura e tempo ainda não
   está resolvida; não se comparam diretamente suas unidades.
4. Financiar as reservas e verificar os outputs, sua maturidade, disponibilidade,
   contexto e política de reorg. Esta etapa continua dependendo das redes.
5. A gera o segredo `t` e prova o vínculo entre os pontos nas curvas usadas.
   A oferece a B um claim DOM adaptado a `t`; B o verifica antes de entregar
   a A um claim XMR adaptado ao mesmo segredo e plano.
6. A completa o claim XMR. B extrai `t` usando **o adaptor que B forneceu e
   a assinatura final correspondente**, e completa o claim DOM.
7. Verificar ambos os resultados nas redes. Se não houver sucesso, cada
   depositante deve recuperar o próprio ativo pelo caminho acordado: devolução
   DOM por altura e recuperação XMR temporizada.

Todas as chaves são exclusivas à reserva. Nonces são consumidos uma única vez
e a publicação depende de persistência anterior. Reabertura não estende prazos
nem autoriza refazer material consumido. Um claim já divulgado não expira
porque a aplicação passou de uma fase a outra.

Essa sequência ainda precisa de uma prova do protocolo de preparação: quais
mensagens podem ser entregues em cada prefixo, o que uma interrupção permite
a cada parte e como validar as cápsulas sem expor suas shares. Ainda falta
validar o setup e a recuperação. O laboratório já contém assinatura conjunta
e uma construção nativa restrita, descritas abaixo; elas não tornam a sequência
um swap completo.

### Estado da recuperação temporizada

O perfil curto atual já produziu um contraexemplo financiado: uma parte abriu
a cápsula cedo, devolveu DOM e recebeu XMR; a claim DOM válida da contraparte
foi rejeitada por input consumido. Esse perfil não serve como configuração de
swap seguro. A [auditoria de abertura antecipada](clsag-lab/EARLY-RECOVERY-AUDIT.md)
registra a sequência, o resultado e os limites do ensaio. As primitivas continuam
experimentais; o mecanismo ainda precisa de preparação e margens temporais seguras.

A primeira implementação pública de VTC auditada não foi aceita como backend.
Na revisão `b18a1c7153abcff407d6d8469de1f6278fabaa1e` de
`primefactor-io/vtc`, um teste local construiu uma cápsula aceita pela
verificação que, ao ser forçada, recupera um escalar que não corresponde ao
ponto público comprometido. O teste está em
[`recovery-audit/vtc_fixed_basis_test.go`](recovery-audit/vtc_fixed_basis_test.go)
e a nota completa em [`recovery-audit/README.md`](recovery-audit/README.md).

Consequência para o DXP1: a recuperação deve verificar a ligação de cada
puzzle com a share pública e deve resolver exatamente um conjunto aceito para
reconstrução. A etapa final também precisa conferir `share * G` e
`recovered * G == committed_point` antes de tratar a cápsula como válida.

O crate `clsag-lab` agora contém `recovery`, uma camada Feldman para essa
validação. Ela gera planos de laboratório, verifica cada share recuperada contra
o compromisso público, reconstrói usando os índices reais abertos e rejeita
shares forjadas, índices duplicados ou pontos inválidos. O plano e a janela têm
bindings próprios para assinatura pela rota. Isso ainda não é a cápsula
temporizada: falta conectar um backend de atraso criptográfico que entregue as
shares somente depois do prazo.

## Experimento histórico de composição — fora do fluxo atual

Esta seção documenta uma exploração anterior do modelo Python. Após a
correção do operador, ela não é requisito nem etapa do mecanismo DOM↔XMR.
O fluxo executável em desenvolvimento usa somente DOM e XMR.
Os testes desse experimento foram preservados em `historical/` e são executados
explicitamente; o comando padrão `model.py` e a suíte principal usam DOM/XMR.

No caso BTC→DOM→XMR, com três participantes:

| Ator | Deposita | Recebe |
| --- | --- | --- |
| 0 | BTC | XMR |
| 1 | DOM | BTC |
| 2 | XMR | DOM |

O ator 0 controla inicialmente `t`. Os claims condicionais são entregues na
ordem BTC, DOM, XMR; cada intermediário precisa verificar e reter sua entrada
antes de liberar a saída. A execução se propaga no sentido inverso: XMR,
DOM, BTC. Nenhum intermediário depende de conseguir extrair um segredo de
uma assinatura de outro elo cujo adaptor ele não possui.

Cada plano deve vincular a rota inteira e o elo local. Dois swaps com segredos
independentes não formam uma rota atômica. Perda de uma mensagem deve permitir
retomada ou observação da assinatura correspondente na rede. Direções inversas
exigem validação própria dos formatos de assinatura e recuperação; permutar
nomes no modelo não demonstra essa compatibilidade.

## Modelo de corridas implementado

Na configuração padrão, `model.py` começa **depois** da preparação, assumindo reservas maduras,
ofertas criptograficamente válidas e recuperação inacessível antes do prazo.
Cada ator paga o ativo `i` e recebe o ativo anterior no ciclo. O explorador
enumera publicação, silêncio, atrasos de inclusão e escolha de transações
concorrentes. Adversários podem se associar e compartilhar segredos privadamente.
Participantes honestos observam somente a assinatura do claim de sua saída.

Um limite explícito `I_i` supõe que uma submissão honesta seja finalizada ou
perca para um conflito em até esse intervalo. Não é uma promessa da blockchain.
`O` cobre observação e reação. A entrada de um intermediário precisa sobreviver
à última corrida possível sobre sua saída:

```
início + I_último < R_último
R_entrada > R_saída + I_saída + O + I_entrada
```

As unidades são ticks abstratos. Não se comparam diretamente alturas DOM e
XMR; a conversão conservadora de prazos reais ainda precisa ser construída.
Reorgs explícitos, preços, taxas, assinaturas, persistência, perda de mensagens
antes da preparação e a segurança das cápsulas estão fora desse modelo.

Atualização da variante direta: `funded_at` e `ready_at` representam os instantes
fixos assumidos de disponibilidade dos inputs e ofertas, desde a divulgação
da cápsula. `honest_recovery` separa o limite mais tardio do honesto do mais cedo
do adversário. Isso permite refutar janelas consumidas pela preparação e
velocidades assimétricas, mas não prova o protocolo de preparação. A
[auditoria temporal](TIMING-BOUND-AUDIT.md) registra um novo contraexemplo e a
restrição inferior condicional extraída dos timestamps DOM. A média alvo dos
blocos não é uma garantia mínima para escolher uma altura de devolução.

Experimento reproduzível importante: no par DOM/XMR, usar os prazos `(6, 3)`
com `I=(1,1)` e `O=1` admite perda para B: A recebe XMR e devolve seu DOM.
Igualdade no limite não basta. A variante `(7, 3)` tem margem estrita e é
explorada nos três casos de corrupção que deixam ao menos um ator honesto.
Isso é um resultado limitado do modelo, não prova geral do DXP1.

Outro controle negativo interrompe os claims quando começa a recuperação
(`resume_claim_after_recovery=False`). Ele encontra perda mesmo com margens
estritas. O candidato continua observando e reagindo à assinatura concorrente
durante o refund. Essa variante é motivada pela análise do PipeSwap; ainda
depende da hipótese de disponibilidade e dos limites de inclusão do modelo.

```sh
python3 -B labs/dom-xmr-direct/model.py
python3 -B -m unittest discover -s labs/dom-xmr-direct -p 'test_*.py' -v
```

O programa recusa uma exploração que ultrapasse seu limite; não transforma
busca incompleta em sucesso. Os testes também exigem troca efetiva quando todos
seguem o protocolo, em vez de aceitar que todo caso termine em cancelamento.

## Experimento criptográfico isolado

[`clsag-lab/`](clsag-lab/README.md) implementa uma hipótese de assinatura CLSAG
adaptada a um segredo. O teste completa a assinatura, valida-a usando o
verificador upstream inalterado e extrai o segredo da assinatura correspondente.
Também testa a propagação direta desse segredo entre DOM/Schnorr e XMR/CLSAG
nos dois sentidos, usando uma prova secp256k1/Ed25519 existente.

A assinatura conjunta experimental mantém duas shares separadas. O módulo
nativo constrói a transação XMR completa com um input e dois outputs padrão,
valida CLSAG, Bulletproofs+ e valores, e testa reconhecimento pelas carteiras.
Há também um executor de experimento exclusivamente em daemon regtest próprio.
O módulo `recovery` valida shares de recuperação por compromissos Feldman e
reconstrói o segredo com os índices realmente abertos. O binding do plano e da
janela evita parâmetros soltos na composição, e a verificação evita a classe de
erro encontrada na auditoria de VTC.

Os módulos `dom_recovery` e `xmr_recovery` também ligam essa reconstrução a
uma share individual de cada reserva. Ensaios separados financiam DOM/XMR em
nós próprios, encerram o emissor dos puzzles, descartam a share original de
um participante e executam um solver público. A share recuperada permite
devolução nativa e gasto posterior. Os resultados estão em
`clsag-lab/DOM-RECOVERY-REGTEST-RESULT.json` e
`clsag-lab/XMR-RECOVERY-REGTEST-RESULT.json`. Não comprovam uma janela segura
de recuperação, a preparação justa ou a atomicidade do par.

O módulo `native_dom` valida a transação DOM completa pelo consenso e exige
o mesmo corpo antes de extrair o segredo. Os testes diretos DOM↔XMR já usam
transações nativas serializadas, ainda com inputs DOM e anéis XMR de fixtures.
O exemplo `regtest_claim` financia ambas as pernas em nós locais: observa a
primeira claim, extrai o segredo e inclui a contraparte. As direções XMR→DOM
e DOM→XMR foram executadas. Verifica também gastos
posteriores dos dois outputs recebidos e rejeição de gasto duplo DOM.
Usa mineração controlada, setup centralizado e ainda não exerce recuperação.
Setup autenticado, persistência, cápsulas de recuperação e prova de segurança
seguem pendentes. Essas claims não demonstram atomicidade econômica.

## Tempo e critérios de conclusão

O alvo médio de bloco Monero é 120 segundos e outputs novos precisam atingir
idade mínima de dez blocos para novo gasto. Criar e gastar uma reserva nova
não tem garantia de terminar em dois minutos. Fontes primárias:
[constantes do Monero](https://github.com/monero-project/monero/blob/master/src/cryptonote_config.h)
e [especificação técnica](https://docs.getmonero.org/technical-specs/).

O novo mecanismo só estará concluído depois de implementar os dois sentidos
DOM↔XMR e a ligação direta entre as duas pernas, verificar cápsulas/adaptors e transações
nativas, demonstrar recuperação não cooperativa e medir a operação completa
com resultado econômico final. Preparação, negociação, execução, confirmações
e recuperação precisam ter medições separadas. A pesquisa em
[RESEARCH.md](RESEARCH.md) não apresentou evidência de um swap nativo completo
em dois minutos que possa simplesmente ser transplantado.

Próxima obrigação técnica: demonstrar uma janela segura desde a primeira
divulgação dos puzzles e compor as duas recuperações com claims concorrentes.
O solver atual recebe bytes públicos antes do financiamento e não impõe um
início posterior: iniciar a medição depois de depositar não reinicia seu trabalho.
As aberturas locais de cerca de um segundo não demonstram proteção durante
preparação, maturidade ou confirmações. A ausência dessa garantia impede tratar
os ensaios financiados como um protocolo seguro para fundos reais.
