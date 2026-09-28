# Substituição da recuperação temporizada XMR: condições de projeto

Estado em 27/09/2026: **candidato experimental implementado, ainda não
aprovado nem ativado em rede**.
O ensaio [`FAST-RACE-AUDIT.md`](clsag-lab/FAST-RACE-AUDIT.md) mostrou que o
candidato atual não é atômico quando a share XMR é recuperada cedo e o peer
recebe os bytes completos do claim antes de sua inclusão. O relógio e o
journal honestos não impõem uma restrição ao peer nem ao consenso XMR.

## Restrição revelada pelo contraexemplo

Se (1) o adversário consegue assinar uma devolução XMR válida enquanto o
claim honesto XMR ainda pode ser divulgado, (2) os bytes desse claim revelam
o witness do claim DOM ao peer, e (3) o claim DOM independe da inclusão XMR,
então existe a ordem: divulgar bytes → incluir devolução XMR → rejeitar
claim XMR → incluir claim DOM. A segurança exige eliminar ao menos uma dessas
três condições por uma restrição **de consenso ou criptográfica**. Política
local, journal, consulta de key image livre e espera em um único daemon não
eliminam essa ordem; a corrida nativa confirmou isso para o perfil atual.

## Referências e consequência para DOM

As [premissas do Farcaster](https://github.com/farcaster-project/RFCs/blob/main/00-introduction.md)
separam a chain que arbitra com lock/refund temporal da chain sem scripts,
como Monero. O [protocolo de Athanor](https://github.com/AthanorLabs/atomic-swap/blob/master/docs/protocol.md)
usa um estado `Ready` e caminhos `Claim`/`Refund` excludentes no contrato da
chain que arbitra; ele também explicita a corrida de segredos divulgados antes
da confirmação. O [trabalho de Gugger](https://github.com/h4sh3d/xmr-btc-atomic-swap)
e a [explicação do COMIT](https://arxiv.org/abs/2101.12332) mostram por que
a chain sem scripts não precisa carregar o timelock quando a outra chain
fornece a arbitragem. São lições de estrutura, não prova para DOM.

Antes deste trabalho, o consenso DOM em
[`transaction.rs`](../../crates/dom-consensus/src/transaction.rs) reconhecia
somente kernels `PLAIN`, `COINBASE` e `HEIGHT_LOCKED`. A reserva do laboratório
tinha uma devolução pré-assinada por altura, sem um output que aceitasse
Claim, Refund e Punish mutuamente exclusivos por fase. O candidato `DXA1`
acrescenta essa regra ao consenso DOM; ela não é uma flag local do daemon e
ainda exige ativação de rede antes de qualquer uso fora do laboratório.

O `unlock_time` existente no Monero não fornece o bloqueio ausente da
devolução: a [documentação de RPC do Monero](https://web.getmonero.org/resources/developer-guides/daemon-rpc.html)
o define como instante em que o **output produzido** pode ser gasto, não como
primeira altura em que a transação assinada pode entrar num bloco. Usá-lo em
uma devolução XMR não impediria a corrida que acabamos de reproduzir.

## Candidato a testar, sem cápsula de tempo

O candidato agora possui um primitivo concreto `DXA1` no consenso DOM. O
output compromete três gastos exatos e fases adjacentes: claim até `Hc`, refund
de `Hc+1` até `Hr`, e punish depois de `Hr`. Claim e punish são adaptados pela
share XMR do dono de XMR; refund é adaptado pela share do dono de DOM. As duas
shares têm provas DLEQ distintas, ligadas à operação e ao papel. Assim, claim
ou punish entrega DOM ao dono de XMR e revela a share que permite ao dono de
DOM gastar a saída XMR conjunta; refund devolve DOM ao dono de DOM e revela a
share que permite ao dono de XMR recuperar XMR.

O primitivo não fica implicitamente ativo por existir no binário. A barreira
de consenso deriva a rede pelo `chain_id` canônico e hoje habilita DXA1 apenas
no Regtest, desde a altura 1. Mainnet, Testnet e IDs desconhecidos retornam
desativado em qualquer altura. Uma ativação pública precisa escolher altura,
elevar e coordenar a versão de bloco e publicar uma release de upgrade; nenhuma
dessas decisões é inferida pelo laboratório.

Testes nativos validam as assinaturas DOM multipartes, a extração de cada
share e a reconstrução da chave XMR conjunta. O nó DOM aplica o contrato no
mempool, bloco direto, reorganização e reconstrução após reinício. Um ensaio
financiado isolado também executou Claim, Refund e Punish separadamente pelo
nó DOM e pelo `monerod`: cada abertura extraída do bloco DOM canônico assinou
um gasto XMR CLSAG/Bulletproof+ aceito e minerado pelo daemon. Uma campanha
paralela dos três resultados terminou em 95,33 s de parede; Claim, Refund e
Punish levaram 84,58 s, 89,91 s e 95,32 s completos, respectivamente.

A ordem do protocolo importa. Refund e Punish ficam pré-assinados e duráveis
antes do funding DOM. O Claim só é concluído e persistido depois que a reserva
XMR conjunta está confirmada e utilizável; essa entrega representa `Ready`.
Se a parte DOM se recusar nesse ponto, Refund revela a share que devolve XMR
ao depositante. Entregar Claim antes do depósito XMR permitiria capturar DOM
sem contrapartida e é proibido pelo fluxo e pelo journal. A autenticidade da
observação XMR que alimenta esse estado ainda depende do coordenador.

Essa máquina de estados agora existe como journal append-only. Ela fixa o
contrato, os adaptors de recuperação e a chave XMR antes do funding, recusa
Claim antes de XMR Ready, valida a fase do settlement e grava os identificadores
das duas chains. O ensaio a reabre duas vezes antes de completar, e testes
recusam corrupção, repetição e ordem inválida. A próxima integração deve ligar
as observações independentes do coordenador a esses mesmos eventos.

A versão v2 grava uma decisão de liberação antes do RPC. Ela fixa o caminho,
hash e primeira altura possível, exige que a margem inteira de inclusão caiba
na fase e aceita como settlement somente a mesma transação dentro da margem.
Isso impede fallback local para um caminho concorrente depois de divulgar uma
share. A margem continua sendo uma hipótese explícita de liveness da chain;
nenhum journal local pode obrigar mineradores a incluir a transação.

A versão v3 não permite gastar XMR assim que o settlement DOM aparece no
primeiro bloco. O mínimo de confirmações faz parte do binding imutável da
sessão. O journal registra o bloco do settlement e uma ponta canônica que
comprove a profundidade exigida; só depois aceita o settlement XMR. O ensaio
financiado usa profundidade dois e recusa a tentativa anterior à finalização.
Isso fecha o reorg de um bloco para a política adotada, mas não transforma duas
confirmações probabilísticas em finalidade absoluta. Uma reorganização mais
profunda continua dentro do modelo adversarial que precisa ser quantificado.

Antes da assinatura XMR há uma segunda leitura do daemon DOM. Ela exige que o
hash canônico na altura do settlement ainda seja o mesmo fixado no journal,
relê a transação desse bloco e recalcula a profundidade contra a ponta atual.
Troca de bloco ou queda abaixo do mínimo são recusadas. Um ensaio com dois nós
agora parte do mesmo histórico até o funding, confirma o Claim no nó principal e
promove uma cadeia concorrente de três blocos sem o settlement. O fork mais
pesado remove o Claim da altura canônica, a rechecagem falha e nenhuma assinatura
ou transação XMR é produzida. Isso exercita o mecanismo real de reorg; não cria
finalidade determinística contra um fork que chegue depois da última leitura.

As shares DLEQ não ficam mais juntas no coordenador do ensaio. Dois processos
geram as shares, validam a prova pública do peer e aplicam regras de papel:
Claim/Punish são concluídos pelo dono de XMR e o gasto XMR pelo dono de DOM;
Refund inverte essas duas responsabilidades. A chave XMR reconstruída existe
somente no processo que assina. A matriz força operações com o papel errado e
exige sua rejeição; também recusa outra oferta válida que não corresponda ao
digest autorizado dentro do contrato fixado. Um proxy liga o `arbiter_party` ao
transporte Noise XX com identidade estática conhecida, `chain_id`, rede, sessão
e sequência exatos. Os controles cobrem peer errado, sessão divergente, ordem e
fragmentação; a matriz inteira usa esse canal e o recria no restart. Falta
repetir entre hosts físicos distintos. O servidor persistente e a configuração
externa do coordenador já permitem essa topologia. Um Claim financiado pelo
mesmo caminho remoto, com os dois servidores isolados em loopback, restaurou os
participantes após a desconexão e passou, com estado cifrado e ativação
restrita ao Regtest, em 93,06 s no total e 27,70 s desde `Ready`; o roteiro
reproduzível está em
`clsag-lab/REMOTE-REGTEST.md`.

O mesmo Claim passou com coordenador e participantes em três contêineres sem
capacidades, estados privados separados, namespaces/endereço distintos e rede
interna sem rota externa. Cada participante recuperou sua chave por um provedor
externo depois do restart e não gravou chave local. O protocolo levou 86,81 s no
total e 26,46 s desde `Ready`; a preparação completa dos contêineres levou
121,78 s. Isso comprova isolamento lógico no mesmo host, não um ensaio em
máquinas físicas distintas.

As chaves de pré-assinatura DOM agora também ficam distribuídas. Cada processo
gera uma share efêmera por caminho, prova sua posse e participa tanto da prova
de faixa colaborativa do output quanto das duas rodadas da assinatura adaptor.
O coordenador soma apenas pontos públicos e não recebe chave de kernel, abertura
de output ou nonce secreto. As duas finalizações produzem a mesma oferta. Após
o restart, as shares efêmeras desaparecem e os processos recusam recriar uma
oferta antiga, mas as ofertas persistidas antes do funding continuam válidas.

O processo de share agora possui retomada durável. Seu arquivo exclusivo `0600`
é sincronizado, bloqueado e vinculado a papel/operação/chain. A share fica
cifrada por XChaCha20-Poly1305 sob uma chave de wrapping `0600` separada; outro
processo, papel errado, adulteração ou chave ausente, errada ou corrompida
falham antes de emitir prova. A matriz mata e reabre ambos os participantes
depois de `Ready`, confere a mesma chave conjunta e os mesmos adaptors e
prossegue somente após reautorizar o contrato público. Conta isolada e KMS ou
hardware seguro continuam requisitos contra leitura privilegiada de ambos os
arquivos pelo host.

Monero impõe a todos os outputs uma janela padrão de dez blocos antes do gasto.
Assim, um depósito XMR criado sob demanda não pode cumprir 2–3 minutos em rede
normal. A meta rápida é tecnicamente possível somente no intervalo
`Ready → Complete`, usando uma reserva conjunta já confirmada e madura. Esse
intervalo mediu 27,47 s para Claim, 32,67 s para Refund e 38,23 s para Punish
sob execução paralela. A rechecagem rejeitou a reorganização em 37,16 s, sem
pedir assinatura XMR. O runner falha se qualquer caso exceder 180 s; a
preparação permanece declarada separadamente.

O lado DOM impõe outra fronteira: `TARGET_SPACING` é 120 s. As duas
confirmações conservadoras do candidato exigem nominalmente 240 s somente para
os blocos. Em um modelo Poisson idealizado, dois blocos chegam em 180 s com
probabilidade de 44,2%, e não há máximo determinístico. Logo, a evidência
Regtest abaixo de três minutos não prova o requisito na rede pública. Manter
duas confirmações preserva a política de reorg e viola o prazo nominal; reduzir
para uma cabe nominalmente, mas enfraquece a segurança e não cria garantia.

## Fast handoff preparado DXF1

O novo fluxo DXF1 não reduz silenciosamente as confirmações do DXA1. DOM e XMR
são preparados antes de `Ready`; no intervalo ativo, o Claim DOM exato é
persistido e aceito pelo daemon. A decisão XMR irreversível é então sincronizada
antes da assinatura e do RPC Monero. O ensaio normal mais recente fez esse
handoff em 17,51 s sem minerar novos blocos durante a medição. Um segundo ensaio
fez o handoff em 16,34 s, removeu o Claim por uma cadeia concorrente depois do
compromisso XMR, manteve Refund proibido, republicou exatamente o mesmo Claim e
acumulou as seis confirmações exigidas. As transações DOM e XMR foram mineradas
e verificadas depois do intervalo ativo.

A segurança continua tendo uma premissa explícita: o Claim deve ser incluído
em até três blocos e acumular seis confirmações ainda dentro de sua fase
exclusiva. Depois do compromisso XMR, o journal nunca autoriza Refund; reorg
apenas reabre a republicação do mesmo Claim. Isso fornece um caminho rápido sob
liveness limitada, não finalidade PoW em cerca de 17 segundos. O journal liga a
inclusão, eventual remoção e confirmação aos hashes de bloco observados pelo nó;
hash trocado ou evento repetido falha fechado. Censura além do limite ou reorg
posterior à profundidade adotada viola a hipótese e precisa ser medido em teste
público antes de produção.

Uma campanha adicional executou o mesmo reorg DXF1 com os signers em dois
servidores Noise persistentes. O coordenador não recebeu shares XMR nem chaves
DOM; os servidores sobreviveram às reconexões, e o handoff ativo terminou em
16,98 s. O teste ainda foi realizado em um único host e não substitui a campanha
física distribuída.

A construção usa uma reserva XMR com chave combinada de duas shares, sem
devolução XMR pré-assinada que possa vencer antecipadamente. Um único
compromisso DOM de arbitragem possui três caminhos: antes de `Ready`, o dono DOM
pode recuperar DOM somente expondo a share que permite ao dono XMR recuperar
XMR; depois de `Ready`, o dono XMR pode receber DOM expondo sua share, que
permite ao dono DOM receber XMR. Se não houver claim, o refund DOM posterior
também expõe a share necessária à recuperação XMR. A transição `Ready` só
pode ocorrer após a reserva XMR correta estar confirmada e utilizável.

Essa descrição **não resolve sozinha** a corrida na borda do prazo: um claim
DOM que divulga a share no mempool e perde para um refund pode permitir que
um lado receba os dois ativos. Antes de qualquer funding, o desenho precisa
especificar janelas sem sobreposição, limites de inclusão/observação,
tratamento de reorg, chave XMR e campos de consenso completos; depois deve
enumerar escalonamentos adversariais e testar as transações nos daemons.

O modelo finito [`arbitration_model.py`](arbitration_model.py) encontra a
mesma falha na alternativa ingênua: claim honesto divulgado na altura 2 com
atraso de 3 blocos perde o limite de claim na altura 4; refund entra na altura
5 e a dona DOM já conhece as duas shares XMR. Com envio honesto até altura 1
e uma **hipótese** de inclusão em até 3 blocos, o modelo não encontra essa
corrida; um único atraso de 4 blocos volta a permiti-la. Três testes em
[`test_arbitration_model.py`](test_arbitration_model.py) verificam ambos os
casos e a exclusão das alturas. Isso mostra a dependência de liveness; não
prova que DOM ou Monero oferecerão tal limite na rede real.

Se a margem requerida ultrapassar a meta aproximada de 2–3 minutos, registrar
isso como inviabilidade da meta sob essas hipóteses. Não esconder espera de
maturidade XMR nem introduzir custódia, pré-funding obrigatório ou BTC.

## Próxima evidência necessária

1. Modelar os estados e eventos `Ready`, `Claim`, `Refund`, divulgação de
   shares, inclusão e reorg, com busca por contraexemplos de dupla captura.
2. Integrar a ordem durável de funding/Ready ao coordenador, sem disponibilizar
   Claim antes da confirmação XMR.
3. Definir ativação do consenso e margens de cutoff com premissas temporais
   declaradas e defensáveis.
4. Repetir sucesso e recuperação com participantes independentes e progressão
   simultânea das duas cadeias antes de afirmar prazo de produção.
