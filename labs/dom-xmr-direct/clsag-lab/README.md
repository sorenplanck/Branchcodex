# Experimento CLSAG do mecanismo novo

Experimentos de assinatura e transação nativa, sem fundos reais. Não é
uma implementação concluída de DOM↔XMR. Este componente investiga uma nova
origem de revelação: completar o claim **XMR** permite extrair o segredo e
completar diretamente a assinatura DOM. O sentido DOM→XMR também é testado.
BTC não participa desse fluxo.

## Candidato rápido atual: DXF1

`DXF1` é uma máquina de liquidação nova, separada da espera por finalidade do
DXA1. Ela usa liquidez DOM previamente confirmada e uma reserva XMR previamente
confirmada e madura. No intervalo ativo, o Claim DOM exato é primeiro gravado e
aceito pelo daemon; depois a decisão XMR é sincronizada em disco, o journal é
reaberto e somente então o gasto exato é assinado e aceito pelo `monerod`.
Nenhum bloco é esperado nesse intervalo.

Depois do compromisso XMR, Refund fica permanentemente proibido e um Claim que
sair da cadeia volta ao estado obrigatório de republicação. Essa regra é
durável, mas não transforma mempool em finalidade: a segurança depende da
hipótese imutável de que o Claim será incluído dentro de 57 blocos, antes da
primeira altura de Refund, e acumulará seis confirmações ainda dentro dessa
janela. O contrato do ensaio reserva essa margem para a recuperação. Censura
além de 57 blocos ou reorg posterior à profundidade adotada permanece fora da
garantia; PoW não oferece limite determinístico. Com o alvo público de 120 s,
essa margem de inclusão representa nominalmente 114 minutos, mas não adiciona
espera ao handoff ativo; ela reserva tempo para republicação antes de Refund.

Os ensaios mais recentes completaram o handoff ativo normal em **17,063 s** e o
caso adversarial em **16,872 s**. No segundo, o `monerod` aceitou o pagamento,
a primeira resposta foi perdida, a autoridade reiniciou e restaurou os mesmos
bytes; depois uma cadeia concorrente retirou o Claim. O journal manteve Refund
proibido, exigiu republicação, e o port de observação do daemon registrou a
reinclusão e seis confirmações. Claim DOM e pagamento XMR foram minerados e
verificados fora do cronômetro ativo. Preparação, handoff e comprovação levaram
**129,651 s** no caso normal e **147,135 s** no caso adversarial.

A máquina de estados e o journal DXF1 agora pertencem ao crate próprio
`crates/dom-xmr-fast-handoff`, isolado das demais pernas e do `dom-interopd`;
o laboratório apenas reexporta e exercita esse mesmo código. A
autoridade persiste a exposição DOM antes do RPC, exige reabertura depois do
compromisso XMR e, antes do RPC Monero, persiste o txid e o SHA-256 dos bytes
assinados exatos. Uma retomada deve restaurar os mesmos bytes. O ensaio com
reorg também republica o Claim por essa autoridade. O journal v4 vincula o
início absoluto dos 180 s e rejeita reinício do contador ou recuo do relógio. A
autoridade também executa o port do `monerod` e só completa após a resposta do
txid exato; o coordenador não possui uma função para registrar essa admissão
diretamente. Criação e transições do journal são privadas ao crate; a referência
exposta pela autoridade é somente para leitura e auditoria.
O port XMR recebe um deadline absoluto derivado dos 180 s persistidos. Sem ao
menos dois segundos inteiros, a autoridade não inicia o RPC; um segundo fica
reservado para validar e sincronizar a admissão. O broadcaster conserva o mesmo
corte durante verificação, submissão e reconciliação, e uma resposta tardia não
conclui o journal. O ensaio financiado `fast-reorg` aceita a transação no
`monerod`, perde a primeira resposta de propósito, reinicia a autoridade,
restaura os mesmos bytes e conclui por `AlreadyKnown`, sem reabrir Refund.
Inclusão, reorg e finalidade DOM só entram por um port de observação do daemon;
o coordenador não possui escritores públicos dessas transições. Junto ao reorg
DOM, passou em **16,872 s** de handoff ativo e **147,135 s** no fixture completo,
que inclui preparação e maturação das reservas em Regtest.
Ainda falta executá-lo em três hosts físicos.
Os testes são:

```text
python3 -B scripts/test_fast_handoff.py \
  --binary target/debug/examples/arbiter_regtest \
  --monerod /caminho/absoluto/monerod \
  --evidence-file /caminho/dxf1-fast-handoff.json

python3 -B scripts/test_fast_handoff.py \
  --binary target/debug/examples/arbiter_regtest \
  --monerod /caminho/absoluto/monerod \
  --outcome fast-reorg \
  --evidence-file /caminho/dxf1-fast-reorg.json
```

## Primitivo de arbitragem reutilizado: DXA1

O mecanismo novo não usa a cápsula temporizada descrita nas seções históricas
abaixo. Um output DOM `DXA1` compromete três gastos exatos e exclusivos por
altura: Claim, Refund e Punish. Duas shares provadas por DLEQ formam a chave da
reserva XMR. Claim/Punish revelam a share do dono de XMR; Refund revela a share
do dono de DOM. O lado econômico correto reconstrói a chave conjunta e gasta a
reserva por uma transação Monero nativa.

A regra de ativação falha fechada pelo `chain_id` canônico. DXA1 fica ativo
somente no Regtest a partir da altura 1. Mainnet, Testnet e cadeias desconhecidas
o recusam em qualquer altura. Uma futura ativação pública exige definir altura,
versão de bloco e rollout coordenado em uma nova release; o laboratório não
ativa silenciosamente uma regra de consenso na rede existente.

`examples/arbiter_regtest.rs` executa cada resultado através de um nó DOM e um
`monerod` isolados. O journal durável exige recovery antes do funding, XMR
confirmado e maduro antes de Claim, e grava os settlements canônicos das duas
chains. Uma política ligada à sessão exige duas confirmações do settlement DOM
antes de extrair a share e enviar a transação XMR. O intervalo
`Ready → Complete` falha automaticamente acima de 180 s.
Monero bloqueia outputs novos por dez blocos; portanto essa meta exige uma
reserva preparada e madura. O tempo de preparação é medido separadamente.

`examples/arbiter_party.rs` mantém cada share XMR num processo próprio. O
coordenador vê somente as provas DLEQ públicas, solicita a conclusão DOM ao
papel correto e entrega a abertura observada ao beneficiário, que assina XMR
sem exportar a chave reconstruída. A matriz exige também a rejeição do papel
errado nas duas operações e de outra oferta válida cujo digest não tenha sido
autorizado para o contrato. `examples/arbiter_party_proxy.rs` transporta essa
mesma interface por TCP com Noise XX. As identidades estáticas ficam em arquivos
`0600`; os dois lados fixam a chave pública esperada, e cada mensagem vincula
rede, `chain_id`, settlement e sequência. A campanha financiada usa o proxy em
todas as chamadas e o reinicia junto com os participantes. Cada processo também
gera shares efêmeras próprias para os três kernels DOM, participa da prova de
faixa colaborativa e da pré-assinatura adaptor e nunca entrega as chaves ao
coordenador. As shares XMR duráveis são cifradas em repouso com
XChaCha20-Poly1305 e uma chave de wrapping separada.

O estabelecimento Noise tem prazo total de 15 s e cada mensagem completa,
inclusive todos os seus fragmentos, tem prazo total de 45 s. Um peer que apenas
abre o TCP ou envia o primeiro fragmento não consegue manter o helper preso por
tempo indefinido. Depois de qualquer timeout o canal é descartado; o modo
persistente volta a aceitar uma conexão autenticada nova.
Durante preparações longas, o coordenador envia presença autenticada entre
operações do daemon para conservar a mesma sessão e as mesmas chaves DOM
efêmeras.

O helper persiste sua share cifrada em um arquivo exclusivo `0600`, sincronizado
e ligado à operação. A chave de wrapping pode ficar num arquivo `0600` separado
ou ser solicitada a um agente externo pelo protocolo de
[`KEY-PROVIDER.md`](KEY-PROVIDER.md), sem arquivo local de chave. A matriz mata e
reinicia ambos os helpers depois de `Ready`, revalida a mesma chave conjunta e
continua. O teste `scripts/test_arbiter_party_state.py` cobre lock simultâneo,
restart, troca de papel, corrupção, chave ausente/errada, resposta cruzada,
socket inseguro e timeout. Um invasor privilegiado que leia a memória do signer
ainda exige HSM com signer integrado, enclave ou isolamento do host.
O formato v2 recusa estados v1 em claro e não executa migração silenciosa;
sessões experimentais antigas precisam ser encerradas pelo caminho de recovery
antes da atualização.

O modo `server-persistent` mantém cada participante em seu próprio endpoint e
reabre o estado privado a cada conexão autenticada. O coordenador aceita esses
endpoints pelo arquivo indicado em `DXA1_REMOTE_PARTIES`; ele não inicia nem
recebe o estado privado dos participantes. O teste
`scripts/test_arbiter_remote.py` percorre esse caminho completo, inclusive a
reconexão dos dois participantes, usando servidores independentes em loopback.
O procedimento para repetir em máquinas distintas está em
[`REMOTE-REGTEST.md`](REMOTE-REGTEST.md).

O mesmo limite remoto agora cobre o DXF1. O runner
`scripts/test_fast_handoff_remote.py` mantém as shares em dois servidores
persistentes, executa o reorg depois do compromisso XMR e exige que ambos
continuem vivos. O ensaio passou em **16,98 s** de handoff ativo e **159,80 s**
no total, com hashes distintos para bloco órfão, reinclusão e ponta final. Os
endpoints usados nessa execução estavam no mesmo host; o roteiro de três hosts
usa o mesmo arquivo de configuração.

Após compilar o exemplo, a matriz paralela é executada assim:

```text
python3 scripts/run_arbiter_matrix.py \
  --binary target/debug/examples/arbiter_regtest \
  --monerod /caminho/absoluto/monerod \
  --evidence-dir /diretorio/novo/de/evidencia \
  --workers 2
```

A campanha mais recente usou dois workers e terminou em 217,82 s de parede,
com duas confirmações DOM, shares XMR e DOM em processos separados, prova de
faixa colaborativa, reinício dos dois participantes, rechecagem canônica antes
da assinatura XMR e todas as operações pelo canal Noise. Claim, Refund e
Punish levaram 27,47 s, 32,67 s e 38,23 s desde `Ready`. Um quarto caso
promoveu uma cadeia DOM concorrente, removeu o Claim e recusou qualquer
assinatura XMR em 37,16 s desde `Ready`. Os registros completos e os limites
atuais estão em `../STATUS.md` e `../ARBITRATION-REPLACEMENT.md`.

O Claim financiado pelo caminho de servidores persistentes, estado cifrado,
barreira de ativação e prazos Noise passou em 93,06 s no total e 27,70 s de
`Ready` até a conclusão. Esse ensaio prova o protocolo de
execução remota e a retomada sobre TCP/Noise, porém usou interfaces loopback no
mesmo host. A execução em máquinas físicas distintas continua pendente.

Um ensaio adicional executa coordenador, dono DOM e dono XMR em três contêineres
sem capacidades, com sistemas de arquivos privados e namespaces/endereço de
rede distintos. A rede Docker é interna e não possui rota externa; o
coordenador não monta nenhum estado dos participantes. Cada participante obtém
sua chave de wrapping por um provedor externo, inclusive após reiniciar, e não
cria arquivo local de chave. O Claim financiado passou em 86,81 s dentro do
protocolo, 26,46 s desde `Ready` e 121,78 s incluindo a preparação dos
contêineres. A imagem Ubuntu é fixada por digest. Esse teste remove o
compartilhamento de pilha de rede do loopback, mas continua no mesmo host físico.

O runner de contêineres agora também executa o DXF1 com reorg. Com a autoridade
DXF1, o journal v4, a recuperação XMR ambígua e a observação DOM pelo daemon, o
handoff ativo terminou em **16,452 s**, o protocolo completo em **143,719 s** e
a campanha, incluindo preparação e inspeção dos contêineres, em **180,658 s**. Os
três processos mantiveram namespaces, endereços e volumes distintos; a rede não
tinha rota externa, as chaves de wrapping vieram de provedores externos e o
coordenador não montou o estado de nenhum signer.

Essa latência usa mineração Regtest solicitada pelo ensaio. A rede DOM pública
tem alvo de 120 s por bloco. Duas confirmações consomem nominalmente 240 s antes
de qualquer trabalho criptográfico e não cabem no teto de 180 s. Mesmo sob um
modelo Poisson idealizado, a chance de dois blocos chegarem em três minutos é
44,2%; não existe limite determinístico para PoW. O módulo
`finality_budget` e os verificadores de evidência impedem que o resultado rápido
do Regtest seja apresentado como cumprimento do prazo em rede pública.

O workflow `.github/workflows/dom-xmr-seconds.yml` reproduz o caminho normal
DXF1 e o cenário adversarial em três contêineres no GitHub, com Monero 0.18.4.0
verificado por hash, limite ativo de 180 s e 20 minutos para todo o job. A
matriz histórica DXA1 não integra esse gate. Os dois resultados DXF1 são
preservados como artefato.

## Construção experimental

Para o membro real do anel, sejam `G` o gerador Ed25519 e `H = Hp(P_real)`.
O dono do segredo `t` entrega `T=tG` e `U=tH`, com uma prova de igualdade
de logaritmos vinculada ao contexto. A pré-assinatura usa compromissos de
nonce `rG+T` e `rH+U`, e resposta ainda incompleta:

```
s_pre = r - c * (mu_P * x + mu_C * z)
s_final = s_pre + t
```

As demais respostas do anel e o desafio inicial seguem o transcript CLSAG.
A conclusão acrescenta `t` somente à resposta do membro real. A extração
primeiro verifica ambas as assinaturas, sua correspondência e os pontos
do segredo. Não se extrai de uma diferença escalar sem validar a assinatura.

O hash-to-point e o verificador final são do `monero-clsag`/`monero-ed25519`
fixados em `c8be5d3d1287669946a83fbfcb296ce2a8852e47`. O verificador upstream
não foi alterado. O transcript adaptado tem atribuição em [NOTICE.md](NOTICE.md).
A prova de igualdade Ed25519 entre `T` e `U` é distinta da prova entre curvas
necessária para associar o mesmo segredo a DOM/secp256k1 e XMR/Ed25519.

## Assinatura conjunta

`joint` produz a pré-assinatura com duas shares separadas, sem reconstruir a
chave privada agregada. Reutiliza as máquinas de nonces do `modular-frost`
0.11.0 e as operações de share de `ClsagMultisig` da revisão fixada. O adaptador
acrescenta `T/U` aos nonces agregados e verifica a pré-assinatura resultante.
Isso não é uma ciphersuite CLSAG padronizada pelo RFC 9591 nem uma construção
auditada; a adaptação exige revisão própria.

Cada rodada consome o estado mesmo em caso de erro. A API não exporta nonces,
seeds de preprocessamento ou clonagem do estado da rodada. O plano fixa
mensagem, rota, sessão, anel, índices, key image e prova do adaptor. A resposta
fica vinculada ao par exato de mensagens de preprocessamento. Os rótulos de
sessão **não autenticam** o remetente. A verificação algébrica continua
necessária mesmo se alguém copiar esses rótulos.

O setup dos testes usa shares aditivas independentes e um roster público já
confiável. Geração distribuída autenticada, prova de posse, armazenamento
durável, proteção contra rollback/fork e retomada após crash ainda faltam.
O oráculo que conhece a chave inteira permanece apenas como controle algébrico.

### Assinatura conjunta DOM

`dom_joint` produz uma pré-assinatura DOM com duas contribuições aditivas e
dois nonces por participante. A intenção imutável inclui o corpo completo da
transação, rede, adaptor, sessão, binding do par e roster ordenado. Exige prova
Schnorr de posse de cada share e que a soma pública corresponda ao kernel.
Essas provas impedem aceitar somente uma declaração de chave, mas não
autenticam identidades nem provam que o financiamento foi distribuído.

Os fatores de vinculação incluem todos os nonces e o plano aprovado. Cada
resposta é verificada contra a chave e os nonces do participante antes da
agregação; o desafio final continua sendo o desafio nativo DOM. Estados com
segredos não são clonáveis ou serializáveis e são consumidos também em falhas.
Ainda falta armazenamento durável, defesa contra rollback, falha de RNG e
retomada. É uma adaptação experimental, não uma ciphersuite FROST padronizada.

O ensaio financiado agora deriva duas shares do kernel sem construir seu
escalar completo, e usa `dom_joint` para a claim. O plano DOM também inclui o
hash da transação XMR aprovada; o contexto XMR já inclui o corpo DOM e os pontos
do segredo entre curvas. Na versão anterior registrada abaixo, o helper conhecia
a abertura inteira da reserva. A versão atual usa `dom_reserve`, descrito a
seguir. A preparação continua no mesmo processo, sem autenticação ou recuperação.
Os controles de gasto posterior/duplo usam chaves locais descartáveis.

O ensaio [JOINT-DOM-XMR-REGTEST-RESULT.json](JOINT-DOM-XMR-REGTEST-RESULT.json)
com as duas assinaturas conjuntas passou: preparação XMR 22,898 s, DOM 11,209 s,
construção até inclusão nas duas cadeias 1,574 s e total 38,090 s. Inclui gastos
posteriores, exclui compilação e usa mineração local controlada. Não mede swap
atômico completo, finalidade pública ou o prazo máximo da missão.

Seis testes verificam consenso nativo, conclusão idêntica pelos dois peers,
extração, provas de posse falsas ou deslocadas, outro corpo válido com o mesmo
kernel, reflexão de nonces e respostas adulteradas ou de outra rodada. Um
doctest rejeita a tentativa de consumir o mesmo estado de nonce duas vezes.

### Reserva DOM compartilhada

`dom_reserve` forma `C = v*H_DOM + R_A + R_B` usando apenas pontos públicos;
cada parte mantém seu próprio `r_i`. Provas de posse vinculam shares ao valor,
rede, sessão, termos e roster. O módulo reutiliza as rodadas da prova de faixa
MPC de `dom-scriptless-bulletproof`; não soma os escalares da reserva.
Os estados de prova são consumidos uma vez, e a prova final precisa passar no
verificador público de `dom-crypto` antes de ser entregue ao financiamento.
Contribuições de assinatura da transação de financiamento e da claim são
derivadas separadamente a partir dessas shares.

O ensaio cria uma moeda comum de preparação via carteira e depois a gasta
para a reserva compartilhada, com prova MPC e assinatura conjunta. Só essa
segunda transação financia a reserva. As duas tentativas de assinar a claim
usando apenas uma contribuição são rejeitadas pelo consenso e pelo nó.
O processo ainda hospeda os dois participantes simulados; não comprova isolamento
entre máquinas, preparação justa, autenticação, recuperação ou segurança contra
todos os ataques de um participante malicioso.

Seis testes cobrem prova nativa nos valores 1, 100.000.000 e 2^52−1, compromisso
ou prova adulterados, shares/provas de posse fora de contexto, mensagens de
outra rodada, nonces comuns divergentes e preservação do binding não vazio
da primitiva. Os testes positivos detectaram a necessidade da correção mínima
no finalizador para outputs plain; ela não muda o verificador de consenso.
Veja [RESERVE-MPC-AUDIT.md](RESERVE-MPC-AUDIT.md) para os limites dessa integração.

O resultado [SHARED-RESERVE-DOM-XMR-REGTEST-RESULT.json](SHARED-RESERVE-DOM-XMR-REGTEST-RESULT.json)
registra preparação XMR 13,077 s, preparação DOM 9,408 s, construção até inclusão
das duas claims 1,788 s e total 26,459 s com gastos posteriores. Reserva DOM na
altura 5, claim na 6 e gasto posterior na 7. Mineração local controlada,
compilação excluída; não demonstra atomicidade completa nem prazo em rede pública.

## Transação Monero nativa

`native::PreparedClaim` usa o construtor upstream com um input RingCT, anel de
16 membros, Bulletproofs+, destinatário padrão e troco padrão. Confere as
aberturas de cada output, valor, cifra da quantia, view tag, taxa máxima e
balanço dos compromissos antes de criar o contexto CLSAG. A assinatura conjunta
fica vinculada ao hash nativo completo. A conclusão preenche a CLSAG e seu
pseudo-output; a extração exige correspondência à transação aprovada.

Ainda não suporta múltiplos inputs, subendereços, payment IDs ou endereços
guaranteed. O segredo de visualização de saída deve ser novo para transações
incompatíveis. A biblioteca não verifica inclusão, maturidade, ausência de
gasto anterior, autenticidade do daemon ou política de reorg por si só.

## Recuperação

`recovery` implementa a camada de validação de shares para uma futura cápsula
temporizada DXP1. O plano publica compromissos Feldman da chave de reserva; uma
share recuperada só é aceita se `share * G` corresponder ao ponto esperado para
seu índice. A reconstrução usa os índices reais abertos, não uma base fixa, e
confere que o segredo final recompõe o ponto público da reserva. O plano e a
janela também produzem bindings para serem incluídos no plano de rota assinado.

Essa camada existe por causa da auditoria em `primefactor-io/vtc`: uma cápsula
que passa na verificação, mas abre para a chave errada, é inutilizável para
recuperação de fundos. O módulo atual ainda não implementa atraso criptográfico,
parâmetros RSA/unknown-order, disponibilidade ou persistência; ele é a barreira
que qualquer backend temporizado precisa atravessar antes de tocar uma reserva.

### Recuperação de uma share DOM

`dom_recovery` liga uma cápsula Ed25519 a uma share exata da reserva DOM.
`ReserveShare::generate_for_recovery` gera essa share no domínio comum de
252 bits; `DomRecoveryMaterial` cria o polinômio Feldman e a prova entre curvas.
O domínio inclui a reserva aprovada e o índice do participante. `DomRecoveryLink`
confere as duas chaves públicas, a prova entre curvas e a janela exata do desafio,
e inclui esses bytes em seu binding. Não verifica sozinho setup RSA, prova de
faixa dos puzzles ou prazo; não é uma autorização para depositar fundos.

Depois da abertura, a reconstrução precisa corresponder aos dois pontos e
à mesma reserva/posição antes de retornar uma share utilizável em DOM. Não
reduz arbitrariamente um escalar Ed25519 módulo secp256k1. Os testes rejeitam
mudança de reserva, função do participante, domínio, prova, janela e abertura.
O material privado do polinômio é zerado ao descartar `DomRecoveryMaterial`.
JSON/Go continuam sem garantia de apagamento físico de todas as cópias.

`examples/dom_recovery_bridge.rs` usa o helper Go em três processos:
emissor `open-only`, verificador `verify-openings` e solver `solve-public`.
O emissor termina sem entregar o escalar atrasado. Depois da verificação pública
da cápsula, o ensaio financia a reserva em nó DOM próprio e descarta a share
original do peer e as chaves da claim preparada. O solver recebe só a oferta
pública e o índice, revalida setup/prova e resolve o puzzle. A share recuperada
permite construir e incluir uma devolução nativa e gastar sua saída.

O ensaio [DOM-RECOVERY-REGTEST-RESULT.json](DOM-RECOVERY-REGTEST-RESULT.json)
passou com 198 puzzles e threshold 100: preparação/verificação da cápsula
92,454 s; financiamento DOM 8,059 s; verificação, abertura, devolução e gasto
posterior 19,381 s (abertura sequencial isolada 1,054 s); total 119,895 s.
Compilação excluída, mineração DOM regtest acelerada. Esse é um ensaio DOM
separado, sem perna XMR executada, com setup RSA centralizado e sem garantia
de atraso mínimo adversarial. Não está integrado às corridas claim/refund do
par, ao protocolo de preparação justa ou à persistência após crash.

```sh
cargo run --offline --locked --release \
  --manifest-path labs/dom-xmr-direct/clsag-lab/Cargo.toml \
  --example dom_recovery_bridge -j 2 -- \
  /caminho/absoluto/lhtlp-bridge 198
```

### Recuperação de uma share XMR

`xmr_recovery` recupera somente a share original de um participante em uma
reserva aditiva 2-de-2. `XmrRecoveryRoster` fixa a ordem das chaves públicas e
o identificador da reserva; `XmrRecoveryLink` vincula essa ordem, o participante,
o plano Feldman e a cápsula/janela exata. O identificador precisa representar
a rede, endereço, rota e sessão acordados pelo chamador. A consistência desses
pontos não autentica participantes nem substitui provas de posse.

A geração só aceita chaves originais: fatores aditivos iguais a um, sem escala
ou offset de saída. A recuperação retorna `ThresholdKeys` com a share individual
verificada; o offset da saída identificado pelo scanner é aplicado depois. O
teste de assinatura descarta a chave original do peer e assina com a recuperada,
nas duas posições do roster. Outros testes rejeitam troca de reserva/posição,
abertura falsa, janela adulterada, pontos inválidos, chaves escaladas ou com
offset, interpolação incompatível e segredo divergente do ponto anunciado.

O modo `regtest_claim ... xmr-recovery` exercita esse caminho no daemon isolado:
prepara e verifica a cápsula antes de minerar fundos, encerra o produtor,
descarta a chave original do peer e chama um novo solver só com material público.
A share recuperada assina conjuntamente a devolução do input selecionado. Os
dois outputs da devolução usam endereços distintos controlados pelo mesmo
participante local; sua soma deve ser igual ao input menos a taxa. Após minerar
dez blocos de maturidade, o ensaio gasta os dois outputs em outra transação.
As outras coinbases geradas para preparar o regtest não fazem parte desse input.

Resultado [XMR-RECOVERY-REGTEST-RESULT.json](XMR-RECOVERY-REGTEST-RESULT.json):
198 puzzles, threshold 100 e 99 aberturas; preparação/verificação da cápsula
66,837 s, mineração inicial 24,196 s, verificação pública e recuperação
19,277 s (solve isolado 1,125 s), devolução até inclusão 0,318 s; total
113,313 s com gasto posterior. Compilação excluída. Foram devolvidas
35.177.188.525.600 unidades atômicas, equivalentes ao input menos a taxa
de 7.082.900.000 unidades do perfil fakechain.

```sh
cargo run --offline --locked --release \
  --manifest-path labs/dom-xmr-direct/clsag-lab/Cargo.toml \
  --example regtest_claim -j 2 -- /caminho/absoluto/monerod \
  xmr-recovery /caminho/absoluto/lhtlp-bridge 198
```

O cliente de processo `examples/support/recovery_bridge.rs` é compartilhado
pelos ensaios DOM e XMR. Agora verifica cada abertura contra Feldman e tenta
outro índice atrasado quando necessário, contabilizando todas as tentativas.
O ensaio financiado `xmr-recovery-bad-first` passou com uma primeira abertura
inválida, segunda válida, devolução incluída e gasto posterior: **20,293 s**
de recuperação, **122,918 s** totais, com seis puzzles de fixture. Detalhes,
custos e limitações em [RECOVERY-SEARCH-AUDIT.md](RECOVERY-SEARCH-AUDIT.md).
O perfil de 198 puzzles também passou: 24,522 s de recuperação e 125,325 s
totais, ainda com apenas duas tentativas de solve; uma execução anterior
expirou na preparação e foi preservada. A conta temporal condicional usa os
99 candidatos possíveis, não apenas os dois observados.
A sessão com verificação única passou depois com índices `[1,4]`: 18,760 s
de recuperação e 187,035 s totais, incluindo duas ofertas na preparação.
Esse total ainda excede três minutos. Também trata um plaintext não canônico
como candidato rejeitado, sem abortar a busca nem reduzi-lo módulo q.
O cliente atual verifica o setup antes da divulgação (`open-staged` /
`prepare-session`) e mantém vivo o verificador público para a recuperação.
Prova de faixa, aberturas e Feldman passam antes do funding. O relatório
separa `setup_verification_seconds`, `public_offer_verification_seconds`
(ambos dentro da preparação) e `recovery_session_seconds`. Isso muda a ordem
do trabalho, mantendo preparação no total e o orçamento dos 99 candidatos;
não estabelece, sozinho, uma margem segura após a divulgação.
Com essa preparação, o ensaio financiado passou em 138,127 s totais, incluindo
duas ofertas, e 5,288 s de recuperação. Os resultados `XMR-RECOVERY-STAGED-198-*`
registram índices `[1,2]`, rejeição de `[1]`, devolução e gasto posterior.
Esse é um ensaio XMR isolado; o perfil curto ainda não demonstra margem segura.
A preparação RSA continua centralizada, sem prova de
atraso mínimo adversarial. Esses dois ensaios de devolução são separados; ainda
falta compor recuperação, claims e preparação justa do par. Não são testes de
swap atômico completo nem de latência mainnet.

## O que os testes verificam

O ensaio separado `direct_recovery_bridge` conecta a cápsula experimental de
uma abertura ao roster XMR Rust. Produtor e verificador são processos distintos;
setup passa antes da oferta, cujo corpo exato recebe um binding conferido nos
dois lados. A recuperação valida a share individual, contexto e papel e aplica
o offset somente depois. Não há funding ou transação nesse exemplo. Estado,
tempos e reprodução em
[DIRECT-PLAINTEXT-RESEARCH.md](../recovery-audit/DIRECT-PLAINTEXT-RESEARCH.md).

- Completar e extrair nas 16 posições do anel; rejeitar a pré-assinatura
  como assinatura nativa final; serializar e verificar o resultado novamente.
- Recusar segredo incorreto, provas adulteradas, troca de rota/mensagem/input,
  chaves ou valores incompatíveis, identidade e pontos com torção.
- Recusar extração de assinatura final inválida ou de outra oferta válida.
- Vincular os pontos secp256k1/Ed25519 por `xmr-dleq-sigma`, e propagar o
  segredo diretamente CLSAG→DOM/Schnorr e no sentido inverso. A verificação DOM
  usa `dom-crypto`.
- Assinar conjuntamente nas 16 posições, com offsets de chave stealth,
  identificar contribuições falsas e recusar pontos inválidos, respostas não
  canônicas, sessões distintas e reaproveitamento de outra rodada.
- Construir e serializar transações XMR completas; validar CLSAG, Bulletproofs+
  e balanço; usar o scanner upstream para reconhecer pagamento e troco exatos;
  recusar alterações de taxa, destino, compromisso, timelock e input.
- Validar shares de recuperação por compromisso Feldman; reconstruir por
  subconjuntos não prefixados; rejeitar share forjada, índices duplicados ou
  fora do intervalo, delayed share fora da janela, ponto público inválido,
  compromisso alterado e binding trocado.

`native_dom` congela uma transação DOM de um input/um output/um kernel plain,
valida estrutura, prova de faixa e balanço, e vincula a pré-assinatura ao kernel.
A conclusão executa `dom_consensus::validate_transaction`; a extração exige o
mesmo corpo completo, rede, assinatura e adaptor. Testes rejeitam alteração de
input/output, offset, taxa, prova, assinatura, rede e substituição por outra oferta.
O teste integrado em `tests/native.rs` propaga o segredo diretamente entre
transações nativas DOM e XMR nos dois sentidos, após serialização e leitura.
Os inputs DOM são fixtures sem fundos, e os anéis/contêineres XMR offline são
sintéticos. Isso não comprova inclusão conjunta, atomicidade ou swap completo.

O exemplo `regtest_claim` também extrai o segredo da claim XMR consultada no
daemon e o usa diretamente para concluir a transação DOM. No ensaio anterior registrado
em `DIRECT-DOM-XMR-REGTEST-RESULT.json`, a preparação de 140 blocos levou
26,919 s; a construção até inclusão XMR levou 1,594 s e a conclusão/verificação
DOM 0,058 s. Total 33,821 s, com gasto posterior do XMR e sem compilação.
O input DOM era uma fixture sem financiamento e não havia inclusão DOM nesse ensaio.

A versão atual financia a reserva DOM com moedas mineradas em um nó regtest
próprio, sem listeners ou peers. Submete a claim à admissão normal, minera um
bloco e consulta seu corpo canônico e índice de kernel. Confere o consumo da
reserva, o output recebido, seu gasto posterior e a rejeição de outro gasto
assinado contra a reserva consumida. Reenviar a mesma transação confirmada é
idempotente. O perfil regtest usa PoW rápido e maturidade coinbase de um bloco.
O setup ainda conhece chaves descartáveis completas; recuperação não participa
desse ensaio. Assim, inclusão nos dois nós não comprova atomicidade ou duração
em redes públicas.

Resultado financiado: [FUNDED-DOM-XMR-REGTEST-RESULT.json](FUNDED-DOM-XMR-REGTEST-RESULT.json).
Preparação XMR 14,867 s; preparação DOM 8,430 s; construção até inclusão nas
duas cadeias 2,000 s; total 28,371 s incluindo gastos posteriores, sem compilação.
Esses tempos são do ambiente local com blocos gerados sob demanda.

```sh
cargo test --release --locked --manifest-path labs/dom-xmr-direct/clsag-lab/Cargo.toml -j 2
```

O workspace é independente. A primitiva `dom-scriptless-bulletproof` recebeu a
correção de seleção de verificador descrita acima; as outras dependências DOM
são consumidas sem alterações. Não se executa o protocolo anterior. `--offline` pode ser
acrescentado quando as dependências já estiverem no cache.

O exemplo `regtest_claim` recebe o caminho absoluto de um `monerod` e,
opcionalmente, `xmr-first` (padrão) ou `dom-first`. Em ambas as direções,
inicia seu próprio daemon offline com configuração vazia e dados novos em
`target/regtest-*`, gera moedas locais e encerra esse processo ao terminar.
Não aceita URL RPC ou carteira existente. Faz uma claim XMR conjunta, confere
inclusão local e extração, minera explicitamente a maturidade da saída recebida
e testa seu gasto posterior. O relatório separa preparação, construção e
inclusão local. Blocos produzidos por RPC não medem o tempo da rede principal.
O resultado obtido está em [REGTEST-RESULT.json](REGTEST-RESULT.json): 15,701 s
para o ensaio local completo, incluindo 140 blocos de preparação. A submissão
ao daemon usa `do_not_relay=true`, pois não há peers para Dandelion++, e mantém
a validação de consenso. A heurística RPC de sanidade de decoys é desabilitada
como no helper upstream; esse ensaio não avalia privacidade de seleção de anel.

```sh
cargo run --release --locked --manifest-path labs/dom-xmr-direct/clsag-lab/Cargo.toml \
  --example regtest_claim -j 2 -- /caminho/absoluto/monerod
```

Para verificar a direção inversa no mesmo executor de laboratório:

```sh
cargo run --offline --release --locked \
  --manifest-path labs/dom-xmr-direct/clsag-lab/Cargo.toml \
  --example regtest_claim -j 2 -- /caminho/absoluto/monerod dom-first
```

`dom-first` conclui a claim DOM, descarta os objetos que guardavam o segredo
original, inclui a transação no nó DOM e extrai o segredo de seu corpo canônico.
Somente esse escalar extraído é usado para concluir a CLSAG XMR; seu ponto
Ed25519 também precisa coincidir com a prova entre curvas aprovada. O ensaio
verifica inclusão XMR, recebimento, gastos posteriores nas duas moedas e
rejeição de gasto conflitante DOM. O descarte dos objetos não comprova apagamento
físico de todas as cópias na memória.

Resultado da direção inversa:
[DOM-FIRST-REGTEST-RESULT.json](DOM-FIRST-REGTEST-RESULT.json), total 25,854 s;
preparação XMR 13,402 s, preparação DOM 8,565 s e preparação das claims até
inclusão em ambas as cadeias 1,623 s. Compilação excluída, blocos locais sob
demanda; setup centralizado e recuperação ausente nesse ensaio. Os campos
`claims_preparation_seconds`, `xmr_transaction_ready_seconds` e
`xmr_claim_through_local_inclusion_seconds` medem marcos desde o início da
preparação das claims; em `dom-first`, os dois últimos incluem a espera pela
inclusão DOM. Não representam somente custo de assinatura ou latência mainnet.

## Obrigações antes de usar em uma troca

O experimento novo `xmr-direct-recovery` usa a prova direta experimental para
restaurar a share original do peer, devolvê-la por CLSAG nativa e gastar os
dois outputs. [Resultado financiado](XMR-DIRECT-RECOVERY-REGTEST-RESULT.json):
52,027 s totais, incluindo preparação; 0,673 s na recuperação. Execução:

```sh
target/release/examples/regtest_claim /caminho/absoluto/monerod \
  xmr-direct-recovery /caminho/absoluto/direct-dlog-bridge
```

Esse modo é isolado, sem DOM e sem admissão temporal. O perfil curto abre
antes do intervalo necessário à preparação e não demonstra uma troca segura.
O bridge exige build explícito descrito na
[pesquisa direta](../recovery-audit/DIRECT-PLAINTEXT-RESEARCH.md).
Um argumento final opcional `10000000` seleciona o perfil experimental longo;
o padrão é `200000`. Somente esses valores são aceitos. O receptor confere a
escolha antes da verificação sequencial, e o relatório registra o T efetivamente
selecionado. Toda a preparação e a abertura continuam dentro do total medido.

O caminho direto agora distingue saldo individual e reserva compartilhada:
gera os 140 blocos iniciais para uma carteira individual antes da cápsula,
verifica a cápsula, publica uma transferência nativa de 5 XMR de teste para
a reserva, confere inclusão/valor e gera os dez blocos de maturação antes de
recuperar. A carteira individual recebe seu troco. Os campos
`owner_balance_preparation_seconds` e `reserve_funding_and_maturity_seconds`
separam esses custos; ambos permanecem em `preparation_seconds` e no total.
Os relatórios anteriores `XMR-DIRECT-RECOVERY-*` e
`XMR-DIRECT-RECOVERY-10M-*` usavam coinbase diretamente na reserva, depois da
cápsula. São evidências históricas desse outro caminho de financiamento.
Essa mudança não abrevia a maturação na rede principal nem cria uma reserva
compartilhada antecipada; somente a geração de saldo individual vem antes.

O [resultado com depósito nativo](XMR-DIRECT-TRANSFER-10M-REGTEST-RESULT.json)
passou em **131,917 s** com T=10.000.000: saldo 14,157 s, depósito/maturação
1,009 s e recuperação 48,180 s. O intervalo após receber a cápsula foi 17,423 s,
contra 48,179 s de abertura. Não é uma garantia contra um adversário mais rápido;
o ensaio ainda não integra DOM nem usa admissão temporal.

Variante posterior à auditoria: a [devolução DOM por altura](DOM-HEIGHT-REFUND.md)
usa uma transação assinada antes de financiar a reserva e remove a cápsula da
share DOM. O nó rejeita a devolução antes da altura, e as assinaturas impedem
reescrevê-la como plain. O ensaio nativo verifica abandono e claim vencedora.
`regtest_claim ... height-xmr-first` e `height-dom-first` integram essa devolução
às claims cooperativas do par. A janela de recuperação XMR e a atomicidade
conjunta continuam pendentes; essa variante não autoriza fundos reais.

O modo `early-dom-refund` reproduziu perda de atomicidade ao compor o perfil
curto de recuperação com claims sem proteção de prazo: o depositante DOM
devolveu seu DOM e recebeu XMR. A claim DOM válida do peer perdeu para o input
já consumido. A [auditoria](EARLY-RECOVERY-AUDIT.md) e o
[relatório](EARLY-DOM-REFUND-REGTEST-RESULT.json) documentam esse controle
negativo financiado com 198 puzzles. Não houve devolução XMR concorrente no
teste; ele não refuta uma construção que implemente as margens necessárias.
Esse perfil continua apenas como ferramenta de laboratório.

`recovery_challenge` implementa o transcript experimental do desafio de
cut-and-choose: plano Feldman, setup, puzzles ordenados e prova de faixa entram
no SHA-512 com campos delimitados por comprimento. Fisher–Yates com amostragem
por rejeição seleciona exatamente metade dos índices, sem redução modular
enviesada. A janela só aceita as shares dos índices selecionados e o mesmo plano.
Os tamanhos permitidos são pares até 512 e threshold `n/2+1`; tamanhos pequenos
continuam sendo fixtures, não parâmetros seguros. Os bytes de setup/puzzle/prova
são opacos nesse módulo e precisam de parsing e verificação no backend.
O exemplo `recovery_puzzle_bridge` usa agora esse módulo com os bytes reais
de setup, puzzles e prova enviados pelo helper Go, antes de solicitar as
aberturas selecionadas. Os testes unitários continuam usando bytes sintéticos.
`JointPlan::new_with_capsule` inclui esse `binding()` no transcript conjunto
depois de revalidar o plano Feldman e a janela exata selecionada. Testes rejeitam
cápsulas diferentes com a mesma janela, peers sem esse vínculo, mutações dos
campos públicos e mensagens com identificadores falsificados. O bridge também
completa e verifica uma CLSAG nativa ligada aos bytes reais da cápsula, com
extração do witness; o anel dessa etapa é sintético e as chaves são descartáveis.
Go é um helper local confiável nesse ensaio; suas respostas não equivalem a
provas de um participante remoto.

`JointPlan::new_with_recovery` vincula a sessão de assinatura a uma janela
Feldman validada cuja chave pública coincide com a chave inteira do input XMR.
O binding entra no transcript conjunto; peers com janelas diferentes ou sem
esse binding são rejeitados. Isso ainda não prova disponibilidade ou atraso
da recuperação: os testes de integração usam somente compromissos públicos.
O exemplo `regtest_claim` continua usando o construtor de laboratório sem
recuperação. A ligação de uma share individual DOM é exercida pelo novo exemplo
de devolução, separadamente da integração CLSAG.

O modo público do helper Go limita campos, confere as 160 rodadas da prova,
valida elementos invertíveis e os poderes do módulo, e recalcula
`h = g^(2^T) mod N` com as 200.000 quadraturas do perfil local. Isso rejeita
alguns setups malformados e inconsistentes. Não prova a fatoração adequada do
módulo, ausência de trapdoor, ordem suficiente do grupo ou um atraso mínimo.

Faltam uma prova de segurança da adaptação (incluindo extração sob ataque),
setup autenticado, codificação do plano completo, persistência antes da
divulgação, proteção contra abort/retry, preparação justa das reservas,
backend temporizado de recuperação não cooperativa e integração dessas garantias
ao ensaio financiado DOM↔XMR, incluindo a direção inversa nas duas cadeias.
O índice real é conhecido pelos participantes deste experimento;
o efeito disso na privacidade também precisa de análise. Nenhum resultado ou
tempo desta suíte deve ser apresentado como duração ou segurança de um swap.
