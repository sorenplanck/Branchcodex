# Integração nativa da cápsula direta DOM↔XMR

Experimento local em nós próprios, sem BTC e sem fundos externos. Não é uma
implementação auditada de swap nem uma demonstração de segurança temporal.

## Resultados completos preservados

| Caminho | Ambas as claims | Total com verificações posteriores | Evidência |
| --- | ---: | ---: | --- |
| XMR-first | 82,206 s | 168,836 s | `DIRECT-PAIR-XMR-FIRST-REGTEST-RESULT.json` |
| DOM-first | 79,088 s | 165,979 s | `DIRECT-PAIR-DOM-FIRST-REGTEST-RESULT.json` |
| Abandono antes dos adaptors | Não há claims cooperativas | 173,551 s | `DIRECT-PAIR-ABANDON-REGTEST-RESULT.json` |

O XMR-first completou as claims com extração da transação observada no monerod,
gastou a saída DOM, a saída XMR do comprador e o troco do dono original. Na
altura DOM 214 rejeitou a devolução conflitante. A sessão da cápsula foi
encerrada sem abertura. Seu watchdog terminou com exit 0 em 168,879 s, sem
timeout. Arquivos `*-PHASES.jsonl`, `*-WATCHDOG.json` e `*-PROVENANCE.json`
preservam etapas, processo e hashes dos executáveis/fontes utilizados.
Esse resultado inclui saldo inicial e cápsula; compilação fica fora do relógio.
Ele não prova segurança bilateral, setup distribuído, finalização de mainnet,
recuperação por abandono ou integração ao daemon de interoperabilidade.

DOM-first também passou, com o segredo original descartado antes da
observação DOM: a claim XMR usou somente o escalar extraído da transação DOM
obtida do bloco canônico. Gastos posteriores e rejeição da devolução na altura
214 passaram. O watchdog terminou com exit 0 em 166,024 s. As linhas da tabela
representam a ordem de inclusão das claims da mesma troca bilateral DOM↔XMR;
nenhuma inclui BTC ou demonstra composição com outra perna.

O abandono concorrente também passou: a abertura/conferência XMR levou
35,499 s; ao concluir, DOM já estava na altura 139. A devolução XMR foi
observada aos 121,739 s, antes do limite condicional, e seus dois outputs
foram gastos aos 125,667 s. O ensaio aguardou a altura DOM 215, incluiu a
devolução pré-assinada na 216 e gastou-a na 217, em 173,551 s totais.
Seu watchdog terminou com exit 0 em 173,593 s. Isso demonstra recuperação
nativa dos dois ativos nesse abandono anterior aos adaptors; não cobre a
disputa entre transações após revelar o segredo nem interrupção/reabertura.

Após o minerador concorrente passaram 20 testes Rust, Clippy de todos os
targets e a regressão nativa `height-dom-first` em 29,106 s. Os arquivos
`HEIGHT-DOM-FIRST-MINER-*` preservam essa regressão. A mineração sequencial
dos outros modos usa o mesmo helper de validação/relógio da tarefa concorrente.

## Caminhos implementados

Os conflitos após entrega dos adaptors e o controle negativo de exposição
tardia estão em [DIRECT-PAIR-CONFLICTS.md](DIRECT-PAIR-CONFLICTS.md).

- `direct-pair-xmr-first`: a claim XMR revela o segredo para a claim DOM.
- `direct-pair-dom-first`: a claim DOM revela o segredo para a claim XMR.
- `direct-pair-abandon`: ambos depositam e abandonam antes da entrega dos
  adaptors; o dono do XMR recupera a share pela cápsula e recebe a devolução,
  e o dono do DOM usa a devolução pré-assinada quando a altura permite.

Os caminhos de sucesso verificam a cápsula antes do depósito XMR e vinculam
seu link exato e os bytes da devolução DOM ao contexto da claim XMR. O contexto
DOM incorpora esse vínculo e o hash da transação XMR. A chave do roster mais
offset precisa coincidir com a chave do output real. A assinatura conjunta
continua usando duas shares; não se reconstrói a chave privada agregada.

O saldo XMR individual é preparado antes da cápsula, com todo o custo no
relógio total. O depósito na reserva é uma transferência nativa posterior à
verificação pública. No sucesso, a quantia acordada vai ao comprador e o troco
vai ao dono original do XMR; ambos os outputs são gastos posteriormente. No
abandono, os dois outputs da devolução pertencem ao dono original do XMR.

O DOM também prepara primeiro a carteira, o saldo individual, a prova de faixa
conjunta e o corpo ainda não assinado do depósito compartilhado. Só depois da
cápsula assina esse depósito e a devolução, publicando o depósito após possuir
a devolução. Um bloco ordinário atualiza a âncora para evitar que um timestamp
antigo prolongue artificialmente a altura necessária. Nada disso antecipa o
financiamento da reserva compartilhada.

## Premissas condicionais do ensaio

O perfil é T=10.000.000. Os números abaixo são uma fixture explícita, **não
limites estabelecidos por benchmark**:

| Campo | Hipótese |
| --- | --- |
| Origem do relógio | Recepção completa da oferta pelo cliente local |
| Abertura adversarial mínima | 30 s após essa origem |
| Ofertas prontas até | origem + 28 s em XMR-first; origem + 26 s em DOM-first |
| Início honesto de recuperação até | origem + 35 s |
| Abertura e conferência honestas | até 60 s, mais 5 s de overhead |
| Resolução de cada cadeia | até 1 s |
| Observação da contraparte | até 1 s |
| Erro do relógio do validador local | 0 s |

Portanto a recuperação honesta termina, sob essas hipóteses, até origem+100 s.
A devolução DOM deve ser estritamente posterior a origem+103 s. O nó DOM
fornece um bloco canônico real para a âncora. `from_direct_costs` e
`required_dom_refund_height` calculam a altura usando essa âncora e a tolerância
nativa de timestamp futuro, sem converter intervalo médio de bloco em mínimo.
A transação de devolução é assinada antes de publicar o depósito DOM.
Em DOM-first, `required_dom_refund_height_for_dom_first` contabiliza também
resolução e observação DOM antes da resolução XMR. A margem de uma única
claim usada em XMR-first seria insuficiente para essa ordem. Um teste confere
essa diferença, a fronteira estrita, a origem do relógio e overflow.

O ensaio aborta por assert se a preparação ultrapassar o orçamento local,
inclusive antes do depósito XMR e da liberação das ofertas; ele não é um
executor durável de recuperação desses abortos. Esse comportamento também
precisa ser integrado antes de uso fora do laboratório.

A recepção completa não autentica a primeira divulgação a um adversário;
os limites de velocidade, rede e disponibilidade não estão provados. Os
relatórios devem conservar `atomic_swap=false`, `timing_bounds_proven=false`
e indicar expressamente os checks condicionais de laboratório. Não usar
esses números como permissão para depositar fundos reais.

## Mineração e medição

Blocos são minerados sob demanda, mas a altura DOM não é antecipada mudando
o relógio do nó. O helper aguarda quando o próximo timestamp ultrapassaria
a tolerância futura real do consenso. Nos caminhos de sucesso ele chega à
altura e confirma que a devolução perde para a claim já incluída. No abandono
inclui a devolução e seu gasto posterior. Esse custo permanece no total.
Nesse caminho a cadeia DOM avança durante a abertura da cápsula XMR: o IPC
bloqueante roda em uma tarefa separada, e um minerador nativo próprio chega
somente à altura calculada, sem publicar a devolução. O coordenador primeiro
inclui e observa a devolução XMR, depois aguarda o minerador DOM e publica
a devolução DOM. O handle é aguardado ou cancelado; não há minerador destacado
sem dono. A altura observada ao concluir a recuperação precisa ter avançado.

Depois de criar o saldo DOM individual, somente nos três modos `direct-pair`,
o nó encerra sua carteira de mineração e usa o minerador regtest nativo sem
carteira. As recompensas dos blocos seguintes não serão gastas; os outputs do
swap continuam sob o material dos participantes e são gastos pelo ensaio.
Isso evita derivação/encriptação/persistência de uma carteira de recompensas
irrelevante em cada bloco. Não altera consenso, dificuldade regtest, timestamps,
altura, armazenamento da cadeia ou validação das transações. Não mede a
durabilidade de uma carteira de mineração em produção.

A observação efetiva da claim XMR também precisa preceder o limite adversarial
condicional; no abandono, a observação da devolução XMR precisa ocorrer até o
limite honesto mais o segundo reservado à resolução. São checks desta execução,
não evidência de que essas premissas valham contra um adversário.

Compilação é medida separadamente. Setup, saldo inicial, prova, verificações,
depósitos, maturação local e as verificações posteriores entram no total do
processo. Não se mede latência de mainnet nem se encurta sua maturação.

```sh
cargo build --offline --release --locked --example regtest_claim -j 2
target/release/examples/regtest_claim /caminho/absoluto/monerod \
  direct-pair-xmr-first /caminho/absoluto/direct-dlog-bridge
```

Os demais modos trocam somente o nome do caminho. Ainda faltam ensaios de
disputa após entrega dos adaptors, autenticação, persistência, política de
reorg/finalização, prova dos prazos e revisão criptográfica. O teste de
abandono antes dos adaptors não cobre essas disputas.

## Primeiro resultado e correção da preparação

O ensaio inicial `direct-pair-xmr-first` interrompeu em 88,295 s, antes do
depósito XMR: a preparação DOM feita após receber a cápsula consumiu a janela
de 28 s. O DOM já tinha seu depósito e devolução preparada; esse processo não
executou a devolução posterior. Evidência em
`DIRECT-PAIR-XMR-FIRST-INITIAL-FAILURE.json` e nos artefatos indicados nele.
A separação da preparação individual DOM descrita acima corrige essa ordem;
não se ampliou a janela de prontidão para contornar a falha.

A segunda tentativa terminou no timeout interno de 240 s (240,185 s de
processo), sem relatório completo. A última mensagem confirmava a cápsula;
sem registros intermediários, não é possível afirmar se concluiu as claims.
Evidência em `DIRECT-PAIR-XMR-FIRST-SECOND-FAILURE.json`. O ensaio agora
preserva eventos públicos em `phases.jsonl` dentro de seu diretório novo,
incluindo as duas claims, gastos posteriores e altura DOM aguardada. Eventos
parciais não substituem o relatório final nem demonstram sucesso global.

A terceira tentativa, já instrumentada, incluiu ambas as claims em 79,335 s
totais e concluiu seus gastos posteriores em 81,064 s. Ela atingiu o timeout
de 240 s minerando até a altura DOM 214; o último progresso registrado foi
176/214. Resultado e log preservados em
`DIRECT-PAIR-XMR-FIRST-INSTRUMENTED-FAILURE.*`. Assim se localizou o custo
posterior às transferências; a rejeição tardia ainda não foi demonstrada por
essa tentativa. A mineração sem carteira de recompensas descrita acima é a
correção a medir na tentativa seguinte; o timeout não foi ampliado.

O primeiro abandono financiado completo passou em **204,880 s**, acima de
três minutos. Recuperou XMR em 33,085 s e observou sua devolução aos 114,844 s;
gastou os outputs XMR aos 115,725 s. Somente então começou a minerar DOM,
incluindo devolução na altura 215 e gasto na 216. Esse intervalo sem blocos
fez o timestamp do bloco seguinte avançar para o relógio atual, prolongando
também a espera pela tolerância futura. Evidência
`DIRECT-PAIR-ABANDON-SERIAL-*`. O ensaio concorrente descrito acima corrige
essa paralisação artificial da cadeia; não altera o atraso criptográfico
nem transforma esse primeiro resultado acima da meta em sucesso temporal.
